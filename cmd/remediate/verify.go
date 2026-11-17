package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"citycountrygame/internal/findings"
)

// MaxVerifications is the hard bound on run_verification calls per run. It is
// a constant, not a flag: CLAUDE.md makes the bound of three an invariant.
const MaxVerifications = 3

// StepResult is one verification step. Output is a tail of the command's
// output, returned to the model and recorded in result.json as evidence.
type StepResult struct {
	Name       string `json:"name"`
	OK         bool   `json:"ok"`
	Skipped    bool   `json:"skipped,omitempty"`
	Output     string `json:"output,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

type Verification struct {
	Attempt    int          `json:"attempt"`
	Passed     bool         `json:"passed"`
	Steps      []StepResult `json:"steps"`
	Unresolved []string     `json:"unresolved,omitempty"` // finding IDs still present
}

// Verify builds, tests and re-checks the findings in the workspace.
//
// Passing requires: go build and go test succeed, every dependency finding's
// package now resolves to at least its fixed-in version (or is no longer
// imported), and, when a Snyk binary is configured, a re-scan no longer reports
// any of the original vulnerabilities. Build and test run with the allowlisted
// environment only; the Snyk token is handed to the Snyk step alone.
func Verify(ctx context.Context, ws *Workspace, fs []findings.Finding, snykBin string, attempt int) Verification {
	v := Verification{Attempt: attempt}
	step := func(name string, timeout time.Duration, env []string, cmd string, args ...string) StepResult {
		start := time.Now()
		out, err := runCmd(ctx, ws.Root, env, timeout, cmd, args...)
		r := StepResult{Name: name, OK: err == nil, Output: tail(out, 3000), DurationMS: time.Since(start).Milliseconds()}
		if err != nil && r.Output == "" {
			r.Output = err.Error()
		}
		return r
	}

	build := step("go build", 3*time.Minute, toolEnv(), "go", "build", "./...")
	v.Steps = append(v.Steps, build)
	if !build.OK {
		return v
	}
	test := step("go test", 5*time.Minute, toolEnv(), "go", "test", "-count=1", "./...")
	v.Steps = append(v.Steps, test)

	fix, unresolved := checkFixedVersions(ctx, ws, fs)
	v.Steps = append(v.Steps, fix)
	v.Unresolved = unresolved

	rescan := rescanSnyk(ctx, ws, fs, snykBin)
	v.Steps = append(v.Steps, rescan)

	v.Passed = build.OK && test.OK && fix.OK && (rescan.OK || rescan.Skipped)
	return v
}

// checkFixedVersions maps each dependency finding's package to the module
// version now selected, and compares it with the scanner's fixed-in version.
// This is deterministic and needs no network or credential.
func checkFixedVersions(ctx context.Context, ws *Workspace, fs []findings.Finding) (StepResult, []string) {
	start := time.Now()
	r := StepResult{Name: "fixed-version check"}
	out, err := runCmd(ctx, ws.Root, toolEnv(), 2*time.Minute, "go", "list", "-deps", "-test",
		"-f", "{{if .Module}}{{.ImportPath}} {{.Module.Path}} {{.Module.Version}}{{end}}", "./...")
	if err != nil {
		r.Output = "go list failed: " + tail(out, 2000)
		r.DurationMS = time.Since(start).Milliseconds()
		return r, nil
	}
	selected := map[string]string{} // package -> "module version"
	for _, line := range strings.Split(string(out), "\n") {
		if f := strings.Fields(line); len(f) == 3 {
			selected[f[0]] = f[1] + " " + f[2]
		}
	}

	var lines, unresolved []string
	for _, f := range fs {
		if f.Kind != findings.KindDependency {
			continue
		}
		mv, imported := selected[f.Package]
		ok, why := fixedStatus(mv, imported, f.FixedIn)
		mark := "FIXED"
		if !ok {
			mark = "NOT FIXED"
			unresolved = append(unresolved, f.ID)
		}
		lines = append(lines, fmt.Sprintf("%s %s %s: %s", f.ID, mark, f.Package, why))
	}
	r.OK = len(unresolved) == 0
	r.Output = strings.Join(lines, "\n")
	r.DurationMS = time.Since(start).Milliseconds()
	return r, unresolved
}

// fixedStatus decides one finding. mv is "module version" from go list.
func fixedStatus(mv string, imported bool, fixedIn []string) (bool, string) {
	if !imported {
		return true, "package is no longer in the build"
	}
	_, version, _ := strings.Cut(mv, " ")
	min := minFixed(fixedIn)
	if min == "" {
		return false, fmt.Sprintf("selected %s; the scanner lists no fixed version", mv)
	}
	if semver.Compare(version, min) >= 0 {
		return true, fmt.Sprintf("selected %s, fixed in %s", mv, min)
	}
	return false, fmt.Sprintf("selected %s, needs at least %s", mv, min)
}

func minFixed(fixedIn []string) string {
	var vs []string
	for _, v := range fixedIn {
		if !strings.HasPrefix(v, "v") {
			v = "v" + v
		}
		if semver.IsValid(v) {
			vs = append(vs, v)
		}
	}
	if len(vs) == 0 {
		return ""
	}
	sort.Slice(vs, func(i, j int) bool { return semver.Compare(vs[i], vs[j]) < 0 })
	return vs[0]
}

// rescanSnyk re-runs `snyk test` in the workspace and fails if any of the
// original vulnerabilities (by rule ID and package) is still reported. New,
// unrelated findings are listed but do not fail the step; they belong to the
// next run's triage. Skipped when no Snyk binary is configured.
func rescanSnyk(ctx context.Context, ws *Workspace, fs []findings.Finding, snykBin string) StepResult {
	r := StepResult{Name: "snyk test (re-scan)"}
	if snykBin == "" {
		r.Skipped = true
		r.Output = "skipped: no -snyk binary configured"
		return r
	}
	start := time.Now()
	defer func() { r.DurationMS = time.Since(start).Milliseconds() }()

	outFile := filepath.Join(ws.tmp, "rescan.json")
	os.Remove(outFile)
	env := toolEnv("SNYK_TOKEN=" + os.Getenv("SNYK_TOKEN"))
	out, runErr := runCmd(ctx, ws.Root, env, 5*time.Minute, snykBin, "test", "--json-file-output="+outFile)

	b, err := os.ReadFile(outFile)
	switch {
	case errors.Is(err, os.ErrNotExist) && runErr == nil:
		r.OK = true
		r.Output = "re-scan clean"
		return r
	case err != nil:
		r.Output = fmt.Sprintf("re-scan produced no report (%v): %s", runErr, tail(out, 1500))
		return r
	}
	now, err := findings.ParseSnykTest(b)
	if err != nil {
		r.Output = "re-scan report unreadable: " + err.Error()
		return r
	}

	type key struct{ rule, pkg string }
	orig := map[key]string{}
	for _, f := range fs {
		if f.Kind == findings.KindDependency {
			orig[key{f.RuleID, f.Package}] = f.ID
		}
	}
	var still, other []string
	for _, f := range now {
		if id, ok := orig[key{f.RuleID, f.Package}]; ok {
			still = append(still, fmt.Sprintf("%s still reported: %s in %s@%s", id, f.RuleID, f.Package, f.Version))
		} else {
			other = append(other, fmt.Sprintf("new or other: %s in %s@%s (%s)", f.RuleID, f.Package, f.Version, f.Severity))
		}
	}
	r.OK = len(still) == 0
	r.Output = strings.Join(append(still, other...), "\n")
	if r.Output == "" {
		r.Output = "re-scan clean"
	}
	return r
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
