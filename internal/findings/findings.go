// Package findings turns scanner output into a normalized list of findings.
//
// Finding is this project's own contract, not Snyk's schema. The Snyk-specific
// parsers map captured scanner output onto it and are written and tested against
// real fixtures in testdata/, never against the documented schema.
//
// Everything in a Finding that came from the scanner (titles, descriptions,
// package names, file paths) is untrusted input: it can carry text written by a
// dependency author or a code comment. Callers must treat it as data.
package findings

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"unicode/utf8"
)

// Kind distinguishes the two remediation paths: bump a version or edit source.
type Kind string

const (
	KindDependency Kind = "dependency" // snyk test (SCA)
	KindCode       Kind = "code"       // snyk code test (SAST)
)

// Finding is one scanner result, normalized across scanners.
type Finding struct {
	// ID is assigned by this package (F1, F2, ...) in a deterministic order so
	// the model can refer to findings and its answers can be checked against the
	// input. It is never taken from scanner output.
	ID string `json:"id"`

	Kind     Kind   `json:"kind"`
	Scanner  string `json:"scanner"`  // "snyk test" or "snyk code test"
	RuleID   string `json:"rule_id"`  // Snyk vulnerability ID or Code rule ID
	Title    string `json:"title"`    // untrusted
	Severity string `json:"severity"` // scanner-assigned: low, medium, high, critical

	// Dependency findings.
	Package string   `json:"package,omitempty"`
	Version string   `json:"version,omitempty"`
	FixedIn []string `json:"fixed_in,omitempty"`
	CVEs    []string `json:"cves,omitempty"`
	Path    []string `json:"path,omitempty"` // dependency chain from the root module

	// Code findings.
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`

	Description string `json:"description,omitempty"` // untrusted, truncated
}

// Expected file names inside the findings artifact, matching the
// --json-file-output paths in .github/workflows/pipeline.yml.
const (
	SCAFile    = "snyk-test.json"
	SASTFile   = "snyk-code.json"
	StatusFile = "scan-status.json"
)

// ScanStatus is written by the security-scan job, not by Snyk: the GitHub
// Actions step outcome ("success", "failure", "cancelled", "skipped") of each
// scan step. It exists because `snyk code test` does not write its
// --json-file-output file when it finds nothing, so a missing file alone
// cannot distinguish a clean scan from one that never ran.
type ScanStatus struct {
	SCA  string `json:"sca"`
	SAST string `json:"sast"`
}

// ErrNotImplemented marks the Snyk mappings that are written only once real
// captured output exists in testdata/.
var ErrNotImplemented = errors.New("snyk parser not implemented: waiting on captured fixtures")

// LoadDir reads both scanner outputs from dir and returns the combined,
// ID-assigned findings. An absent scan result must never be mistaken for a
// clean one: a missing findings file is accepted as zero findings only when
// scan-status.json records that scan step as "success", and a missing or
// unreadable status file is itself an error.
func LoadDir(dir string) ([]Finding, error) {
	sb, err := os.ReadFile(filepath.Join(dir, StatusFile))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", StatusFile, err)
	}
	var st ScanStatus
	if err := json.Unmarshal(sb, &st); err != nil {
		return nil, fmt.Errorf("parse %s: %w", StatusFile, err)
	}
	if st.SCA == "" || st.SAST == "" {
		return nil, fmt.Errorf("%s: missing sca or sast outcome", StatusFile)
	}

	var all []Finding
	for _, src := range []struct {
		name    string
		outcome string
		parse   func([]byte) ([]Finding, error)
	}{
		{SCAFile, st.SCA, ParseSnykTest},
		{SASTFile, st.SAST, ParseSnykCode},
	} {
		b, err := os.ReadFile(filepath.Join(dir, src.name))
		if errors.Is(err, fs.ErrNotExist) && src.outcome == "success" {
			continue // clean scan: Snyk wrote no output file
		}
		if err != nil {
			return nil, fmt.Errorf("read %s (scan step outcome %q): %w", src.name, src.outcome, err)
		}
		found, err := src.parse(b)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", src.name, err)
		}
		all = append(all, found...)
	}
	for i := range all {
		all[i].ID = fmt.Sprintf("F%d", i+1)
	}
	return all, nil
}

// maxDescription caps the untrusted description text passed downstream. Snyk
// descriptions are long markdown advisories; the model needs the gist, and a
// cap bounds how much attacker-influenced text reaches the prompt.
const maxDescription = 1000

// snykTestReport is the subset of `snyk test --json-file-output` this package
// reads, as observed in testdata/snyk-test.json (single Go module, gomodules).
type snykTestReport struct {
	// Pointer so a missing key (an error report, or a different output shape)
	// is distinguishable from an empty list (a clean scan).
	Vulnerabilities *[]snykVuln `json:"vulnerabilities"`
	Error           string      `json:"error"`
}

type snykVuln struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	PackageName string   `json:"packageName"`
	Version     string   `json:"version"`
	FixedIn     []string `json:"fixedIn"`
	From        []string `json:"from"`
	Description string   `json:"description"`
	Identifiers struct {
		CVE []string `json:"CVE"`
	} `json:"identifiers"`
}

// ParseSnykTest maps `snyk test --json-file-output` output to findings.
//
// Snyk emits one entry per dependency path, so the same vulnerability in the
// same package version appears many times. Those collapse to one Finding that
// keeps the shortest path (first seen wins ties). Output is sorted by rule ID,
// package and version so IDs assigned by LoadDir are stable across runs.
func ParseSnykTest(b []byte) ([]Finding, error) {
	var r snykTestReport
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if r.Error != "" {
		return nil, fmt.Errorf("snyk reported an error: %s", r.Error)
	}
	if r.Vulnerabilities == nil {
		return nil, errors.New(`no "vulnerabilities" key: not a recognized snyk test report`)
	}

	type key struct{ id, pkg, ver string }
	byKey := map[key]*Finding{}
	var order []key
	for i, v := range *r.Vulnerabilities {
		if v.ID == "" || v.PackageName == "" {
			return nil, fmt.Errorf("vulnerability %d: missing id or packageName", i)
		}
		k := key{v.ID, v.PackageName, v.Version}
		if f, ok := byKey[k]; ok {
			if len(v.From) < len(f.Path) {
				f.Path = v.From
			}
			continue
		}
		byKey[k] = &Finding{
			Kind:        KindDependency,
			Scanner:     "snyk test",
			RuleID:      v.ID,
			Title:       v.Title,
			Severity:    v.Severity,
			Package:     v.PackageName,
			Version:     v.Version,
			FixedIn:     v.FixedIn,
			CVEs:        v.Identifiers.CVE,
			Path:        v.From,
			Description: truncate(v.Description, maxDescription),
		}
		order = append(order, k)
	}

	sort.Slice(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if a.id != b.id {
			return a.id < b.id
		}
		if a.pkg != b.pkg {
			return a.pkg < b.pkg
		}
		return a.ver < b.ver
	})
	out := make([]Finding, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	return out, nil
}

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

// ParseSnykCode maps `snyk code test --json-file-output` output to findings.
func ParseSnykCode(b []byte) ([]Finding, error) { return nil, ErrNotImplemented }
