package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

// Workspace is a scratch git worktree of the checked-out commit. Every file the
// model can read and every command its tools run goes through it, so staged
// changes never touch the real checkout and a failed run leaves nothing behind.
type Workspace struct {
	Root string // absolute, symlinks resolved
	repo string
	tmp  string
}

// NewWorkspace adds a detached worktree of repoDir's HEAD in a temp directory.
func NewWorkspace(ctx context.Context, repoDir string) (*Workspace, error) {
	tmp, err := os.MkdirTemp("", "remediate-*")
	if err != nil {
		return nil, err
	}
	wt := filepath.Join(tmp, "wt")
	if out, err := runCmd(ctx, repoDir, toolEnv(), 2*time.Minute, "git", "worktree", "add", "--detach", wt, "HEAD"); err != nil {
		os.RemoveAll(tmp)
		return nil, fmt.Errorf("git worktree add: %w: %s", err, out)
	}
	root, err := filepath.EvalSymlinks(wt)
	if err != nil {
		os.RemoveAll(tmp)
		return nil, err
	}
	return &Workspace{Root: root, repo: repoDir, tmp: tmp}, nil
}

func (w *Workspace) Close() error {
	_, err := runCmd(context.Background(), w.repo, toolEnv(), time.Minute, "git", "worktree", "remove", "--force", w.Root)
	return errors.Join(err, os.RemoveAll(w.tmp))
}

// ---- path rules ------------------------------------------------------------

// deniedPath reports whether a slash-separated, workspace-relative path is off
// limits. .github is denied so the agent can never read or edit the workflow
// that constrains it; .git so it cannot touch repository internals or hooks.
// Matching is case-insensitive because the runner's filesystem may not be.
func deniedPath(rel string) bool {
	for _, seg := range strings.Split(rel, "/") {
		switch strings.ToLower(seg) {
		case ".github", ".git":
			return true
		}
	}
	return false
}

// resolve maps a model-supplied path to an absolute path inside the workspace,
// or refuses. The check runs twice: on the path as written, and on the real
// path after symlinks, so a link inside the repo cannot point outside it or
// into a denied directory.
func (w *Workspace) resolve(p string) (string, error) {
	if p == "" || strings.ContainsRune(p, 0) || filepath.IsAbs(p) || filepath.VolumeName(p) != "" ||
		strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) {
		return "", fmt.Errorf("path %q: must be relative to the repository root", p)
	}
	clean := filepath.Clean(filepath.FromSlash(p))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q: outside the repository", p)
	}
	if deniedPath(filepath.ToSlash(clean)) {
		return "", fmt.Errorf("path %q: access denied", p)
	}
	real, err := filepath.EvalSymlinks(filepath.Join(w.Root, clean))
	if err != nil {
		return "", fmt.Errorf("path %q: not found", p)
	}
	rel, err := filepath.Rel(w.Root, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q: resolves outside the repository", p)
	}
	if deniedPath(filepath.ToSlash(rel)) {
		return "", fmt.Errorf("path %q: access denied", p)
	}
	return real, nil
}

const maxReadBytes = 64 << 10

func (w *Workspace) ReadFile(p string) (string, error) {
	full, err := w.resolve(p)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(full)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("path %q is a directory", p)
	}
	if info.Size() > maxReadBytes {
		return "", fmt.Errorf("path %q is %d bytes; the limit is %d", p, info.Size(), maxReadBytes)
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return "", err
	}
	if bytes.IndexByte(b, 0) >= 0 {
		return "", fmt.Errorf("path %q is a binary file", p)
	}
	return string(b), nil
}

// ---- dependencies ----------------------------------------------------------

type Requirement struct {
	Path     string `json:"path"`
	Version  string `json:"version"`
	Indirect bool   `json:"indirect,omitempty"`
}

// ListDependencies returns go.mod's require list.
func (w *Workspace) ListDependencies(ctx context.Context) ([]Requirement, error) {
	out, err := runCmd(ctx, w.Root, toolEnv(), time.Minute, "go", "mod", "edit", "-json")
	if err != nil {
		return nil, fmt.Errorf("go mod edit -json: %w: %s", err, out)
	}
	var mod struct {
		Require []Requirement
	}
	if err := json.Unmarshal(out, &mod); err != nil {
		return nil, err
	}
	return mod.Require, nil
}

// moduleGraph returns the main module path and the selected version of every
// module in the build graph (`go list -m all`).
func (w *Workspace) moduleGraph(ctx context.Context) (string, map[string]string, error) {
	out, err := runCmd(ctx, w.Root, toolEnv(), 2*time.Minute, "go", "list", "-m", "all")
	if err != nil {
		return "", nil, fmt.Errorf("go list -m all: %w: %s", err, out)
	}
	var main string
	graph := map[string]string{}
	for i, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(line)
		if i == 0 {
			main = f[0]
			continue
		}
		if len(f) >= 2 {
			graph[f[0]] = f[1]
		}
	}
	return main, graph, nil
}

// checkBump is the policy for set_dependency: the module must already be in
// the build graph (the agent can change versions, never introduce code from a
// module the project does not already use), and the version must be a valid
// semantic version strictly newer than the one selected now. It returns the
// normalized version.
func checkBump(mainModule string, graph map[string]string, module, version string) (string, error) {
	if module == mainModule {
		return "", fmt.Errorf("%s is this repository's own module", module)
	}
	cur, ok := graph[module]
	if !ok {
		return "", fmt.Errorf("%s is not in the module graph; only existing dependencies can be changed", module)
	}
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	if !semver.IsValid(version) {
		return "", fmt.Errorf("%q is not a valid semantic version", version)
	}
	if semver.Major(version) != semver.Major(cur) {
		return "", fmt.Errorf("%s is a major-version change from %s; Go treats that as a different module path", version, cur)
	}
	if semver.Compare(version, cur) <= 0 {
		return "", fmt.Errorf("%s is not newer than the selected %s; only upgrades are allowed", version, cur)
	}
	return version, nil
}

// SetDependency upgrades module to version with `go get`, then `go mod tidy`,
// and reports every module whose selected version changed as a result.
func (w *Workspace) SetDependency(ctx context.Context, module, version string) (string, error) {
	mainMod, before, err := w.moduleGraph(ctx)
	if err != nil {
		return "", err
	}
	version, err = checkBump(mainMod, before, module, version)
	if err != nil {
		return "", err
	}
	if out, err := runCmd(ctx, w.Root, toolEnv(), 3*time.Minute, "go", "get", module+"@"+version); err != nil {
		return "", fmt.Errorf("go get %s@%s failed: %s", module, version, tail(out, 2000))
	}
	if out, err := runCmd(ctx, w.Root, toolEnv(), 3*time.Minute, "go", "mod", "tidy"); err != nil {
		return "", fmt.Errorf("go mod tidy failed: %s", tail(out, 2000))
	}
	_, after, err := w.moduleGraph(ctx)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Upgraded %s to %s. Selected versions that changed:\n", module, version)
	for _, m := range sortedKeys(after) {
		if before[m] != after[m] {
			fmt.Fprintf(&b, "  %s %s -> %s\n", m, orNone(before[m]), after[m])
		}
	}
	for _, m := range sortedKeys(before) {
		if _, ok := after[m]; !ok {
			fmt.Fprintf(&b, "  %s %s -> (removed)\n", m, before[m])
		}
	}
	return b.String(), nil
}

// Diff stages everything in the worktree and returns the unified diff and the
// list of changed paths.
func (w *Workspace) Diff(ctx context.Context) (string, []string, error) {
	if out, err := runCmd(ctx, w.Root, toolEnv(), time.Minute, "git", "add", "-A"); err != nil {
		return "", nil, fmt.Errorf("git add: %w: %s", err, out)
	}
	names, err := runCmd(ctx, w.Root, toolEnv(), time.Minute, "git", "diff", "--cached", "--name-only")
	if err != nil {
		return "", nil, fmt.Errorf("git diff --name-only: %w: %s", err, names)
	}
	diff, err := runCmd(ctx, w.Root, toolEnv(), time.Minute, "git", "diff", "--cached")
	if err != nil {
		return "", nil, fmt.Errorf("git diff: %w: %s", err, diff)
	}
	return string(diff), strings.Fields(string(names)), nil
}

// patchAllowed lists the only paths a patch may touch in this phase
// (dependency upgrades). The publish job enforces the same list independently.
var patchAllowed = map[string]bool{"go.mod": true, "go.sum": true}

// ---- subprocesses ----------------------------------------------------------

// passEnv is the allowlist of environment variables a tool subprocess inherits.
// It is an allowlist, not a denylist, so no credential reaches `go test`, which
// runs code the model chose (dependency versions now, source edits later). In
// particular the Anthropic API key is never passed on.
var passEnv = map[string]bool{
	"PATH": true, "HOME": true, "USERPROFILE": true, "TMPDIR": true, "TEMP": true, "TMP": true,
	"SYSTEMROOT": true, "SYSTEMDRIVE": true, "COMSPEC": true, "PATHEXT": true, "WINDIR": true,
	"LOCALAPPDATA": true, "APPDATA": true, "PROGRAMDATA": true,
	"GOPATH": true, "GOMODCACHE": true, "GOCACHE": true, "GOPROXY": true, "GOSUMDB": true,
	"GOPRIVATE": true, "GONOSUMDB": true, "GONOPROXY": true,
	"LANG": true, "LC_ALL": true,
}

// toolEnv builds a subprocess environment from the allowlist plus extra
// entries. GOTOOLCHAIN=local stops a dependency's go directive from silently
// downloading and running a different toolchain.
func toolEnv(extra ...string) []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if passEnv[strings.ToUpper(k)] {
			env = append(env, kv)
		}
	}
	env = append(env, "GOTOOLCHAIN=local", "GOFLAGS=")
	return append(env, extra...)
}

// runCmd executes a command in dir with the given environment and a timeout
// bounded by ctx, returning combined output.
func runCmd(ctx context.Context, dir string, env []string, timeout time.Duration, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("%s timed out after %s", name, timeout)
	}
	return out, err
}

// tail keeps the last n bytes of output, where build and test failures report.
func tail(b []byte, n int) string {
	s := strings.TrimSpace(string(b))
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
