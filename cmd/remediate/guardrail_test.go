package main

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// These tests enforce the invariant in CLAUDE.md: the agent binary never
// imports or calls a GitHub client and never reads GITHUB_TOKEN. They check the
// code, not a promise in a prompt.

// forbiddenImport reports whether an import path is a GitHub API client.
// Matching is on the client libraries, not on the "github.com/" host prefix,
// which nearly every Go module path starts with.
func forbiddenImport(path string) bool {
	for _, s := range []string{
		"google/go-github",
		"shurcooL/githubv4",
		"cli/go-gh",
		"octokit",
	} {
		if strings.Contains(path, s) {
			return true
		}
	}
	return false
}

// agentSourceDirs are the packages compiled into the agent binary that this
// repo owns.
var agentSourceDirs = []string{".", "../../internal/findings"}

func TestNoGitHubClientInAgentDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	for _, pkg := range strings.Fields(string(out)) {
		if forbiddenImport(pkg) {
			t.Errorf("agent binary depends on GitHub client package %q", pkg)
		}
	}
}

func TestAgentSourceNeverReferencesGitHubCredentials(t *testing.T) {
	forbidden := []string{"GITHUB_TOKEN", "GH_TOKEN", "api.github.com", "ACTIONS_RUNTIME_TOKEN"}
	for _, dir := range agentSourceDirs {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range forbidden {
				if strings.Contains(string(b), s) {
					t.Errorf("%s references %q", f, s)
				}
			}
			af, err := parser.ParseFile(token.NewFileSet(), f, b, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range af.Imports {
				if forbiddenImport(strings.Trim(imp.Path.Value, `"`)) {
					t.Errorf("%s imports GitHub client %s", f, imp.Path.Value)
				}
			}
		}
	}
}

func TestForbiddenImportMatcher(t *testing.T) {
	for path, want := range map[string]bool{
		"github.com/google/go-github/v66/github":    true,
		"github.com/shurcooL/githubv4":              true,
		"github.com/cli/go-gh/v2/pkg/api":           true,
		"github.com/anthropics/anthropic-sdk-go/v2": false,
		"golang.org/x/text/language":                false,
	} {
		if got := forbiddenImport(path); got != want {
			t.Errorf("forbiddenImport(%q) = %v, want %v", path, got, want)
		}
	}
}
