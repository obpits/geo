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
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	SCAFile  = "snyk-test.json"
	SASTFile = "snyk-code.json"
)

// ErrNotImplemented marks the Snyk mappings that are written only once real
// captured output exists in testdata/.
var ErrNotImplemented = errors.New("snyk parser not implemented: waiting on captured fixtures")

// LoadDir reads both scanner outputs from dir and returns the combined,
// ID-assigned findings. A missing file is an error: an absent scan result must
// never be mistaken for a clean one.
func LoadDir(dir string) ([]Finding, error) {
	var all []Finding
	for _, src := range []struct {
		name  string
		parse func([]byte) ([]Finding, error)
	}{
		{SCAFile, ParseSnykTest},
		{SASTFile, ParseSnykCode},
	} {
		b, err := os.ReadFile(filepath.Join(dir, src.name))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", src.name, err)
		}
		fs, err := src.parse(b)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", src.name, err)
		}
		all = append(all, fs...)
	}
	for i := range all {
		all[i].ID = fmt.Sprintf("F%d", i+1)
	}
	return all, nil
}

// ParseSnykTest maps `snyk test --json-file-output` output to findings.
func ParseSnykTest(b []byte) ([]Finding, error) { return nil, ErrNotImplemented }

// ParseSnykCode maps `snyk code test --json-file-output` output to findings.
func ParseSnykCode(b []byte) ([]Finding, error) { return nil, ErrNotImplemented }
