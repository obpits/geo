package findings

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// TestParseSnykTestFixture runs against real output captured from the
// security-scan job (testdata/snyk-test.json): 16 path entries covering two
// vulnerabilities in go.opentelemetry.io, pulled in by anthropic-sdk-go.
func TestParseSnykTestFixture(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("testdata", SCAFile))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := ParseSnykTest(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("got %d findings, want 2 (16 path entries, 2 unique vulns)", len(fs))
	}

	baggage, prop := fs[0], fs[1]
	if baggage.RuleID != "SNYK-GOLANG-GOOPENTELEMETRYIOOTELBAGGAGE-22566138" ||
		prop.RuleID != "SNYK-GOLANG-GOOPENTELEMETRYIOOTELPROPAGATION-22566137" {
		t.Fatalf("unexpected order: %s, %s", baggage.RuleID, prop.RuleID)
	}

	for _, f := range fs {
		if f.Kind != KindDependency || f.Scanner != "snyk test" {
			t.Errorf("%s: kind=%q scanner=%q", f.RuleID, f.Kind, f.Scanner)
		}
		if f.Severity != "medium" || f.Version != "1.33.0" {
			t.Errorf("%s: severity=%q version=%q", f.RuleID, f.Severity, f.Version)
		}
		if !reflect.DeepEqual(f.FixedIn, []string{"1.47.0"}) {
			t.Errorf("%s: fixedIn=%v", f.RuleID, f.FixedIn)
		}
		if !reflect.DeepEqual(f.CVEs, []string{"CVE-2026-128086"}) {
			t.Errorf("%s: cves=%v", f.RuleID, f.CVEs)
		}
		if f.Title == "" || f.Description == "" {
			t.Errorf("%s: empty title or description", f.RuleID)
		}
		if len(f.Description) > maxDescription+len("…") {
			t.Errorf("%s: description not truncated (%d bytes)", f.RuleID, len(f.Description))
		}
		if f.ID != "" {
			t.Errorf("%s: parser must not assign IDs, got %q", f.RuleID, f.ID)
		}
		if len(f.Path) == 0 || f.Path[0] != "citycountrygame@0.0.0" ||
			f.Path[len(f.Path)-1] != f.Package+"@"+f.Version {
			t.Errorf("%s: path %v does not run root -> package", f.RuleID, f.Path)
		}
	}

	// Shortest of the dependency paths in the fixture.
	wantProp := []string{
		"citycountrygame@0.0.0",
		"github.com/anthropics/anthropic-sdk-go/v2@2.10.0",
		"github.com/anthropics/anthropic-sdk-go/v2/internal/tracing@2.10.0",
		"go.opentelemetry.io/otel/propagation@1.33.0",
	}
	if !reflect.DeepEqual(prop.Path, wantProp) {
		t.Errorf("propagation path = %v\nwant %v", prop.Path, wantProp)
	}
}

func TestParseSnykTestClean(t *testing.T) {
	fs, err := ParseSnykTest([]byte(`{"ok": true, "vulnerabilities": []}`))
	if err != nil || len(fs) != 0 {
		t.Fatalf("clean report: got %v, %v", fs, err)
	}
}

// An absent or unrecognized result must never read as a clean scan.
func TestParseSnykTestRejects(t *testing.T) {
	for name, in := range map[string]string{
		"error report":   `{"ok": false, "error": "Authentication failed"}`,
		"no vulns key":   `{"ok": true}`,
		"array output":   `[{"vulnerabilities": []}]`,
		"not json":       `Snyk CLI failed`,
		"missing fields": `{"vulnerabilities": [{"title": "x"}]}`,
	} {
		if _, err := ParseSnykTest([]byte(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

// writeDir builds a findings directory. A nil value means the file is absent.
func writeDir(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, b := range files {
		if b == nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadDir(t *testing.T) {
	sca, err := os.ReadFile(filepath.Join("testdata", SCAFile))
	if err != nil {
		t.Fatal(err)
	}
	status := func(sca, sast string) []byte {
		return []byte(`{"sca":"` + sca + `","sast":"` + sast + `"}`)
	}

	// The real run: SCA found issues, SAST was clean and wrote no file.
	t.Run("clean sast, no file", func(t *testing.T) {
		dir := writeDir(t, map[string][]byte{
			StatusFile: status("failure", "success"),
			SCAFile:    sca,
		})
		fs, err := LoadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(fs) != 2 || fs[0].ID != "F1" || fs[1].ID != "F2" {
			t.Fatalf("got %d findings, ids %v", len(fs), fs)
		}
	})

	t.Run("both clean, no files", func(t *testing.T) {
		dir := writeDir(t, map[string][]byte{StatusFile: status("success", "success")})
		fs, err := LoadDir(dir)
		if err != nil || len(fs) != 0 {
			t.Fatalf("got %v, %v", fs, err)
		}
	})

	for name, files := range map[string]map[string][]byte{
		"sast failed, no file": {StatusFile: status("failure", "failure"), SCAFile: sca},
		"sast skipped":         {StatusFile: status("failure", "skipped"), SCAFile: sca},
		"sca failed, no file":  {StatusFile: status("failure", "success")},
		"no status file":       {SCAFile: sca},
		"empty status":         {StatusFile: []byte(`{}`), SCAFile: sca},
		"garbage status":       {StatusFile: []byte(`success`), SCAFile: sca},
	} {
		t.Run(name, func(t *testing.T) {
			if fs, err := LoadDir(writeDir(t, files)); err == nil {
				t.Fatalf("expected error, got %d findings", len(fs))
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	s := strings.Repeat("é", 10) // 2 bytes per rune
	got := truncate(s, 5)
	if !utf8.ValidString(got) || got != "éé…" {
		t.Errorf("truncate = %q", got)
	}
	if truncate("short", 10) != "short" {
		t.Error("short string changed")
	}
}
