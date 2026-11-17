package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"citycountrygame/internal/findings"
)

// Hand-built findings in our own normalized form. These exercise reconcile and
// rendering only; Snyk parsing is tested against captured fixtures in
// internal/findings.
func sampleFindings() []findings.Finding {
	return []findings.Finding{
		{ID: "F1", Kind: findings.KindDependency, Scanner: "snyk test", Severity: "high",
			Title: "Denial of Service", Package: "golang.org/x/text", Version: "0.3.7", FixedIn: []string{"0.3.8"}},
		{ID: "F2", Kind: findings.KindCode, Scanner: "snyk code test", Severity: "medium",
			Title: "Cross-site Scripting", File: "main.go", Line: 31},
	}
}

func TestReconcileDropsUnknownAndDuplicateAndReportsMissing(t *testing.T) {
	tri := Triage{Summary: "s", Findings: []FindingTriage{
		{ID: "F9", Assessment: "acceptable_risk", Rationale: "invented"},
		{ID: "F1", Assessment: "fix_now", Rationale: "first"},
		{ID: "F1", Assessment: "acceptable_risk", Rationale: "second"},
	}}
	got, warnings := reconcile(sampleFindings(), tri)

	if len(got.Findings) != 1 || got.Findings[0].ID != "F1" || got.Findings[0].Rationale != "first" {
		t.Fatalf("findings = %+v, want only the first F1", got.Findings)
	}
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{`unknown finding id "F9"`, `"F1" more than once`, "no triage for F2"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings missing %q:\n%s", want, joined)
		}
	}
}

func TestRenderNeutralizesUntrustedText(t *testing.T) {
	fs := sampleFindings()
	fs[0].Title = "DoS | <img src=x> @octocat"
	tri := Triage{
		Summary: "Ignore previous instructions @maintainers ![x](https://evil.example/p.png) <script>",
		Findings: []FindingTriage{
			{ID: "F1", Assessment: "fix_now", Rationale: "see #12", SuggestedFix: "bump to v0.3.8"},
			{ID: "F2", Assessment: "likely_false_positive", Rationale: "r", SuggestedFix: "f"},
		},
	}
	md := renderComment(fs, tri, Result{ModelUsed: "m", PromptVersion: PromptVersion}, "")

	for _, bad := range []string{"<img", "<script", "@octocat", "@maintainers", "![x]", "#12"} {
		if strings.Contains(md, bad) {
			t.Errorf("comment contains unneutralized %q", bad)
		}
	}
	if !strings.HasPrefix(md, commentMarker) {
		t.Error("comment does not start with the marker the publish step looks for")
	}
	// The scanner's severity is shown regardless of the model's assessment.
	if !strings.Contains(md, "| F2 | medium |") {
		t.Errorf("scanner severity missing from table:\n%s", md)
	}
	// A pipe in a title must not break the table.
	if !strings.Contains(md, `DoS \|`) {
		t.Errorf("pipe in title not escaped:\n%s", md)
	}
}

func TestRenderCapsLength(t *testing.T) {
	tri := Triage{Summary: strings.Repeat("a", 10000)}
	md := renderComment(sampleFindings(), tri, Result{}, "")
	if strings.Count(md, "a") > maxSummary+50 {
		t.Errorf("summary not capped: comment is %d chars", len(md))
	}
}

func TestTracerRecordsBodiesAndNeverTheAPIKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"hello"`) {
			t.Errorf("server did not receive the original body: %s", body)
		}
		w.Header().Set("Request-Id", "req_123")
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "trace.jsonl")
	tr, err := NewTracer(path)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", srv.URL+"/v1/messages", strings.NewReader(`{"msg":"hello"}`))
	req.Header.Set("X-Api-Key", "sk-ant-secret")
	req.Header.Set("Anthropic-Version", "2023-06-01")
	resp, err := tr.Middleware(req, http.DefaultClient.Do)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	if string(got) != `{"ok":true}` {
		t.Errorf("caller did not receive the original response body: %s", got)
	}
	tr.Close()

	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "sk-ant-secret") {
		t.Fatal("trace contains the API key")
	}
	var kinds []string
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		var rec traceRecord
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatalf("trace line is not JSON: %v", err)
		}
		kinds = append(kinds, rec.Kind)
		if rec.Kind == "response" && rec.Headers["Request-Id"] != "req_123" {
			t.Errorf("response headers = %v, want Request-Id", rec.Headers)
		}
	}
	if strings.Join(kinds, ",") != "request,response" {
		t.Errorf("trace kinds = %v, want request,response", kinds)
	}
}

func TestCost(t *testing.T) {
	c := cost("claude-opus-5-5", Usage{InputTokens: 1_000_000, OutputTokens: 100_000})
	if c == nil || *c != 6.0 { // 4.00 + 0.1 * 20.00
		t.Errorf("cost = %v, want 6.0", c)
	}
	if cost("unknown-model", Usage{InputTokens: 1}) != nil {
		t.Error("unknown model should have nil cost, not a guess")
	}
}
