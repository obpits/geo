package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"

	"citycountrygame/internal/findings"
)

// ---- path rules --------------------------------------------------------------

func TestDeniedPath(t *testing.T) {
	for p, want := range map[string]bool{
		".github/workflows/pipeline.yml": true,
		".GitHub/workflows/x.yml":        true,
		"sub/.github/x":                  true,
		".git/config":                    true,
		".git/hooks/pre-commit":          true,
		"main.go":                        false,
		"internal/findings/findings.go":  false,
		".gitignore":                     false,
		"docs/github.md":                 false,
	} {
		if got := deniedPath(p); got != want {
			t.Errorf("deniedPath(%q) = %v, want %v", p, got, want)
		}
	}
}

// newRepo creates a git repository with a go.mod, a source file and a
// workflow, committed, and returns its path.
func newRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	files := map[string]string{
		"go.mod":                         "module example.com/m\n\ngo 1.21\n",
		"main.go":                        "package main\n\nfunc main() {}\n",
		".github/workflows/pipeline.yml": "on: push\n",
	}
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		{"init", "-q"},
		{"-c", "user.email=t@example.com", "-c", "user.name=t", "add", "-A"},
		{"-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "-m", "init"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	return dir
}

func TestWorkspaceReadFileRules(t *testing.T) {
	ws, err := NewWorkspace(context.Background(), newRepo(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	if s, err := ws.ReadFile("main.go"); err != nil || !strings.Contains(s, "package main") {
		t.Fatalf("ReadFile(main.go) = %q, %v", s, err)
	}
	for _, p := range []string{
		".github/workflows/pipeline.yml",
		"./.github/workflows/pipeline.yml",
		"x/../.github/workflows/pipeline.yml",
		".git/HEAD",
		"../outside.txt",
		"/etc/passwd",
		`C:\Windows\win.ini`,
		"",
		"missing.go",
	} {
		if _, err := ws.ReadFile(p); err == nil {
			t.Errorf("ReadFile(%q) succeeded, want refusal", p)
		}
	}
}

func TestWorkspaceSymlinkCannotEscape(t *testing.T) {
	ws, err := NewWorkspace(context.Background(), newRepo(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	outside := filepath.Join(t.TempDir(), "secret.txt")
	os.WriteFile(outside, []byte("secret"), 0o644)
	links := map[string]string{
		"escape": outside,
		"wflink": filepath.Join(ws.Root, ".github", "workflows", "pipeline.yml"),
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(ws.Root, name)); err != nil {
			if runtime.GOOS == "windows" {
				t.Skipf("cannot create symlinks here: %v", err)
			}
			t.Fatal(err)
		}
		if _, err := ws.ReadFile(name); err == nil {
			t.Errorf("ReadFile(%q -> %s) succeeded, want refusal", name, target)
		}
	}
}

func TestWorkspaceDiffSeesChanges(t *testing.T) {
	ws, err := NewWorkspace(context.Background(), newRepo(t))
	if err != nil {
		t.Fatal(err)
	}
	defer ws.Close()

	os.WriteFile(filepath.Join(ws.Root, "go.mod"), []byte("module example.com/m\n\ngo 1.22\n"), 0o644)
	diff, changed, err := ws.Diff(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 1 || changed[0] != "go.mod" || !strings.Contains(diff, "+go 1.22") {
		t.Fatalf("changed=%v diff=%s", changed, diff)
	}
}

// ---- subprocess environment -------------------------------------------------

func TestToolEnvPassesNoCredentials(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-secret")
	t.Setenv("SNYK_TOKEN", "snyk-secret")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
	t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "oidc-secret")
	env := strings.Join(toolEnv(), "\n")
	for _, s := range []string{"sk-ant-secret", "snyk-secret", "aws-secret", "oidc-secret"} {
		if strings.Contains(env, s) {
			t.Errorf("tool environment contains %q", s)
		}
	}
	if !strings.Contains(env, "GOTOOLCHAIN=local") {
		t.Error("GOTOOLCHAIN=local missing")
	}
	// The Snyk step adds its own token explicitly, and nothing else.
	snyk := strings.Join(toolEnv("SNYK_TOKEN=snyk-secret"), "\n")
	if !strings.Contains(snyk, "snyk-secret") || strings.Contains(snyk, "sk-ant-secret") {
		t.Error("snyk environment should carry the Snyk token and not the API key")
	}
}

// ---- dependency policy ------------------------------------------------------

func TestCheckBump(t *testing.T) {
	graph := map[string]string{"go.opentelemetry.io/otel": "v1.33.0", "example.com/v2": "v2.1.0"}
	ok := map[[2]string]string{
		{"go.opentelemetry.io/otel", "v1.47.0"}: "v1.47.0",
		{"go.opentelemetry.io/otel", "1.47.0"}:  "v1.47.0", // scanner style, no v
	}
	for in, want := range ok {
		got, err := checkBump("example.com/main", graph, in[0], in[1])
		if err != nil || got != want {
			t.Errorf("checkBump(%v) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range [][2]string{
		{"go.opentelemetry.io/otel", "v1.33.0"},  // same
		{"go.opentelemetry.io/otel", "v1.20.0"},  // downgrade
		{"go.opentelemetry.io/otel", "v2.0.0"},   // major change
		{"go.opentelemetry.io/otel", "latest"},   // not semver
		{"go.opentelemetry.io/otel", "v1.47.0 "}, // whitespace
		{"evil.example/backdoor", "v1.0.0"},      // not in graph
		{"example.com/main", "v9.9.9"},           // own module
	} {
		if v, err := checkBump("example.com/main", graph, in[0], in[1]); err == nil {
			t.Errorf("checkBump(%v) = %q, want refusal", in, v)
		}
	}
}

func TestFixedStatus(t *testing.T) {
	cases := []struct {
		mv       string
		imported bool
		fixedIn  []string
		want     bool
	}{
		{"go.opentelemetry.io/otel v1.47.0", true, []string{"1.47.0"}, true},
		{"go.opentelemetry.io/otel v1.48.1", true, []string{"1.47.0"}, true},
		{"go.opentelemetry.io/otel v1.33.0", true, []string{"1.47.0"}, false},
		{"go.opentelemetry.io/otel v1.40.0", true, []string{"1.47.0", "1.39.2"}, true}, // lowest fixed
		{"go.opentelemetry.io/otel v1.33.0", true, nil, false},                         // no fix published
		{"", false, []string{"1.47.0"}, true},                                          // no longer imported
	}
	for _, c := range cases {
		if got, why := fixedStatus(c.mv, c.imported, c.fixedIn); got != c.want {
			t.Errorf("fixedStatus(%q, %v, %v) = %v (%s), want %v", c.mv, c.imported, c.fixedIn, got, why, c.want)
		}
	}
}

// ---- finalize gate ----------------------------------------------------------

func finalizeInput(outcome string) json.RawMessage {
	b, _ := json.Marshal(Final{Outcome: outcome, Summary: "s", Items: []FindingTriage{}})
	return b
}

func TestFinalizePatchedRequiresPassingVerification(t *testing.T) {
	ctx := context.Background()
	pass := Verification{Passed: true}
	fail := Verification{Passed: false}

	cases := []struct {
		name    string
		tb      Toolbox
		refused bool   // finalize returns an error the model must act on
		outcome string // recorded outcome when accepted
	}{
		{"never verified", Toolbox{changed: true, dirty: true}, true, ""},
		{"verified, then changed", Toolbox{changed: true, dirty: true, verifications: []Verification{pass}}, true, ""},
		{"verified but failed", Toolbox{changed: true, verifications: []Verification{fail}}, true, ""},
		{"verified with no change", Toolbox{verifications: []Verification{pass}}, true, ""},
		{"passed, nothing since", Toolbox{changed: true, verifications: []Verification{pass}}, false, OutcomePatched},
		{"out of attempts, last failed", Toolbox{changed: true, verifications: []Verification{fail, fail, fail}}, false, OutcomeUnfixable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tb := c.tb
			out, isErr := tb.Call(ctx, "finalize", finalizeInput(OutcomePatched))
			if isErr != c.refused {
				t.Fatalf("isErr = %v (%s), want %v", isErr, out, c.refused)
			}
			if c.refused {
				if tb.Final() != nil {
					t.Fatal("refused finalize still recorded a result")
				}
				return
			}
			if tb.Final().Outcome != c.outcome {
				t.Fatalf("outcome = %q, want %q", tb.Final().Outcome, c.outcome)
			}
		})
	}
}

func TestVerificationBudget(t *testing.T) {
	tb := Toolbox{verifications: make([]Verification, MaxVerifications)}
	out, isErr := tb.Call(context.Background(), "run_verification", json.RawMessage(`{}`))
	if !isErr || !strings.Contains(out, "exhausted") {
		t.Fatalf("fourth verification: %v %q", isErr, out)
	}
}

func TestPatchProblem(t *testing.T) {
	ok := &Toolbox{changed: true, verifications: []Verification{{Passed: true}}}
	if why := patchProblem(ok, "diff", []string{"go.mod", "go.sum"}); why != "" {
		t.Errorf("valid patch refused: %s", why)
	}
	if why := patchProblem(ok, "diff", []string{"go.mod", "main.go"}); why == "" {
		t.Error("patch touching main.go accepted")
	}
	if why := patchProblem(ok, "diff", []string{".github/workflows/pipeline.yml"}); why == "" {
		t.Error("patch touching the workflow accepted")
	}
	if why := patchProblem(&Toolbox{changed: true, dirty: true, verifications: []Verification{{Passed: true}}},
		"diff", []string{"go.mod"}); why == "" {
		t.Error("patch changed after verification accepted")
	}
}

// ---- loop -------------------------------------------------------------------

// fakeTools records calls and finishes when finalize is called.
type fakeTools struct {
	calls []string
	final *Final
}

func (f *fakeTools) Defs() []anthropic.BetaToolUnionParam { return toolDefs() }
func (f *fakeTools) Final() *Final                        { return f.final }
func (f *fakeTools) Call(_ context.Context, name string, in json.RawMessage) (string, bool) {
	f.calls = append(f.calls, name+" "+string(in))
	if name == "finalize" {
		var fin Final
		json.Unmarshal(in, &fin)
		f.final = &fin
	}
	return "ok from " + name, false
}

// fakeAPI serves scripted Messages API responses in order and records each
// request body.
func fakeAPI(t *testing.T, responses ...string) (*httptest.Server, *[]string) {
	t.Helper()
	var bodies []string
	i := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		if i >= len(responses) {
			t.Errorf("unexpected request %d", i+1)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, responses[i])
		i++
	}))
	t.Cleanup(srv.Close)
	return srv, &bodies
}

func toolUse(id, name, input string) string {
	return `{"id":"msg_` + id + `","type":"message","role":"assistant","model":"claude-opus-5-5",` +
		`"content":[{"type":"tool_use","id":"tu_` + id + `","name":"` + name + `","input":` + input + `}],` +
		`"stop_reason":"tool_use","usage":{"input_tokens":100,"output_tokens":10}}`
}

func endTurn(id string) string {
	return `{"id":"msg_` + id + `","type":"message","role":"assistant","model":"claude-opus-5-5",` +
		`"content":[{"type":"text","text":"done"}],"stop_reason":"end_turn","usage":{"input_tokens":100,"output_tokens":10}}`
}

func testClient(srv *httptest.Server) anthropic.Client {
	return anthropic.NewClient(option.WithBaseURL(srv.URL), option.WithAPIKey("test"), option.WithMaxRetries(0))
}

func testConfig() config {
	return config{model: "claude-opus-5-5", effort: "medium", maxTokens: 1000, tokenBudget: 1_000_000, maxTurns: 10}
}

func TestLoopRunsToolsUntilFinalize(t *testing.T) {
	srv, bodies := fakeAPI(t,
		toolUse("1", "list_dependencies", `{}`),
		toolUse("2", "set_dependency", `{"module":"go.opentelemetry.io/otel","version":"v1.47.0"}`),
		toolUse("3", "finalize", `{"outcome":"patched","summary":"s","approaches_tried":"a","findings":[]}`),
	)
	tools := &fakeTools{}
	meta, err := runLoop(context.Background(), testClient(srv), testConfig(), "<findings>[]</findings>", tools)
	if err != nil {
		t.Fatal(err)
	}
	if meta.turns != 3 || meta.usage.InputTokens != 300 || meta.usage.OutputTokens != 30 {
		t.Errorf("meta = %+v", meta)
	}
	if len(tools.calls) != 3 || !strings.HasPrefix(tools.calls[1], `set_dependency {"module":"go.opentelemetry.io/otel"`) {
		t.Errorf("calls = %v", tools.calls)
	}
	if tools.final == nil || tools.final.Outcome != "patched" {
		t.Errorf("final = %+v", tools.final)
	}
	// Each later request carries the previous tool result back to the model.
	if !strings.Contains((*bodies)[1], `"tool_use_id":"tu_1"`) || !strings.Contains((*bodies)[1], "ok from list_dependencies") {
		t.Errorf("second request lacks the first tool result:\n%s", (*bodies)[1])
	}
}

func TestLoopNudgesOnceThenFails(t *testing.T) {
	srv, _ := fakeAPI(t, endTurn("1"), endTurn("2"))
	_, err := runLoop(context.Background(), testClient(srv), testConfig(), "x", &fakeTools{})
	if err == nil || !strings.Contains(err.Error(), "without calling finalize") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoopStopsAtTurnLimit(t *testing.T) {
	c := testConfig()
	c.maxTurns = 2
	srv, _ := fakeAPI(t, toolUse("1", "list_dependencies", `{}`), toolUse("2", "list_dependencies", `{}`))
	_, err := runLoop(context.Background(), testClient(srv), c, "x", &fakeTools{})
	if err == nil || !strings.Contains(err.Error(), "no finalize after 2 turns") {
		t.Fatalf("err = %v", err)
	}
}

func TestLoopStopsAtTokenBudget(t *testing.T) {
	c := testConfig()
	c.tokenBudget = 150 // one response uses 110
	srv, _ := fakeAPI(t, toolUse("1", "list_dependencies", `{}`), toolUse("2", "list_dependencies", `{}`))
	meta, err := runLoop(context.Background(), testClient(srv), c, "x", &fakeTools{})
	if err == nil || !strings.Contains(err.Error(), "token budget") || meta.turns != 2 {
		t.Fatalf("turns=%d err=%v", meta.turns, err)
	}
}

// ---- rendering of verification evidence ---------------------------------------

func TestRenderNeutralizesCommandOutput(t *testing.T) {
	res := Result{
		Status: StatusUnfixable,
		Verifications: []Verification{{Attempt: 1, Steps: []StepResult{
			{Name: "go test", Output: "FAIL </pre><img src=x> @octocat ![p](https://evil.example/p.png)"},
		}}},
		ApproachesTried: "tried <script> and #5",
	}
	md := renderComment([]findings.Finding{}, Triage{}, res, "")
	for _, bad := range []string{"</pre><img", "<img", "<script", "@octocat", "![p]", "#5"} {
		if strings.Contains(md, bad) {
			t.Errorf("comment contains unneutralized %q", bad)
		}
	}
	if !strings.Contains(md, "without a verified fix") {
		t.Errorf("unfixable heading missing:\n%s", md)
	}
}
