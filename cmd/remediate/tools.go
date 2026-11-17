package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go/v2"

	"citycountrygame/internal/findings"
)

// Outcomes the model may report through finalize.
const (
	OutcomePatched   = "patched"   // a change was made and verification passed
	OutcomeUnfixable = "unfixable" // tried, or judged no safe fix exists; explain why
	OutcomeNoChange  = "no_change" // no change warranted (e.g. accepted risk)
)

// Final is the model's terminal answer, recorded by the finalize tool.
type Final struct {
	Outcome string          `json:"outcome"`
	Summary string          `json:"summary"`
	Tried   string          `json:"approaches_tried"`
	Items   []FindingTriage `json:"findings"`
}

func (f Final) Triage() Triage { return Triage{Summary: f.Summary, Findings: f.Items} }

// toolRunner is what the loop needs from the tool layer; tests substitute a fake.
type toolRunner interface {
	Defs() []anthropic.BetaToolUnionParam
	Call(ctx context.Context, name string, input json.RawMessage) (out string, isError bool)
	Final() *Final
}

// Toolbox implements the tools over a Workspace and holds the run's state:
// the verification count and whether anything changed since the last one.
type Toolbox struct {
	ws            *Workspace
	fs            []findings.Finding
	snykBin       string
	verifications []Verification
	changed       bool // the worktree differs from HEAD
	dirty         bool // changed since the last verification
	final         *Final
}

func NewToolbox(ws *Workspace, fs []findings.Finding, snykBin string) *Toolbox {
	return &Toolbox{ws: ws, fs: fs, snykBin: snykBin}
}

func (t *Toolbox) Final() *Final                 { return t.final }
func (t *Toolbox) Verifications() []Verification { return t.verifications }

// lastPassed reports whether the most recent verification passed and nothing
// has changed since. This is the gate for reporting OutcomePatched.
func (t *Toolbox) lastPassed() bool {
	n := len(t.verifications)
	return n > 0 && t.verifications[n-1].Passed && !t.dirty && t.changed
}

func (t *Toolbox) Call(ctx context.Context, name string, input json.RawMessage) (string, bool) {
	switch name {
	case "read_file":
		var in struct{ Path string }
		if err := json.Unmarshal(input, &in); err != nil {
			return "invalid input: " + err.Error(), true
		}
		s, err := t.ws.ReadFile(in.Path)
		if err != nil {
			return err.Error(), true
		}
		return s, false

	case "list_dependencies":
		reqs, err := t.ws.ListDependencies(ctx)
		if err != nil {
			return err.Error(), true
		}
		b, _ := json.MarshalIndent(reqs, "", "  ")
		return string(b), false

	case "set_dependency":
		var in struct{ Module, Version string }
		if err := json.Unmarshal(input, &in); err != nil {
			return "invalid input: " + err.Error(), true
		}
		out, err := t.ws.SetDependency(ctx, in.Module, in.Version)
		if err != nil {
			return err.Error(), true
		}
		t.changed, t.dirty = true, true
		return out, false

	case "run_verification":
		if len(t.verifications) >= MaxVerifications {
			return fmt.Sprintf("verification budget exhausted (%d of %d used). Call finalize.", MaxVerifications, MaxVerifications), true
		}
		v := Verify(ctx, t.ws, t.fs, t.snykBin, len(t.verifications)+1)
		t.verifications = append(t.verifications, v)
		t.dirty = false
		return formatVerification(v), false

	case "finalize":
		var f Final
		if err := json.Unmarshal(input, &f); err != nil {
			return "invalid input: " + err.Error(), true
		}
		if f.Outcome == OutcomePatched && !t.lastPassed() {
			if len(t.verifications) < MaxVerifications {
				return "outcome \"patched\" requires a change followed by a passing run_verification with no changes since. Verify, or finalize as \"unfixable\".", true
			}
			// Out of attempts: record honestly rather than refuse forever.
			f.Outcome = OutcomeUnfixable
		}
		t.final = &f
		return "recorded", false
	}
	return fmt.Sprintf("unknown tool %q", name), true
}

func formatVerification(v Verification) string {
	var b strings.Builder
	verdict := "FAILED"
	if v.Passed {
		verdict = "PASSED"
	}
	fmt.Fprintf(&b, "Verification attempt %d of %d: %s\n", v.Attempt, MaxVerifications, verdict)
	for _, s := range v.Steps {
		status := "ok"
		switch {
		case s.Skipped:
			status = "skipped"
		case !s.OK:
			status = "FAILED"
		}
		fmt.Fprintf(&b, "\n## %s: %s\n%s\n", s.Name, status, s.Output)
	}
	return b.String()
}

// ---- tool definitions -------------------------------------------------------

func obj(props map[string]any, required ...string) anthropic.BetaToolInputSchemaParam {
	if props == nil {
		props = map[string]any{}
	}
	return anthropic.BetaToolInputSchemaParam{
		Properties:  props,
		Required:    required,
		ExtraFields: map[string]any{"additionalProperties": false},
	}
}

func tool(name, desc string, schema anthropic.BetaToolInputSchemaParam) anthropic.BetaToolUnionParam {
	return anthropic.BetaToolUnionParam{OfTool: &anthropic.BetaToolParam{
		Name:        name,
		Description: anthropic.String(desc),
		InputSchema: schema,
		Strict:      anthropic.Bool(true),
	}}
}

var str = map[string]any{"type": "string"}

func (t *Toolbox) Defs() []anthropic.BetaToolUnionParam { return toolDefs() }

func toolDefs() []anthropic.BetaToolUnionParam {
	return []anthropic.BetaToolUnionParam{
		tool("read_file",
			"Read a text file from the repository, by path relative to the repository root. "+
				"Files under .github/ and .git/ are not accessible. Limit 64 KB.",
			obj(map[string]any{"path": str}, "path")),
		tool("list_dependencies",
			"List the require directives in go.mod: module path, version, and whether it is indirect.",
			obj(nil)),
		tool("set_dependency",
			"Upgrade one module that is already in the build graph to a newer version (same major version), "+
				"then run go mod tidy. Works for indirect dependencies too: requiring a newer version of a "+
				"transitive module overrides the older one its dependents ask for. Returns every module whose "+
				"selected version changed. Downgrades and new modules are refused.",
			obj(map[string]any{
				"module":  map[string]any{"type": "string", "description": "Module path, e.g. go.opentelemetry.io/otel"},
				"version": map[string]any{"type": "string", "description": "Target version, e.g. v1.47.0"},
			}, "module", "version")),
		tool("run_verification",
			fmt.Sprintf("Build, test, check each finding's package against its fixed-in version, and re-scan. "+
				"Limited to %d calls per run, so make your change first.", MaxVerifications),
			obj(nil)),
		tool("finalize",
			"End the run with your answer. Call exactly once. Use outcome \"patched\" only after a change and "+
				"a passing run_verification with nothing changed since.",
			obj(map[string]any{
				"outcome": map[string]any{"type": "string", "enum": []string{OutcomePatched, OutcomeUnfixable, OutcomeNoChange}},
				"summary": map[string]any{"type": "string", "description": "At most three sentences for the reviewer."},
				"approaches_tried": map[string]any{"type": "string",
					"description": "What you changed and what verification showed, attempt by attempt. Empty if nothing was tried."},
				"findings": map[string]any{
					"type": "array",
					"items": map[string]any{
						"type":                 "object",
						"additionalProperties": false,
						"required":             []string{"id", "assessment", "rationale", "suggested_fix"},
						"properties": map[string]any{
							"id": str,
							"assessment": map[string]any{"type": "string",
								"enum": []string{"fix_now", "fix_soon", "acceptable_risk", "likely_false_positive"}},
							"rationale":     str,
							"suggested_fix": str,
						},
					},
				},
			}, "outcome", "summary", "approaches_tried", "findings")),
	}
}
