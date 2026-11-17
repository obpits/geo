// Command remediate is the vulnerability remediation agent.
//
// It reads normalized scanner findings from disk, works in a scratch git
// worktree through a small set of tools (read a file, list and upgrade
// dependencies, verify), and writes result.json, comment.md, trace.jsonl and,
// when a verified fix exists, patch.diff and pr.md to disk. The only network
// calls it makes are to the Messages API and, through its tools, to the Go
// module proxy and Snyk.
//
// INVARIANT: this binary never imports a GitHub client and never reads a
// GitHub credential from the environment. Publishing is the agent-publish
// job's work, in a separate job that contains no model call.
// guardrail_test.go enforces this.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"

	"citycountrygame/internal/findings"
)

type config struct {
	findingsDir string
	outDir      string
	repoDir     string
	snykBin     string
	model       string
	effort      string
	maxTokens   int64 // per response
	tokenBudget int64 // whole run, all turns
	maxTurns    int
	timeout     time.Duration
	runURL      string
}

func main() {
	var c config
	flag.StringVar(&c.findingsDir, "findings", "findings", "directory holding scan-status.json and the snyk reports")
	flag.StringVar(&c.outDir, "out", "out", "directory to write result.json, comment.md, trace.jsonl, patch.diff and pr.md")
	flag.StringVar(&c.repoDir, "repo", ".", "git checkout to create the scratch worktree from")
	flag.StringVar(&c.snykBin, "snyk", "", "snyk CLI for the verification re-scan; empty skips the re-scan")
	flag.StringVar(&c.model, "model", "claude-opus-5-5", "model identifier")
	flag.StringVar(&c.effort, "effort", "medium", "output_config.effort: low, medium, high, xhigh, max")
	flag.Int64Var(&c.maxTokens, "max-tokens", 16000, "token ceiling for each response")
	flag.Int64Var(&c.tokenBudget, "token-budget", 400000, "token ceiling for the whole run, input and output, all turns")
	flag.IntVar(&c.maxTurns, "max-turns", 20, "maximum model calls per run")
	flag.DurationVar(&c.timeout, "timeout", 10*time.Minute, "wall-clock limit for the whole run, tools included")
	flag.StringVar(&c.runURL, "run-url", "", "workflow run URL, linked from the comment so readers can find the trace")
	flag.Parse()

	if err := run(c); err != nil {
		log.Fatal(err)
	}
}

func run(c config) error {
	start := time.Now()
	if err := os.MkdirAll(c.outDir, 0o755); err != nil {
		return err
	}
	res := Result{PromptVersion: PromptVersion, ModelRequested: c.model}
	finish := func(err error) error {
		res.DurationMS = time.Since(start).Milliseconds()
		if err != nil {
			res.Status = StatusError
			res.Error = err.Error()
		}
		if werr := writeJSON(filepath.Join(c.outDir, "result.json"), res); werr != nil {
			return errors.Join(err, werr)
		}
		return err
	}

	// The trace file is always created, so the artifact upload never has a gap
	// that could be mistaken for "the model was not called".
	tracer, err := NewTracer(filepath.Join(c.outDir, "trace.jsonl"))
	if err != nil {
		return finish(err)
	}
	defer tracer.Close()

	fs, err := findings.LoadDir(c.findingsDir)
	if err != nil {
		return finish(err)
	}
	res.FindingsCount = len(fs)
	if len(fs) == 0 {
		// Clean scan: no model call, no comment. The publish job keys off status.
		res.Status = StatusNoFindings
		return finish(nil)
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	ws, err := NewWorkspace(ctx, c.repoDir)
	if err != nil {
		return finish(err)
	}
	defer ws.Close()
	tb := NewToolbox(ws, fs, c.snykBin)

	client := anthropic.NewClient(
		option.WithMiddleware(tracer.Middleware),
		option.WithMaxRetries(2),
	)
	user, err := buildUserMessage(fs)
	if err != nil {
		return finish(err)
	}
	meta, loopErr := runLoop(ctx, client, c, user, tb)
	res.ModelUsed = meta.model
	res.StopReason = meta.stopReason
	res.Turns = meta.turns
	res.Usage = meta.usage
	res.CostUSD = cost(meta.model, meta.usage)
	res.Verifications = tb.Verifications()
	if loopErr != nil {
		return finish(loopErr)
	}

	final := tb.Final()
	tri, warnings := reconcile(fs, final.Triage())
	res.Triage = &tri
	res.Outcome = final.Outcome
	res.ApproachesTried = final.Tried
	res.Warnings = warnings

	var patch string
	switch final.Outcome {
	case OutcomePatched:
		var changed []string
		patch, changed, err = ws.Diff(ctx)
		if err != nil {
			return finish(err)
		}
		// Defence in depth: the finalize gate already required a passing
		// verification. Re-check here, and check the patch stays in bounds.
		if why := patchProblem(tb, patch, changed); why != "" {
			res.Warnings = append(res.Warnings, "patch withheld: "+why)
			res.Status = StatusUnfixable
			patch = ""
		} else {
			res.Status = StatusPatched
			res.ChangedFiles = changed
		}
	case OutcomeUnfixable:
		res.Status = StatusUnfixable
	default:
		res.Status = StatusTriaged
	}
	res.DurationMS = time.Since(start).Milliseconds()

	files := map[string]string{"comment.md": renderComment(fs, tri, res, c.runURL)}
	if patch != "" {
		files["patch.diff"] = patch
		files["pr.md"] = renderPR(fs, tri, res, c.runURL)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(c.outDir, name), []byte(body), 0o644); err != nil {
			return finish(err)
		}
	}
	return finish(nil)
}

// patchProblem returns why a patch must not be published, or "".
func patchProblem(tb *Toolbox, patch string, changed []string) string {
	if !tb.lastPassed() {
		return "the latest verification did not pass, or changes followed it"
	}
	if patch == "" || len(changed) == 0 {
		return "the worktree has no changes"
	}
	for _, p := range changed {
		if !patchAllowed[p] {
			return fmt.Sprintf("it touches %s; only go.mod and go.sum may change in this phase", p)
		}
	}
	return ""
}

type callMeta struct {
	model      string
	stopReason string
	turns      int
	usage      Usage
}

// runLoop drives the conversation until the model calls finalize. It is
// bounded by turn count, a whole-run token budget and ctx's deadline; the
// verification bound is enforced by the tools themselves.
func runLoop(ctx context.Context, client anthropic.Client, c config, user string, tools toolRunner) (callMeta, error) {
	var meta callMeta
	msgs := []anthropic.BetaMessageParam{anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(user))}
	nudged := false

	for meta.turns < c.maxTurns {
		if meta.usage.Total() >= c.tokenBudget {
			return meta, fmt.Errorf("token budget of %d exhausted after %d turns", c.tokenBudget, meta.turns)
		}
		meta.turns++
		resp, err := client.Beta.Messages.New(ctx, anthropic.BetaMessageNewParams{
			Model:     anthropic.Model(c.model),
			MaxTokens: c.maxTokens,
			System:    []anthropic.BetaTextBlockParam{{Text: systemPrompt}},
			Messages:  msgs,
			Tools:     tools.Defs(),
			ToolChoice: anthropic.BetaToolChoiceUnionParam{
				OfAuto: &anthropic.BetaToolChoiceAutoParam{DisableParallelToolUse: anthropic.Bool(true)},
			},
			OutputConfig: anthropic.BetaOutputConfigParam{Effort: anthropic.BetaOutputConfigEffort(c.effort)},
			// Caches the growing conversation prefix, so each turn pays full price
			// only for what is new.
			CacheControl: anthropic.NewBetaCacheControlEphemeralParam(),
			// If a safety classifier declines the request, the server re-serves it on
			// a fallback model inside the same call. The model that actually answered
			// is recorded from the response, never assumed from the request.
			Betas:     []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01},
			Fallbacks: anthropic.BetaFallbacksParamOfDefault(),
		})
		if err != nil {
			return meta, fmt.Errorf("messages API (turn %d): %w", meta.turns, err)
		}
		meta.model = string(resp.Model)
		meta.stopReason = string(resp.StopReason)
		meta.usage.Add(Usage{
			InputTokens:      resp.Usage.InputTokens,
			OutputTokens:     resp.Usage.OutputTokens,
			CacheReadTokens:  resp.Usage.CacheReadInputTokens,
			CacheWriteTokens: resp.Usage.CacheCreationInputTokens,
		})

		switch resp.StopReason {
		case anthropic.BetaStopReasonRefusal:
			return meta, fmt.Errorf("model refused (category %q)", resp.StopDetails.Category)
		case anthropic.BetaStopReasonMaxTokens:
			return meta, fmt.Errorf("response hit the %d-token ceiling before completing", c.maxTokens)
		}

		msgs = append(msgs, resp.ToParam())
		var results []anthropic.BetaContentBlockParamUnion
		for _, block := range resp.Content {
			tu, ok := block.AsAny().(anthropic.BetaToolUseBlock)
			if !ok {
				continue
			}
			input := json.RawMessage(tu.JSON.Input.Raw())
			if len(input) == 0 {
				input, _ = json.Marshal(tu.Input)
			}
			out, isErr := tools.Call(ctx, tu.Name, input)
			results = append(results, anthropic.NewBetaToolResultBlock(tu.ID, out, isErr))
		}
		if tools.Final() != nil {
			return meta, nil
		}
		if len(results) == 0 {
			if nudged {
				return meta, errors.New("model ended its turn twice without calling finalize")
			}
			nudged = true
			msgs = append(msgs, anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(
				"Continue with the tools, and end by calling finalize.")))
			continue
		}
		msgs = append(msgs, anthropic.NewBetaUserMessage(results...))
	}
	return meta, fmt.Errorf("no finalize after %d turns", c.maxTurns)
}

// reconcile checks the model's answer against the input. The model cannot add
// findings, drop findings silently, or answer the same one twice: unknown and
// duplicate IDs are discarded and missing ones are reported. Output order
// follows the input, not the model.
func reconcile(fs []findings.Finding, tri Triage) (Triage, []string) {
	var warnings []string
	byID := map[string]FindingTriage{}
	known := map[string]bool{}
	for _, f := range fs {
		known[f.ID] = true
	}
	for _, t := range tri.Findings {
		switch {
		case !known[t.ID]:
			warnings = append(warnings, fmt.Sprintf("model returned unknown finding id %q; discarded", t.ID))
		case byID[t.ID] != (FindingTriage{}):
			warnings = append(warnings, fmt.Sprintf("model returned finding id %q more than once; kept the first", t.ID))
		default:
			byID[t.ID] = t
		}
	}
	out := Triage{Summary: tri.Summary}
	for _, f := range fs {
		t, ok := byID[f.ID]
		if !ok {
			warnings = append(warnings, fmt.Sprintf("model returned no triage for %s", f.ID))
			continue
		}
		out.Findings = append(out.Findings, t)
	}
	return out, warnings
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
