// Command remediate is the vulnerability remediation agent.
//
// Phase 1: read normalized scanner findings from disk, make one Messages API
// call that returns a structured triage, and write result.json, comment.md and
// trace.jsonl to disk. It makes no other network calls.
//
// INVARIANT: this binary never imports a GitHub client and never reads a
// GitHub credential from the environment. Publishing the triage is the agent-comment job's work, in a
// separate job that contains no model call. guardrail_test.go enforces this.
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
	model       string
	effort      string
	maxTokens   int64
	timeout     time.Duration
	runURL      string
}

func main() {
	var c config
	flag.StringVar(&c.findingsDir, "findings", "findings", "directory holding snyk-test.json and snyk-code.json")
	flag.StringVar(&c.outDir, "out", "out", "directory to write result.json, comment.md and trace.jsonl")
	flag.StringVar(&c.model, "model", "claude-opus-5-5", "model identifier")
	flag.StringVar(&c.effort, "effort", "medium", "output_config.effort: low, medium, high, xhigh, max")
	flag.Int64Var(&c.maxTokens, "max-tokens", 16000, "token ceiling for the response")
	flag.DurationVar(&c.timeout, "timeout", 3*time.Minute, "wall-clock limit for the whole run, retries included")
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
		// Clean scan: no model call, no comment. The comment job keys off status.
		res.Status = StatusNoFindings
		return finish(nil)
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	client := anthropic.NewClient(
		option.WithMiddleware(tracer.Middleware),
		option.WithMaxRetries(2),
	)
	tri, meta, err := callTriage(ctx, client, c, fs)
	res.ModelUsed = meta.model
	res.StopReason = meta.stopReason
	res.Usage = meta.usage
	res.CostUSD = cost(meta.model, meta.usage)
	if err != nil {
		return finish(err)
	}

	tri, warnings := reconcile(fs, tri)
	res.Status = StatusTriaged
	res.Triage = &tri
	res.Warnings = warnings
	res.DurationMS = time.Since(start).Milliseconds()

	md := renderComment(fs, tri, res, c.runURL)
	if err := os.WriteFile(filepath.Join(c.outDir, "comment.md"), []byte(md), 0o644); err != nil {
		return finish(err)
	}
	return finish(nil)
}

type callMeta struct {
	model      string
	stopReason string
	usage      Usage
}

func callTriage(ctx context.Context, client anthropic.Client, c config, fs []findings.Finding) (Triage, callMeta, error) {
	var meta callMeta
	user, err := buildUserMessage(fs)
	if err != nil {
		return Triage{}, meta, err
	}

	resp, err := client.Beta.Messages.New(ctx, anthropic.BetaMessageNewParams{
		Model:     anthropic.Model(c.model),
		MaxTokens: c.maxTokens,
		System:    []anthropic.BetaTextBlockParam{{Text: systemPrompt}},
		Messages: []anthropic.BetaMessageParam{
			anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(user)),
		},
		OutputConfig: anthropic.BetaOutputConfigParam{
			Effort: anthropic.BetaOutputConfigEffort(c.effort),
			Format: anthropic.BetaJSONOutputFormatParam{Schema: triageSchema},
		},
		// If a safety classifier declines the request, the server re-serves it on a
		// fallback model inside the same call. The model that actually answered is
		// recorded from the response, never assumed from the request.
		Betas:     []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01},
		Fallbacks: anthropic.BetaFallbacksParamOfDefault(),
	})
	if err != nil {
		return Triage{}, meta, fmt.Errorf("messages API: %w", err)
	}

	meta.model = string(resp.Model)
	meta.stopReason = string(resp.StopReason)
	meta.usage = Usage{
		InputTokens:      resp.Usage.InputTokens,
		OutputTokens:     resp.Usage.OutputTokens,
		CacheReadTokens:  resp.Usage.CacheReadInputTokens,
		CacheWriteTokens: resp.Usage.CacheCreationInputTokens,
	}

	switch resp.StopReason {
	case anthropic.BetaStopReasonRefusal:
		return Triage{}, meta, fmt.Errorf("model refused (category %q)", resp.StopDetails.Category)
	case anthropic.BetaStopReasonMaxTokens:
		return Triage{}, meta, fmt.Errorf("response hit the %d-token ceiling before completing", c.maxTokens)
	}

	var text string
	for _, block := range resp.Content {
		if tb, ok := block.AsAny().(anthropic.BetaTextBlock); ok {
			text += tb.Text
		}
	}
	var tri Triage
	if err := json.Unmarshal([]byte(text), &tri); err != nil {
		return Triage{}, meta, fmt.Errorf("decode structured output: %w", err)
	}
	return tri, meta, nil
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
