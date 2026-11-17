package main

import (
	"fmt"
	"strings"

	"citycountrygame/internal/findings"
)

// commentMarker lets the publish step find and update its own comment.
const commentMarker = "<!-- geo-remediation-agent -->"

// Field caps keep one runaway string from producing an unreadable comment and
// keep the whole body well under GitHub's 65,536-character limit.
const (
	maxSummary   = 1200
	maxRationale = 1200
	maxFix       = 1200
	maxTitle     = 200
	// Verification output can be long; three attempts of four steps each must
	// still fit well under the limit alongside everything else.
	maxApproaches = 1500
	maxStepOutput = 2000
)

var assessmentLabel = map[string]string{
	"fix_now":               "Fix now",
	"fix_soon":              "Fix soon",
	"acceptable_risk":       "Acceptable risk",
	"likely_false_positive": "Likely false positive",
}

// renderComment builds the PR comment deterministically from structured data.
// Severity comes from the scanner, not the model, so a prompt injection that
// talks the model into a lower assessment still sits beside the scanner's own
// rating. All scanner, model and command-output text passes through clean().
func renderComment(fs []findings.Finding, tri Triage, res Result, runURL string) string {
	var b strings.Builder
	b.WriteString(commentMarker + "\n")
	n := fmt.Sprintf("%d finding%s", len(fs), plural(len(fs)))
	switch res.Status {
	case StatusPatched:
		fmt.Fprintf(&b, "### Security fix proposed: %s\n\n", n)
		b.WriteString("A verified fix is in a pull request against this branch, for you to review and merge.\n\n")
	case StatusUnfixable:
		fmt.Fprintf(&b, "### Security findings without a verified fix: %s\n\n", n)
	default:
		fmt.Fprintf(&b, "### Security triage: %s\n\n", n)
	}
	b.WriteString(clean(tri.Summary, maxSummary) + "\n\n")
	writeTriage(&b, fs, tri)
	writeAttempts(&b, res)
	writeWarnings(&b, res)
	writeFooter(&b, res, runURL)
	return b.String()
}

// renderPR builds the body of the agent's pull request, under the same rules
// as the comment. The title is set by the publish job, not here.
func renderPR(fs []findings.Finding, tri Triage, res Result, runURL string) string {
	var b strings.Builder
	b.WriteString(commentMarker + "\n")
	b.WriteString("Dependency upgrade proposed by the remediation agent for the findings below. ")
	b.WriteString("It passed build, tests and the fixed-version check in the agent's workspace. ")
	b.WriteString("Checks do not run automatically on this pull request, so the full pipeline runs ")
	b.WriteString("again on your branch once you merge it there.\n\n")
	b.WriteString(clean(tri.Summary, maxSummary) + "\n\n")
	b.WriteString("**Files changed:** ")
	for i, f := range res.ChangedFiles {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "`%s`", code(f))
	}
	b.WriteString("\n\n")
	writeTriage(&b, fs, tri)
	writeAttempts(&b, res)
	writeWarnings(&b, res)
	writeFooter(&b, res, runURL)
	return b.String()
}

func writeTriage(b *strings.Builder, fs []findings.Finding, tri Triage) {
	byID := map[string]FindingTriage{}
	for _, t := range tri.Findings {
		byID[t.ID] = t
	}
	b.WriteString("| ID | Scanner severity | Finding | Where | Agent assessment |\n")
	b.WriteString("|---|---|---|---|---|\n")
	for _, f := range fs {
		assess := "_not triaged_"
		if t, ok := byID[f.ID]; ok {
			assess = assessmentLabel[t.Assessment]
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s |\n",
			f.ID, cell(f.Severity, 20), cell(f.Title, maxTitle), cell(where(f), 200), assess)
	}
	b.WriteString("\n")

	for _, f := range fs {
		t, ok := byID[f.ID]
		if !ok {
			continue
		}
		fmt.Fprintf(b, "<details><summary><b>%s</b>: %s</summary>\n\n", f.ID, cell(f.Title, maxTitle))
		fmt.Fprintf(b, "**Why:** %s\n\n", clean(t.Rationale, maxRationale))
		fmt.Fprintf(b, "**Suggested fix:** %s\n\n", clean(t.SuggestedFix, maxFix))
		b.WriteString("</details>\n\n")
	}
}

// writeAttempts shows what the agent tried and the verification evidence.
// Command output is untrusted (tests print what they like), so it goes through
// clean() inside <pre>, where clean()'s HTML escaping renders as plain text.
func writeAttempts(b *strings.Builder, res Result) {
	if res.ApproachesTried == "" && len(res.Verifications) == 0 {
		return
	}
	b.WriteString("#### What the agent tried\n\n")
	if res.ApproachesTried != "" {
		b.WriteString(clean(res.ApproachesTried, maxApproaches) + "\n\n")
	}
	for _, v := range res.Verifications {
		verdict := "failed"
		if v.Passed {
			verdict = "passed"
		}
		var parts []string
		for _, s := range v.Steps {
			st := "ok"
			switch {
			case s.Skipped:
				st = "skipped"
			case !s.OK:
				st = "**failed**"
			}
			parts = append(parts, s.Name+" "+st)
		}
		fmt.Fprintf(b, "<details><summary>Verification %d of %d: %s</summary>\n\n%s\n\n",
			v.Attempt, MaxVerifications, verdict, strings.Join(parts, " · "))
		for _, s := range v.Steps {
			if s.Output == "" {
				continue
			}
			fmt.Fprintf(b, "<b>%s</b>\n<pre>%s</pre>\n\n", s.Name, clean(s.Output, maxStepOutput))
		}
		b.WriteString("</details>\n\n")
	}
}

func writeWarnings(b *strings.Builder, res Result) {
	if len(res.Warnings) == 0 {
		return
	}
	b.WriteString("> [!WARNING]\n> The agent's answer did not match the findings or the rules exactly:\n")
	for _, w := range res.Warnings {
		fmt.Fprintf(b, "> - %s\n", clean(w, 300))
	}
	b.WriteString("\n")
}

func writeFooter(b *strings.Builder, res Result, runURL string) {
	b.WriteString("---\n<sub>")
	if res.Status == StatusPatched {
		b.WriteString("Generated by a model from scanner output. The change is proposed for review only; nothing was merged. ")
	} else {
		b.WriteString("Generated by a model from scanner output. It is a recommendation only: nothing was changed. ")
	}
	in := res.Usage.InputTokens + res.Usage.CacheReadTokens + res.Usage.CacheWriteTokens
	fmt.Fprintf(b, "Model `%s`, prompt `%s`, %d turn%s, %d in / %d out tokens",
		code(res.ModelUsed), code(res.PromptVersion), res.Turns, plural(res.Turns), in, res.Usage.OutputTokens)
	if res.CostUSD != nil {
		fmt.Fprintf(b, ", $%.4f", *res.CostUSD)
	}
	fmt.Fprintf(b, ", %.1fs.", float64(res.DurationMS)/1000)
	if runURL != "" {
		fmt.Fprintf(b, " [Run and trace](%s).", runURL)
	}
	b.WriteString("</sub>\n")
}

func where(f findings.Finding) string {
	switch f.Kind {
	case findings.KindDependency:
		s := f.Package
		if f.Version != "" {
			s += "@" + f.Version
		}
		return s
	case findings.KindCode:
		if f.Line > 0 {
			return fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		return f.File
	}
	return ""
}

// clean neutralizes untrusted text for a GitHub comment: no raw HTML (which
// covers tracking images and hidden content), no @mentions or #references that
// would notify people or link issues, no markdown images, and a length cap.
func clean(s string, max int) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > max {
		s = string(r[:max]) + "…"
	}
	s = strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"@", "@​",
		"#", "#​",
		"![", "!​[",
	).Replace(s)
	return s
}

// cell is clean() for a single table cell: no newlines, no column breaks.
func cell(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	return strings.ReplaceAll(clean(s, max), "|", "\\|")
}

// code makes a value safe inside a single-backtick span.
func code(s string) string { return strings.ReplaceAll(s, "`", "'") }

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
