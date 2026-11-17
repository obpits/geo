package main

// Result is written to result.json on every run, including failures, so every
// run records model, prompt version, tokens, cost and duration.
type Result struct {
	Status         string   `json:"status"`
	PromptVersion  string   `json:"prompt_version"`
	ModelRequested string   `json:"model_requested"`
	ModelUsed      string   `json:"model_used,omitempty"` // differs from requested if a fallback served the call
	StopReason     string   `json:"stop_reason,omitempty"`
	FindingsCount  int      `json:"findings_count"`
	Usage          Usage    `json:"usage"`
	CostUSD        *float64 `json:"cost_usd"` // null when the model has no entry in the price table
	DurationMS     int64    `json:"duration_ms"`
	Triage         *Triage  `json:"triage,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
	Error          string   `json:"error,omitempty"`
}

const (
	StatusNoFindings = "no_findings" // comment job stays silent
	StatusTriaged    = "triaged"     // comment job posts comment.md
	StatusError      = "error"       // job fails; nothing is posted
)

type Usage struct {
	InputTokens      int64 `json:"input_tokens"`
	OutputTokens     int64 `json:"output_tokens"`
	CacheReadTokens  int64 `json:"cache_read_input_tokens"`
	CacheWriteTokens int64 `json:"cache_creation_input_tokens"`
}

// USD per million tokens, first-party API list prices as of November 2026.
// Cache writes are the 5-minute TTL rate (1.25x input).
type price struct{ in, out, cacheRead, cacheWrite float64 }

var prices = map[string]price{
	"claude-opus-5-5": {in: 4, out: 20, cacheRead: 0.20, cacheWrite: 5},
	"claude-opus-4-8": {in: 5, out: 25, cacheRead: 0.50, cacheWrite: 6.25},
}

func cost(model string, u Usage) *float64 {
	p, ok := prices[model]
	if !ok {
		return nil
	}
	c := (float64(u.InputTokens)*p.in +
		float64(u.OutputTokens)*p.out +
		float64(u.CacheReadTokens)*p.cacheRead +
		float64(u.CacheWriteTokens)*p.cacheWrite) / 1e6
	return &c
}
