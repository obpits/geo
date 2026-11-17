package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// Tracer appends one JSON line per model request and per model response to
// trace.jsonl. It sits in the SDK's HTTP middleware chain, so it records exactly
// what went over the wire, including retries, rather than a reconstruction.
//
// Only an allowlist of headers is recorded. In particular x-api-key is never
// written, because the trace is uploaded as a build artifact.
type Tracer struct {
	mu  sync.Mutex
	enc *json.Encoder
	f   *os.File
	now func() time.Time
}

var tracedHeaders = []string{"Anthropic-Version", "Anthropic-Beta", "Request-Id", "Content-Type", "Retry-After"}

type traceRecord struct {
	Time    string            `json:"time"`
	Kind    string            `json:"kind"` // request | response | transport_error
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url,omitempty"`
	Status  int               `json:"status,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    json.RawMessage   `json:"body,omitempty"`
	Error   string            `json:"error,omitempty"`
}

func NewTracer(path string) (*Tracer, error) {
	f, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	return newTracer(f), nil
}

func newTracer(f *os.File) *Tracer {
	return &Tracer{enc: json.NewEncoder(f), f: f, now: time.Now}
}

func (t *Tracer) Close() error {
	if t.f == nil {
		return nil
	}
	return t.f.Close()
}

func (t *Tracer) write(r traceRecord) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r.Time = t.now().UTC().Format(time.RFC3339Nano)
	_ = t.enc.Encode(r)
}

// Middleware matches option.Middleware's signature.
func (t *Tracer) Middleware(req *http.Request, next func(*http.Request) (*http.Response, error)) (*http.Response, error) {
	var reqBody []byte
	if req.Body != nil {
		reqBody, _ = io.ReadAll(req.Body)
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(reqBody)), nil }
	}
	t.write(traceRecord{
		Kind:    "request",
		Method:  req.Method,
		URL:     req.URL.String(),
		Headers: pick(req.Header),
		Body:    asJSON(reqBody),
	})

	resp, err := next(req)
	if err != nil {
		t.write(traceRecord{Kind: "transport_error", Error: err.Error()})
		return resp, err
	}

	respBody, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(respBody))
	rec := traceRecord{
		Kind:    "response",
		Status:  resp.StatusCode,
		Headers: pick(resp.Header),
		Body:    asJSON(respBody),
	}
	if readErr != nil {
		rec.Error = readErr.Error()
	}
	t.write(rec)
	return resp, nil
}

func pick(h http.Header) map[string]string {
	out := map[string]string{}
	for _, k := range tracedHeaders {
		if v := h.Get(k); v != "" {
			out[k] = v
		}
	}
	return out
}

// asJSON embeds a valid JSON body as-is and anything else as a JSON string.
func asJSON(b []byte) json.RawMessage {
	if len(b) == 0 {
		return nil
	}
	if json.Valid(b) {
		return json.RawMessage(b)
	}
	s, _ := json.Marshal(string(b))
	return s
}
