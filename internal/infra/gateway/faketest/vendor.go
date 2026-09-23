package faketest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

// Vendor is an OpenAI-compatible vendor on the wire: an http.Handler that
// answers /chat/completions with canned payloads, ordered SSE chunks, injected
// failures and latency.
//
// Declared as an openai-compatibility entry in the gateway configuration (see
// Compatibility), upstream registers its models and its own OpenAI-compatible
// executor for it, so a request entering the embedded server goes through the
// real access control, model routing, translators and streaming stack before it
// reaches this handler. That is the path Executor, which sits behind the
// conductor, cannot exercise; Executor remains the double for conductor-level
// behaviour (failover, cooldown, retry) that HTTP cannot reach.
type Vendor struct {
	// Payload is the non-streaming response body.
	Payload []byte
	// Chunks are the data payloads of the SSE events of a streaming response,
	// written and flushed in order. A terminating "data: [DONE]" follows unless
	// DieMidStream is set.
	Chunks [][]byte
	// FailStatus, when non-zero, fails every request with this status and
	// FailBody before any payload is produced.
	FailStatus int
	FailBody   []byte
	// DieMidStream drops the connection once Chunks are written, reproducing a
	// vendor that dies mid-stream.
	DieMidStream bool
	// Latency is waited out before the non-streaming response and before each
	// streaming chunk, or until the caller goes away. Zero means no delay.
	Latency time.Duration

	mu       sync.Mutex
	requests []Request
	// started counts streaming chunks the vendor has begun writing.
	started atomic.Int64
}

// Request is what the vendor received.
type Request struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

// Start serves v on a loopback listener for the duration of the test.
func Start(t *testing.T, v *Vendor) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(v)
	t.Cleanup(srv.Close)
	return srv
}

// Compatibility is the openai-compatibility configuration entry that routes
// alias to model on the vendor listening at baseURL.
func Compatibility(name, baseURL, apiKey, model, alias string) cliproxyconfig.OpenAICompatibility {
	return cliproxyconfig.OpenAICompatibility{
		Name:          name,
		BaseURL:       baseURL,
		APIKeyEntries: []cliproxyconfig.OpenAICompatibilityAPIKey{{APIKey: apiKey}},
		Models:        []cliproxyconfig.OpenAICompatibilityModel{{Name: model, Alias: alias}},
	}
}

// Requests returns a copy of the requests received so far, in arrival order.
func (v *Vendor) Requests() []Request {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]Request(nil), v.requests...)
}

// ChunksStarted reports how many streaming chunks the vendor has begun to
// write, across all requests. It is incremented before a chunk is written, so
// while it is below len(Chunks) the last chunk has not been sent.
func (v *Vendor) ChunksStarted() int {
	return int(v.started.Load())
}

// ServeHTTP answers as the vendor would.
func (v *Vendor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	v.mu.Lock()
	v.requests = append(v.requests, Request{Method: r.Method, Path: r.URL.Path, Header: r.Header.Clone(), Body: body})
	v.mu.Unlock()

	if v.FailStatus != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(v.FailStatus)
		_, _ = w.Write(v.FailBody)
		return
	}

	var mode struct {
		Stream bool `json:"stream"`
	}
	_ = json.Unmarshal(body, &mode)
	if !mode.Stream {
		if !wait(r, v.Latency) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(v.Payload)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	for _, c := range v.Chunks {
		if !wait(r, v.Latency) {
			return
		}
		v.started.Add(1)
		if _, err := fmt.Fprintf(w, "data: %s\n\n", c); err != nil {
			return
		}
		flusher.Flush()
	}
	if v.DieMidStream {
		panic(http.ErrAbortHandler)
	}
	_, _ = io.WriteString(w, "data: [DONE]\n\n")
	flusher.Flush()
}

// wait sleeps for d and reports whether the caller is still there.
func wait(r *http.Request, d time.Duration) bool {
	if d <= 0 {
		return r.Context().Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-r.Context().Done():
		return false
	case <-timer.C:
		return true
	}
}
