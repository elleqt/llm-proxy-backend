// Package faketest provides behavioural fakes of a vendor.
//
// They are deliberately hand-written rather than generated: a mock asserts which
// calls were made, while an end-to-end proxy test needs a double that actually
// produces payloads, streaming sequences, latencies and reproducible failures.
//
// Vendor is the fake on the wire and the one end-to-end tests use: a request
// through the embedded server reaches it via upstream's own executor. Executor
// plugs in behind the conductor and is only for conductor-level tests.
package faketest

import (
	"context"
	"net/http"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// Executor answers as a vendor would, without network access or live grants.
// The zero value is usable: it identifies an empty provider and returns an
// empty payload. It implements coreauth.ProviderExecutor.
type Executor struct {
	// Provider is the provider key the auth manager routes by.
	Provider string
	// Payload is the non-streaming response body.
	Payload []byte
	// Chunks are the streaming payload units, emitted in order.
	Chunks [][]byte
	// Err fails Execute and ExecuteStream before any payload is produced.
	Err error
	// StreamErr is delivered as the terminal chunk once Chunks are exhausted,
	// reproducing a vendor that dies mid-stream.
	StreamErr error
	// Latency is waited out before the non-streaming response and before each
	// streaming chunk. Zero means no delay.
	Latency time.Duration
}

// Identifier returns the provider key handled by this executor.
func (e *Executor) Identifier() string { return e.Provider }

// Execute returns the canned payload, or the canned error.
func (e *Executor) Execute(ctx context.Context, _ *coreauth.Auth,
	_ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if err := sleep(ctx, e.Latency); err != nil {
		return cliproxyexecutor.Response{}, err
	}
	if e.Err != nil {
		return cliproxyexecutor.Response{}, e.Err
	}
	return cliproxyexecutor.Response{Payload: e.Payload}, nil
}

// ExecuteStream emits the canned chunks in order, honouring Latency between
// them and cancellation of ctx. The channel is buffered to the full sequence
// so a consumer that abandons the stream cannot leak the producer goroutine.
func (e *Executor) ExecuteStream(ctx context.Context, _ *coreauth.Auth,
	_ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	if e.Err != nil {
		return nil, e.Err
	}
	ch := make(chan cliproxyexecutor.StreamChunk, len(e.Chunks)+1)
	go func() {
		defer close(ch)
		for _, c := range e.Chunks {
			if err := sleep(ctx, e.Latency); err != nil {
				ch <- cliproxyexecutor.StreamChunk{Err: err}
				return
			}
			ch <- cliproxyexecutor.StreamChunk{Payload: c}
		}
		if e.StreamErr != nil {
			ch <- cliproxyexecutor.StreamChunk{Err: e.StreamErr}
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: http.Header{}, Chunks: ch}, nil
}

// Refresh reports the credential as still valid: a fake grant never expires.
func (e *Executor) Refresh(_ context.Context, a *coreauth.Auth) (*coreauth.Auth, error) {
	return a, nil
}

// CountTokens returns a fixed count; the fake charges nothing.
func (e *Executor) CountTokens(_ context.Context, _ *coreauth.Auth,
	_ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	if e.Err != nil {
		return cliproxyexecutor.Response{}, e.Err
	}
	return cliproxyexecutor.Response{Payload: []byte(`{"input_tokens":0}`)}, nil
}

// HttpRequest answers passthrough requests with an empty 200, or the canned error.
func (e *Executor) HttpRequest(_ context.Context, _ *coreauth.Auth,
	_ *http.Request) (*http.Response, error) {
	if e.Err != nil {
		return nil, e.Err
	}
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}

// sleep waits for d, or returns early if ctx is done. A zero duration never blocks.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

var _ coreauth.ProviderExecutor = (*Executor)(nil)
