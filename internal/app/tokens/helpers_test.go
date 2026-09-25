package tokens_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/stretchr/testify/require"
)

// Doubles and helpers shared by this package's tests, as in internal/app's own
// tests: trivial no-op implementations; anything a test asserts against is a
// generated mock instead.

// assertCompensationContext requires the compensating write to have run under a context
// that was alive although the request that led to it was cancelled, and bounded by a
// deadline of its own, so a database that hangs cannot hold the compensation forever.
func assertCompensationContext(t *testing.T, seen compensationSeen) {
	t.Helper()

	require.True(t, seen.called, "the compensating write was never made")
	require.NoError(t, seen.err, "the compensating write ran on a dead context: the client's hang-up skipped it")
	require.True(t, seen.hasDeadline, "the compensating write runs with no deadline: a hung database holds it forever")
}

// compensationSeen is what a compensating write's context looked like when the write
// was made. It is captured at the call: the service cancels that context on return.
type compensationSeen struct {
	called      bool
	err         error
	hasDeadline bool
}

type discardLogger struct{}

func (discardLogger) Warn(string, ...slog.Attr) {}

func (discardLogger) Info(string, ...slog.Attr) {}

type nopAudit struct{}

func (nopAudit) Record(context.Context, app.AuditEvent) error { return nil }

func observe(ctx context.Context) compensationSeen {
	_, ok := ctx.Deadline()

	return compensationSeen{called: true, err: ctx.Err(), hasDeadline: ok}
}

// Pin each double to the port it stands in for: a double that stops satisfying its
// interface fails here rather than in a service test months later.
var (
	_ app.AuditSink  = nopAudit{}
	_ app.InfoLogger = discardLogger{}
)
