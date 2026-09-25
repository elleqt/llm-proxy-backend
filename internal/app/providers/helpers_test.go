package providers_test

import (
	"log/slog"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

// Doubles and helpers shared by this package's tests, as in internal/app's own
// tests: trivial no-op implementations; anything a test asserts against is a
// generated mock instead.

type discardLogger struct{}

func (discardLogger) Warn(string, ...slog.Attr) {}

func (discardLogger) Info(string, ...slog.Attr) {}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

// Pin each double to the port it stands in for: a double that stops satisfying its
// interface fails here rather than in a service test months later.
var (
	_ app.Clock      = systemClock{}
	_ app.InfoLogger = discardLogger{}
)
