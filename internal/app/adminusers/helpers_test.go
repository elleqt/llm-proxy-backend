package adminusers_test

import (
	"log/slog"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

// Doubles and helpers shared by this package's tests, as in internal/app's own
// tests: trivial no-op implementations; anything a test asserts against is a
// generated mock instead.

type discardLogger struct{}

func (discardLogger) Warn(string, ...slog.Attr) {}

func (discardLogger) Info(string, ...slog.Attr) {}

// frozen is the instant the injected clock reports, so every timestamp the service
// writes is asserted exactly rather than within a tolerance.
var frozen = time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)

// testHasher runs the real argon2 derivations with room for every test in the package
// to derive at once: the bound is under test in hasher_test.go, not here.
func testHasher() *app.PasswordHasher {
	return app.NewPasswordHasher(64, identity.HashPassword, identity.VerifyPassword)
}

// Pin each double to the port it stands in for: a double that stops satisfying its
// interface fails here rather than in a service test months later.
var _ app.InfoLogger = discardLogger{}
