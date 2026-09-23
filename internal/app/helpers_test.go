// The app-layer tests live in package app_test: internal/app/mocks imports
// internal/app, so a test declared `package app` that touches a generated mock is
// an import cycle. Nothing here needs unexported identifiers.
package app_test

import (
	"context"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

// Doubles that are not mocks: trivial no-op implementations shared by the tests of
// this package. Anything a test needs to assert against is a generated mock instead.

type nopAudit struct{}

func (nopAudit) Record(context.Context, app.AuditEvent) error { return nil }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

func mustPolicy(t *testing.T, rules ...string) access.Policy {
	t.Helper()
	var p access.Policy
	for _, raw := range rules {
		r, err := access.ParseRule(raw)
		if err != nil {
			t.Fatalf("ParseRule(%q): %v", raw, err)
		}
		p = append(p, r)
	}
	return p
}

type discardLogger struct{}

func (discardLogger) Warnf(string, ...any) {}

// testHasher runs the real argon2 derivations with room for every test in the package
// to derive at once: the bound is under test in hasher_test.go, not here.
func testHasher() *app.PasswordHasher {
	return app.NewPasswordHasher(64, identity.HashPassword, identity.VerifyPassword)
}

// Pin each double to the port it stands in for: a double that stops satisfying its
// interface fails here rather than in a service test months later.
var (
	_ app.AuditSink = nopAudit{}
	_ app.Clock     = systemClock{}
	_ app.Logger    = discardLogger{}
)
