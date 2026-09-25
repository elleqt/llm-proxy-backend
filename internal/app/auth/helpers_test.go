package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/stretchr/testify/require"
)

// Doubles and helpers shared by this package's tests, as in internal/app's own
// tests: trivial no-op implementations; anything a test asserts against is a
// generated mock instead.

// isExactly reports whether err is target itself rather than something wrapping it,
// for control flow such as a switch case; assertions use require.Same. Refusals are
// compared this way on purpose: fmt.Errorf("no such user: %w", ErrInvalidCredentials)
// satisfies errors.Is while putting the reason back in the message, which is the
// oracle those tests exist to close.
func isExactly(err, target error) bool {
	return err == target //nolint:errorlint // identity, not errors.Is, is the check
}

func mustPolicy(t *testing.T, rules ...string) access.Policy {
	t.Helper()

	policy := make(access.Policy, 0, len(rules))

	for _, raw := range rules {
		rule, err := access.ParseRule(raw)
		require.NoError(t, err, "ParseRule(%q)", raw)

		policy = append(policy, rule)
	}

	return policy
}

type nopAudit struct{}

func (nopAudit) Record(context.Context, app.AuditEvent) error { return nil }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

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
)
