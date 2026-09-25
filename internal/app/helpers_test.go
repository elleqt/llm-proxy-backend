// The app-layer tests live in package app_test: internal/app/mocks imports
// internal/app, so a test declared `package app` that touches a generated mock is
// an import cycle. Nothing here needs unexported identifiers.
package app_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Doubles that are not mocks: trivial no-op implementations shared by the tests of
// this package. Anything a test needs to assert against is a generated mock instead.

type nopAudit struct{}

func (nopAudit) Record(context.Context, app.AuditEvent) error { return nil }

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

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

// isExactly reports whether err is target itself rather than something wrapping it,
// for control flow such as a switch case; assertions use require.Same. Refusals are
// compared this way on purpose: fmt.Errorf("no such user: %w", ErrInvalidCredentials)
// satisfies errors.Is while putting the reason back in the message, which is the
// oracle those tests exist to close.
func isExactly(err, target error) bool {
	return err == target //nolint:errorlint // identity, not errors.Is, is the check
}

type discardLogger struct{}

func (discardLogger) Warn(string, ...slog.Attr) {}
func (discardLogger) Info(string, ...slog.Attr) {}

// testHasher runs the real argon2 derivations with room for every test in the package
// to derive at once: the bound is under test in hasher_test.go, not here.
func testHasher() *app.PasswordHasher {
	return app.NewPasswordHasher(64, identity.HashPassword, identity.VerifyPassword)
}

// Pin each double to the port it stands in for: a double that stops satisfying its
// interface fails here rather than in a service test months later.
var (
	_ app.AuditSink  = nopAudit{}
	_ app.Clock      = systemClock{}
	_ app.InfoLogger = discardLogger{}
)

// assertNoSecret fails if any audit detail carries one of the secrets.
func assertNoSecret(t *testing.T, events []app.AuditEvent, secrets ...string) {
	t.Helper()

	for _, event := range events {
		raw, err := json.Marshal(event.Detail)
		require.NoError(t, err, "marshal detail")

		for _, s := range secrets {
			if s != "" {
				require.NotContains(t, string(raw)+event.Target, s, "audit event %s carries a secret", event.Action)
			}
		}
	}
}

func newAdmin() identity.User {
	return identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleAdmin, Status: identity.StatusActive}
}

func newPerson() identity.User {
	return identity.User{
		ID: uuid.New(), Kind: identity.KindHuman, Email: "person@example.com",
		DisplayName: "Person", Role: identity.RoleUser, Status: identity.StatusActive,
		PolicySource: identity.PolicyLocal,
	}
}

// fixedClock pins time so an expiry window is a decision of the test rather than a
// race with the wall clock.
type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func humanUser(email string) identity.User {
	return identity.User{
		ID:           uuid.New(),
		Kind:         identity.KindHuman,
		Email:        email,
		DisplayName:  "A Person",
		Role:         identity.RoleUser,
		Status:       identity.StatusActive,
		PolicySource: identity.PolicyLocal,
	}
}

func mustHash(t *testing.T, plain string) string {
	t.Helper()

	h, err := identity.HashPassword(plain)
	require.NoError(t, err, "HashPassword")

	return h
}

const (
	testMaxFailures = 5
	testLockFor     = 15 * time.Minute
)

var settingsNow = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
