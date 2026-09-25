package recovery_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// Doubles and helpers shared by this package's tests, as in internal/app's own
// tests: trivial no-op implementations; anything a test asserts against is a
// generated mock instead.

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

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }

// testHasher runs the real argon2 derivations with room for every test in the package
// to derive at once: the bound is under test in internal/app's hasher_test.go, not here.
func testHasher() *app.PasswordHasher {
	return app.NewPasswordHasher(64, identity.HashPassword, identity.VerifyPassword)
}

const (
	testMaxFailures = 5
	testLockFor     = 15 * time.Minute
)

// Pin each double to the port it stands in for: a double that stops satisfying its
// interface fails here rather than in a service test months later.
var _ app.Clock = systemClock{}
