package prices_test

import (
	"log/slog"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/google/uuid"
)

// Doubles and helpers shared by this package's tests, as in internal/app's own
// tests: trivial no-op implementations; anything a test asserts against is a
// generated mock instead.

type discardLogger struct{}

func (discardLogger) Warn(string, ...slog.Attr) {}

func (discardLogger) Info(string, ...slog.Attr) {}

// fixedClock pins time so an expiry window is a decision of the test rather than a
// race with the wall clock.
type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

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

var settingsNow = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

// Pin each double to the port it stands in for: a double that stops satisfying its
// interface fails here rather than in a service test months later.
var _ app.InfoLogger = discardLogger{}
