package settings_test

import (
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/google/uuid"
)

// Doubles and helpers shared by this package's tests, as in internal/app's own
// tests: trivial no-op implementations; anything a test asserts against is a
// generated mock instead.

// fixedClock pins time so an expiry window is a decision of the test rather than a
// race with the wall clock.
type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

func newAdmin() identity.User {
	return identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleAdmin, Status: identity.StatusActive}
}
