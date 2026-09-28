package spendlimits_test

import (
	"context"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/app/spendlimits"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

// frozen is the instant the injected clock reports, so every window the service
// opens and every timestamp it writes is asserted exactly.
var frozen = time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

// fixture wires spendlimits.Service to strict mocks: a repository call a test did
// not expect fails it, so a refusal that still reaches a write is caught.
type fixture struct {
	users    *mocks.UserRepo
	settings *mocks.SettingsRepo
	windows  *mocks.SpendWindowRepo
	audit    *mocks.AuditSink
	svc      *spendlimits.Service
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		users:    mocks.NewUserRepo(t),
		settings: mocks.NewSettingsRepo(t),
		windows:  mocks.NewSpendWindowRepo(t),
		audit:    mocks.NewAuditSink(t),
	}
	clock := mocks.NewClock(t)
	clock.EXPECT().Now().Return(frozen).Maybe()
	f.svc = spendlimits.New(f.users, f.settings, f.windows, f.audit, clock)

	return f
}

// recordAudit captures every audit event. Registering it is also an assertion: the
// strict mock fails the test if the action under test records nothing.
func (f *fixture) recordAudit() *[]app.AuditEvent {
	var events []app.AuditEvent

	f.audit.EXPECT().Record(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, e app.AuditEvent) error {
		events = append(events, e)

		return nil
	})

	return &events
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
