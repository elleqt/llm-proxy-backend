package display_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/display"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var frozen = time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

func newService(t *testing.T) (*display.Service, *mocks.SettingsRepo, *mocks.AuditSink) {
	t.Helper()

	settings, audit, clock := mocks.NewSettingsRepo(t), mocks.NewAuditSink(t), mocks.NewClock(t)
	clock.EXPECT().Now().Return(frozen).Maybe()

	return display.New(settings, audit, clock), settings, audit
}

func user(role identity.Role) identity.User {
	return identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: role, Status: identity.StatusActive}
}

// Costs are hidden from users until an administrator turns them on, and shown to
// administrators always.
func TestCostsVisibleTo(t *testing.T) {
	svc, settings, audit := newService(t)
	person, admin := user(identity.RoleUser), user(identity.RoleAdmin)

	require.False(t, svc.CostsVisibleTo(person), "a user before Load")
	require.True(t, svc.CostsVisibleTo(admin), "an administrator before Load")

	settings.EXPECT().SetDisplayConfig(mock.Anything, app.DisplayConfig{CostsVisible: true, MaskUnknownErrors: true}, admin.ID, frozen).Return(nil)
	audit.EXPECT().Record(mock.Anything, app.AuditEvent{
		At: frozen, ActorID: admin.ID, Action: "display.update", Target: "display",
		Detail: map[string]any{"costs_visible": true, "mask_unknown_errors": true},
	}).Return(nil)

	_, err := svc.Set(context.Background(), admin, display.Patch{CostsVisible: new(true)})
	require.NoError(t, err, "Set")
	require.True(t, svc.CostsVisibleTo(person), "a user once turned on")
	require.True(t, svc.MaskUnknownErrors(), "cost visibility must not disable error masking")
}

// A failed write leaves the setting in force as it was; only an administrator may
// read or change it, and a refusal touches nothing.
func TestSetKeepsTheStoredValueOnFailure(t *testing.T) {
	svc, settings, _ := newService(t)
	admin := user(identity.RoleAdmin)

	settings.EXPECT().SetDisplayConfig(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("connection refused"))

	_, err := svc.Set(context.Background(), admin, display.Patch{CostsVisible: new(true)})
	require.Error(t, err, "Set with the store down")
	require.False(t, svc.CostsVisible(), "in force after a failed write")

	_, err = svc.Set(context.Background(), user(identity.RoleUser), display.Patch{CostsVisible: new(true)})
	require.ErrorIs(t, err, app.ErrForbidden, "Set by a user")

	_, err = svc.Get(user(identity.RoleUser))
	require.ErrorIs(t, err, app.ErrForbidden, "Get by a user")
}

// Load puts the stored setting in force.
func TestLoadReadsTheStoredSetting(t *testing.T) {
	svc, settings, _ := newService(t)
	settings.EXPECT().DisplayConfig(mock.Anything).Return(app.DisplayConfig{CostsVisible: true}, nil)

	require.NoError(t, svc.Load(context.Background()), "Load")
	require.True(t, svc.CostsVisible(), "after Load")
}

func TestMaskingPreferencePreservesOtherSettings(t *testing.T) {
	svc, settings, audit := newService(t)
	admin := user(identity.RoleAdmin)

	require.True(t, svc.MaskUnknownErrors(), "safe default before any saved settings")
	settings.EXPECT().DisplayConfig(mock.Anything).Return(app.DisplayConfig{CostsVisible: true, MaskUnknownErrors: true}, nil)
	require.NoError(t, svc.Load(t.Context()))
	settings.EXPECT().SetDisplayConfig(mock.Anything, app.DisplayConfig{CostsVisible: true, MaskUnknownErrors: false}, admin.ID, frozen).Return(nil)
	audit.EXPECT().Record(mock.Anything, mock.Anything).Return(nil).Once()

	_, err := svc.Set(t.Context(), admin, display.Patch{MaskUnknownErrors: new(false)})
	require.NoError(t, err)
	require.False(t, svc.MaskUnknownErrors())
	require.True(t, svc.CostsVisible())
	settings.EXPECT().SetDisplayConfig(mock.Anything, app.DisplayConfig{CostsVisible: false, MaskUnknownErrors: false}, admin.ID, frozen).Return(nil)
	audit.EXPECT().Record(mock.Anything, mock.Anything).Return(nil).Once()

	_, err = svc.Set(t.Context(), admin, display.Patch{CostsVisible: new(false)})
	require.NoError(t, err)
	require.False(t, svc.MaskUnknownErrors(), "unrelated writes must preserve an explicit off")
}

func TestMaskingFailedWriteAndEmptyPatchLeaveSafeDefault(t *testing.T) {
	svc, settings, _ := newService(t)
	admin := user(identity.RoleAdmin)

	settings.EXPECT().SetDisplayConfig(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(errors.New("database unavailable")).Once()

	_, err := svc.Set(t.Context(), admin, display.Patch{MaskUnknownErrors: new(false)})
	require.Error(t, err)
	require.True(t, svc.MaskUnknownErrors())
	_, err = svc.Set(t.Context(), admin, display.Patch{})
	require.ErrorIs(t, err, app.ErrInvalidInput)
	_, err = svc.Set(t.Context(), user(identity.RoleUser), display.Patch{MaskUnknownErrors: new(false)})
	require.ErrorIs(t, err, app.ErrForbidden)
}
