package spendlimits_test

import (
	"errors"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/limits"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var (
	twoHours = limits.Rule{Window: 2 * time.Hour, AmountUSD: 10}
	oneDay   = limits.Rule{Window: 24 * time.Hour, AmountUSD: 50}
	oneHour  = limits.Rule{Window: time.Hour, AmountUSD: 5}
)

func TestEffectiveUsesLoadedDefaults(t *testing.T) {
	f := newFixture(t)
	defaults := limits.Set{twoHours, oneDay}
	f.settings.EXPECT().SpendLimitDefaults(mock.Anything).Return(defaults, nil)

	require.NoError(t, f.svc.Load(t.Context()), "load")
	require.Equal(t, defaults, f.svc.Effective(nil), "an inheriting account")
	require.Empty(t, f.svc.Effective(&limits.Set{}), "an account with no limits of its own")
}

// An admitted request opens every window its set has and storage lacks, at the
// clock's now.
func TestAdmitOpensDueWindows(t *testing.T) {
	f := newFixture(t)
	ctx, id := t.Context(), uuid.New()
	f.windows.EXPECT().Windows(ctx, id).Return(nil, nil)
	f.windows.EXPECT().Open(ctx, id, []time.Duration{2 * time.Hour, 24 * time.Hour}, []time.Duration(nil), frozen).Return(nil)

	d, err := f.svc.Admit(ctx, id, limits.Set{twoHours, oneDay})
	require.NoError(t, err, "admit")
	require.False(t, d.Blocked, "blocked")
}

// A refusal writes nothing: the strict mock carries no Open expectation, so an
// exhausted account cannot restart its other windows by retrying, and even an
// orphaned window waits for an admitted request to be dropped.
func TestAdmitRefusalWritesNothing(t *testing.T) {
	f := newFixture(t)
	ctx, id := t.Context(), uuid.New()
	f.windows.EXPECT().Windows(ctx, id).Return([]limits.Window{
		{Length: 2 * time.Hour, StartedAt: frozen.Add(-time.Hour), SpentUSD: 10},
		{Length: time.Hour, StartedAt: frozen.Add(-time.Minute), SpentUSD: 1},
	}, nil)

	d, err := f.svc.Admit(ctx, id, limits.Set{twoHours, oneDay})
	require.NoError(t, err, "admit")
	require.True(t, d.Blocked, "blocked")
	require.Equal(t, twoHours, d.Rule, "exhausted rule")
	require.Equal(t, frozen.Add(time.Hour), d.ResetsAt, "resets at")
}

func TestAdmitWithNothingDueWritesNothing(t *testing.T) {
	f := newFixture(t)
	ctx, id := t.Context(), uuid.New()
	f.windows.EXPECT().Windows(ctx, id).Return([]limits.Window{
		{Length: 2 * time.Hour, StartedAt: frozen.Add(-time.Hour), SpentUSD: 9.99},
		{Length: 24 * time.Hour, StartedAt: frozen.Add(-23 * time.Hour), SpentUSD: 1},
	}, nil)

	d, err := f.svc.Admit(ctx, id, limits.Set{twoHours, oneDay})
	require.NoError(t, err, "admit")
	require.False(t, d.Blocked, "blocked")
}

func TestAdmitSurfacesStorageErrors(t *testing.T) {
	f := newFixture(t)
	ctx, id := t.Context(), uuid.New()
	boom := errors.New("connection reset")
	f.windows.EXPECT().Windows(ctx, id).Return(nil, boom)

	_, err := f.svc.Admit(ctx, id, limits.Set{twoHours})
	require.ErrorIs(t, err, boom, "admit")
}

// The in-memory defaults change only once the store has them: a failed write
// leaves requests limited by the set that is still stored.
func TestSetDefaultsSwapsMemoryAfterTheWrite(t *testing.T) {
	f := newFixture(t)
	ctx, admin := t.Context(), newAdmin()
	old, next := limits.Set{twoHours}, limits.Set{oneHour, oneDay}
	f.settings.EXPECT().SpendLimitDefaults(ctx).Return(old, nil)
	require.NoError(t, f.svc.Load(ctx), "load")

	boom := errors.New("connection reset")
	f.settings.EXPECT().SetSpendLimitDefaults(ctx, next, admin.ID, frozen).Return(boom).Once()
	_, err := f.svc.SetDefaults(ctx, admin, next)
	require.ErrorIs(t, err, boom, "failed write")
	require.Equal(t, old, f.svc.Effective(nil), "defaults after a failed write")

	f.settings.EXPECT().SetSpendLimitDefaults(ctx, next, admin.ID, frozen).Return(nil).Once()
	events := f.recordAudit()
	got, err := f.svc.SetDefaults(ctx, admin, next)
	require.NoError(t, err, "write")
	require.Equal(t, next, got, "returned set")
	require.Equal(t, next, f.svc.Effective(nil), "defaults after the write")
	require.Len(t, *events, 1, "audit events")
	require.Equal(t, "limits.defaults_update", (*events)[0].Action, "action")
	require.Equal(t, "spend_limits", (*events)[0].Target, "target")
	require.Equal(t, admin.ID, (*events)[0].ActorID, "actor")
	require.Equal(t, frozen, (*events)[0].At, "at")
}

func TestSetDefaultsRefusesInvalidSetsAndNonAdmins(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()

	_, err := f.svc.SetDefaults(ctx, newAdmin(), limits.Set{twoHours, twoHours})
	var bad *app.InvalidInputError
	require.ErrorAs(t, err, &bad, "duplicate window")
	require.Equal(t, "[1].windowMinutes", bad.Field, "field")

	_, err = f.svc.SetDefaults(ctx, newPerson(), limits.Set{twoHours})
	require.ErrorIs(t, err, app.ErrForbidden, "plain user")
}

// Custom limits are written, the windows of rules the account no longer has are
// dropped at once, and the change is audited with the new rules.
func TestSetUserWritesDropsAndAudits(t *testing.T) {
	f := newFixture(t)
	ctx, admin, user := t.Context(), newAdmin(), newPerson()
	set := limits.Set{oneHour}
	f.users.EXPECT().ByID(ctx, user.ID).Return(user, nil)
	f.users.EXPECT().UpdateSpendLimits(ctx, user.ID, &set).Return(nil)
	f.windows.EXPECT().Windows(ctx, user.ID).Return([]limits.Window{
		{Length: 2 * time.Hour, StartedAt: frozen.Add(-time.Hour), SpentUSD: 3},
		{Length: time.Hour, StartedAt: frozen.Add(-30 * time.Minute), SpentUSD: 1},
	}, nil)
	f.windows.EXPECT().Open(ctx, user.ID, []time.Duration(nil), []time.Duration{2 * time.Hour}, frozen).Return(nil)
	events := f.recordAudit()

	view, err := f.svc.SetUser(ctx, admin, user.ID, &set)
	require.NoError(t, err, "set user")
	require.Equal(t, &set, view.Custom, "custom")
	require.Len(t, view.Windows, 1, "windows")
	require.Equal(t, oneHour, view.Windows[0].Rule, "window rule")

	require.Len(t, *events, 1, "audit events")
	require.Equal(t, "user.limits_update", (*events)[0].Action, "action")
	require.Equal(t, user.ID.String(), (*events)[0].Target, "target")
	require.Equal(t, map[string]any{
		"mode":   "custom",
		"limits": []map[string]any{{"window_minutes": int64(60), "amount_usd": 5.0}},
	}, (*events)[0].Detail, "detail")
}

func TestSetUserBackToDefault(t *testing.T) {
	f := newFixture(t)
	ctx, admin, user := t.Context(), newAdmin(), newPerson()
	custom := limits.Set{oneHour}
	user.SpendLimits = &custom
	f.users.EXPECT().ByID(ctx, user.ID).Return(user, nil)
	f.users.EXPECT().UpdateSpendLimits(ctx, user.ID, (*limits.Set)(nil)).Return(nil)
	f.windows.EXPECT().Windows(ctx, user.ID).Return(nil, nil)
	events := f.recordAudit()

	view, err := f.svc.SetUser(ctx, admin, user.ID, nil)
	require.NoError(t, err, "set user")
	require.Nil(t, view.Custom, "custom")
	require.Len(t, *events, 1, "audit events")
	require.Equal(t, map[string]any{"mode": "default"}, (*events)[0].Detail, "detail")
}

// Only a window of the account's effective set can be reset: anything else is
// refused before storage is touched.
func TestResetRefusesAWindowOutsideTheSet(t *testing.T) {
	f := newFixture(t)
	ctx, user := t.Context(), newPerson()
	custom := limits.Set{twoHours}
	user.SpendLimits = &custom
	f.users.EXPECT().ByID(ctx, user.ID).Return(user, nil)

	window := time.Hour
	_, err := f.svc.Reset(ctx, newAdmin(), user.ID, &window)
	var bad *app.InvalidInputError
	require.ErrorAs(t, err, &bad, "reset")
	require.Equal(t, "windowMinutes", bad.Field, "field")
}

func TestResetOne(t *testing.T) {
	f := newFixture(t)
	ctx, user := t.Context(), newPerson()
	custom := limits.Set{twoHours, oneDay}
	user.SpendLimits = &custom
	window := 2 * time.Hour
	f.users.EXPECT().ByID(ctx, user.ID).Return(user, nil)
	f.windows.EXPECT().Reset(ctx, user.ID, &window).Return(nil)
	f.windows.EXPECT().Windows(ctx, user.ID).Return(nil, nil)
	events := f.recordAudit()

	_, err := f.svc.Reset(ctx, newAdmin(), user.ID, &window)
	require.NoError(t, err, "reset")
	require.Len(t, *events, 1, "audit events")
	require.Equal(t, "user.limits_reset", (*events)[0].Action, "action")
	require.Equal(t, map[string]any{"window_minutes": int64(120)}, (*events)[0].Detail, "detail")
}

func TestResetAll(t *testing.T) {
	f := newFixture(t)
	ctx, user := t.Context(), newPerson()
	f.users.EXPECT().ByID(ctx, user.ID).Return(user, nil)
	f.windows.EXPECT().Reset(ctx, user.ID, (*time.Duration)(nil)).Return(nil)
	f.windows.EXPECT().Windows(ctx, user.ID).Return(nil, nil)
	events := f.recordAudit()

	_, err := f.svc.Reset(ctx, newAdmin(), user.ID, nil)
	require.NoError(t, err, "reset")
	require.Len(t, *events, 1, "audit events")
	require.Equal(t, "user.limits_reset", (*events)[0].Action, "action")
	require.Equal(t, map[string]any{"window_minutes": "all"}, (*events)[0].Detail, "detail")
}

// An account inheriting the defaults sees them, with its live windows, and no
// custom set.
func TestMineShowsTheEffectiveSet(t *testing.T) {
	f := newFixture(t)
	ctx, user := t.Context(), newPerson()
	f.settings.EXPECT().SpendLimitDefaults(ctx).Return(limits.Set{oneDay, twoHours}, nil)
	require.NoError(t, f.svc.Load(ctx), "load")
	rows := []limits.Window{{Length: 2 * time.Hour, StartedAt: frozen.Add(-time.Hour), SpentUSD: 4}}
	f.windows.EXPECT().Windows(ctx, user.ID).Return(rows, nil)

	view, err := f.svc.Mine(ctx, user)
	require.NoError(t, err, "mine")
	require.Nil(t, view.Custom, "custom")
	require.Equal(t, limits.States(limits.Set{twoHours, oneDay}, rows, frozen), view.Windows, "windows")
}
