package spendlimits_test

import (
	"errors"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
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
	fx := newFixture(t)
	defaults := limits.Set{twoHours, oneDay}
	fx.settings.EXPECT().SpendLimitDefaults(mock.Anything).Return(defaults, nil)

	require.NoError(t, fx.svc.Load(t.Context()), "load")
	require.Equal(t, defaults, fx.svc.Effective(nil), "an inheriting account")
	require.Empty(t, fx.svc.Effective(&limits.Set{}), "an account with no limits of its own")
}

// An admitted request opens every window its set has and storage lacks, at the
// clock's now.
func TestAdmitOpensDueWindows(t *testing.T) {
	fx := newFixture(t)
	ctx, id := t.Context(), uuid.New()
	fx.windows.EXPECT().Windows(ctx, id).Return(nil, nil)
	fx.windows.EXPECT().Open(ctx, id, []time.Duration{2 * time.Hour, 24 * time.Hour}, []time.Duration(nil), frozen).Return(nil)

	decision, err := fx.svc.Admit(ctx, id, limits.Set{twoHours, oneDay})
	require.NoError(t, err, "admit")
	require.False(t, decision.Blocked, "blocked")
}

// A refusal writes nothing: the strict mock carries no Open expectation, so an
// exhausted account cannot restart its other windows by retrying, and even an
// orphaned window waits for an admitted request to be dropped.
func TestAdmitRefusalWritesNothing(t *testing.T) {
	fx := newFixture(t)
	ctx, id := t.Context(), uuid.New()
	fx.windows.EXPECT().Windows(ctx, id).Return([]limits.Window{
		{Length: 2 * time.Hour, StartedAt: frozen.Add(-time.Hour), SpentUSD: 10},
		{Length: time.Hour, StartedAt: frozen.Add(-time.Minute), SpentUSD: 1},
	}, nil)

	decision, err := fx.svc.Admit(ctx, id, limits.Set{twoHours, oneDay})
	require.NoError(t, err, "admit")
	require.True(t, decision.Blocked, "blocked")
	require.Equal(t, twoHours, decision.Rule, "exhausted rule")
	require.Equal(t, frozen.Add(time.Hour), decision.ResetsAt, "resets at")
}

func TestAdmitWithNothingDueWritesNothing(t *testing.T) {
	fx := newFixture(t)
	ctx, id := t.Context(), uuid.New()
	fx.windows.EXPECT().Windows(ctx, id).Return([]limits.Window{
		{Length: 2 * time.Hour, StartedAt: frozen.Add(-time.Hour), SpentUSD: 9.99},
		{Length: 24 * time.Hour, StartedAt: frozen.Add(-23 * time.Hour), SpentUSD: 1},
	}, nil)

	decision, err := fx.svc.Admit(ctx, id, limits.Set{twoHours, oneDay})
	require.NoError(t, err, "admit")
	require.False(t, decision.Blocked, "blocked")
}

func TestAdmitSurfacesStorageErrors(t *testing.T) {
	fx := newFixture(t)
	ctx, id := t.Context(), uuid.New()
	boom := errors.New("connection reset")
	fx.windows.EXPECT().Windows(ctx, id).Return(nil, boom)

	_, err := fx.svc.Admit(ctx, id, limits.Set{twoHours})
	require.ErrorIs(t, err, boom, "read")

	fx = newFixture(t)
	fx.windows.EXPECT().Windows(ctx, id).Return(nil, nil)
	fx.windows.EXPECT().Open(ctx, id, []time.Duration{2 * time.Hour}, []time.Duration(nil), frozen).Return(boom)

	_, err = fx.svc.Admit(ctx, id, limits.Set{twoHours})
	require.ErrorIs(t, err, boom, "open")
}

// With no window due, an admitted request still deletes the windows of rules its
// set no longer has.
func TestAdmitDropsOrphansWithNothingDue(t *testing.T) {
	fx := newFixture(t)
	ctx, id := t.Context(), uuid.New()
	fx.windows.EXPECT().Windows(ctx, id).Return([]limits.Window{
		{Length: 2 * time.Hour, StartedAt: frozen.Add(-time.Hour), SpentUSD: 1},
		{Length: 5 * time.Hour, StartedAt: frozen.Add(-time.Hour), SpentUSD: 1},
		{Length: time.Hour, StartedAt: frozen.Add(-time.Minute), SpentUSD: 1},
	}, nil)
	fx.windows.EXPECT().Open(ctx, id, []time.Duration(nil), []time.Duration{time.Hour, 5 * time.Hour}, frozen).Return(nil)

	decision, err := fx.svc.Admit(ctx, id, limits.Set{twoHours})
	require.NoError(t, err, "admit")
	require.False(t, decision.Blocked, "blocked")
}

// Every administrator method refuses a plain user before any repository is
// touched: the strict mocks carry no expectations.
func TestAdminMethodsRefuseAPlainUser(t *testing.T) {
	person, id, window := newPerson(), uuid.New(), 2*time.Hour

	for name, call := range map[string]func(*fixture) error{
		"Defaults": func(fx *fixture) error {
			_, err := fx.svc.Defaults(person)

			return err
		},
		"SetDefaults": func(fx *fixture) error {
			_, err := fx.svc.SetDefaults(t.Context(), person, limits.Set{twoHours})

			return err
		},
		"ForUser": func(fx *fixture) error {
			_, err := fx.svc.ForUser(t.Context(), person, id)

			return err
		},
		"SetUser": func(fx *fixture) error {
			_, err := fx.svc.SetUser(t.Context(), person, id, &limits.Set{twoHours})

			return err
		},
		"Reset": func(fx *fixture) error {
			_, err := fx.svc.Reset(t.Context(), person, id, &window)

			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, call(newFixture(t)), app.ErrForbidden, name)
		})
	}
}

func TestForUserWrapsAnUnknownUser(t *testing.T) {
	fx := newFixture(t)
	ctx, id := t.Context(), uuid.New()
	fx.users.EXPECT().ByID(ctx, id).Return(identity.User{}, app.ErrNotFound)

	_, err := fx.svc.ForUser(ctx, newAdmin(), id)
	require.ErrorIs(t, err, app.ErrNotFound, "for user")
}

// The in-memory defaults change only once the store has them: a failed write
// leaves requests limited by the set that is still stored. Once audited, the
// windows of rules the new set lacks go from every inheriting account.
func TestSetDefaultsSwapsMemoryAfterTheWrite(t *testing.T) {
	fx := newFixture(t)
	ctx, admin := t.Context(), newAdmin()
	old, next := limits.Set{twoHours}, limits.Set{oneHour, oneDay}
	fx.settings.EXPECT().SpendLimitDefaults(ctx).Return(old, nil)
	require.NoError(t, fx.svc.Load(ctx), "load")

	boom := errors.New("connection reset")
	fx.settings.EXPECT().SetSpendLimitDefaults(ctx, next, admin.ID, frozen).Return(boom).Once()
	_, err := fx.svc.SetDefaults(ctx, admin, next)
	require.ErrorIs(t, err, boom, "failed write")
	require.Equal(t, old, fx.svc.Effective(nil), "defaults after a failed write")

	fx.settings.EXPECT().SetSpendLimitDefaults(ctx, next, admin.ID, frozen).Return(nil).Once()
	events := fx.recordAudit()
	fx.windows.EXPECT().DropInherited(ctx, []time.Duration{time.Hour, 24 * time.Hour}).Return(nil).Once().NotBefore(fx.audited)
	got, err := fx.svc.SetDefaults(ctx, admin, next)
	require.NoError(t, err, "write")
	require.Equal(t, next, got, "returned set")
	require.Equal(t, next, fx.svc.Effective(nil), "defaults after the write")
	require.Len(t, *events, 1, "audit events")
	require.Equal(t, "limits.defaults_update", (*events)[0].Action, "action")
	require.Equal(t, "spend_limits", (*events)[0].Target, "target")
	require.Equal(t, admin.ID, (*events)[0].ActorID, "actor")
	require.Equal(t, frozen, (*events)[0].At, "at")
}

// A failure dropping stale windows reports the new defaults as applied: they are
// stored, in force and audited.
func TestSetDefaultsReportsStaleWindows(t *testing.T) {
	fx := newFixture(t)
	ctx, admin, next := t.Context(), newAdmin(), limits.Set{}
	boom := errors.New("connection reset")

	fx.settings.EXPECT().SetSpendLimitDefaults(ctx, next, admin.ID, frozen).Return(nil)
	events := fx.recordAudit()
	fx.windows.EXPECT().DropInherited(ctx, []time.Duration{}).Return(boom)

	_, err := fx.svc.SetDefaults(ctx, admin, next)
	require.ErrorIs(t, err, boom, "set defaults")
	require.ErrorContains(t, err, "applied but stale windows remain", "set defaults")
	require.Empty(t, fx.svc.Effective(nil), "defaults in force")
	require.Len(t, *events, 1, "audit events")
}

// Validation errors name the web API's field: the count as a whole, or a rule's
// window or amount by its index in the body's limits array.
func TestInvalidSetsNameTheField(t *testing.T) {
	eleven := make(limits.Set, 0, limits.MaxRules+1)
	for i := range limits.MaxRules + 1 {
		eleven = append(eleven, limits.Rule{Window: time.Duration(i+1) * time.Hour, AmountUSD: 1})
	}

	for field, set := range map[string]limits.Set{
		"limits":            eleven,
		"[1].windowMinutes": {twoHours, twoHours},
		"[0].amountUsd":     {{Window: time.Hour, AmountUSD: 0}},
	} {
		fx := newFixture(t)

		_, err := fx.svc.SetDefaults(t.Context(), newAdmin(), set)

		var bad *app.InvalidInputError
		require.ErrorAs(t, err, &bad, "defaults refusing %s", field)
		require.Equal(t, field, bad.Field, "defaults")

		_, err = fx.svc.SetUser(t.Context(), newAdmin(), uuid.New(), &set)
		require.ErrorAs(t, err, &bad, "user limits refusing %s", field)
		require.Equal(t, field, bad.Field, "user limits")
	}
}

// Custom limits are written and audited, and then the windows of rules the
// account no longer has are dropped at once.
func TestSetUserWritesAuditsAndDrops(t *testing.T) {
	fx := newFixture(t)
	ctx, admin, user := t.Context(), newAdmin(), newPerson()
	set := limits.Set{oneHour}

	fx.users.EXPECT().ByID(ctx, user.ID).Return(user, nil)
	fx.users.EXPECT().UpdateSpendLimits(ctx, user.ID, &set).Return(nil)
	events := fx.recordAudit()
	fx.windows.EXPECT().Windows(ctx, user.ID).Return([]limits.Window{
		{Length: 2 * time.Hour, StartedAt: frozen.Add(-time.Hour), SpentUSD: 3},
		{Length: time.Hour, StartedAt: frozen.Add(-30 * time.Minute), SpentUSD: 1},
	}, nil).NotBefore(fx.audited)
	fx.windows.EXPECT().Open(ctx, user.ID, []time.Duration(nil), []time.Duration{2 * time.Hour}, frozen).Return(nil)

	view, err := fx.svc.SetUser(ctx, admin, user.ID, &set)
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

// A failure dropping stale windows reports the change as made: it is audited.
func TestSetUserReportsStaleWindows(t *testing.T) {
	fx := newFixture(t)
	ctx, user := t.Context(), newPerson()
	boom := errors.New("connection reset")

	fx.users.EXPECT().ByID(ctx, user.ID).Return(user, nil)
	fx.users.EXPECT().UpdateSpendLimits(ctx, user.ID, &limits.Set{}).Return(nil)
	events := fx.recordAudit()
	fx.windows.EXPECT().Windows(ctx, user.ID).Return(nil, boom)

	_, err := fx.svc.SetUser(ctx, newAdmin(), user.ID, &limits.Set{})
	require.ErrorIs(t, err, boom, "set user")
	require.ErrorContains(t, err, "set but stale windows remain", "set user")
	require.Len(t, *events, 1, "audit events")
}

// Back on the defaults, the account's windows of rules the defaults lack go.
func TestSetUserBackToDefault(t *testing.T) {
	fx := newFixture(t)
	ctx, admin, user := t.Context(), newAdmin(), newPerson()
	fx.settings.EXPECT().SpendLimitDefaults(ctx).Return(limits.Set{twoHours}, nil)
	require.NoError(t, fx.svc.Load(ctx), "load")

	custom := limits.Set{oneHour}
	user.SpendLimits = &custom
	fx.users.EXPECT().ByID(ctx, user.ID).Return(user, nil)
	fx.users.EXPECT().UpdateSpendLimits(ctx, user.ID, (*limits.Set)(nil)).Return(nil)
	events := fx.recordAudit()
	fx.windows.EXPECT().Windows(ctx, user.ID).Return([]limits.Window{
		{Length: time.Hour, StartedAt: frozen.Add(-30 * time.Minute), SpentUSD: 1},
	}, nil)
	fx.windows.EXPECT().Open(ctx, user.ID, []time.Duration(nil), []time.Duration{time.Hour}, frozen).Return(nil)

	view, err := fx.svc.SetUser(ctx, admin, user.ID, nil)
	require.NoError(t, err, "set user")
	require.Nil(t, view.Custom, "custom")
	require.Len(t, *events, 1, "audit events")
	require.Equal(t, map[string]any{"mode": "default"}, (*events)[0].Detail, "detail")
}

// Only a window of the account's effective set can be reset: anything else is
// refused before storage is touched.
func TestResetRefusesAWindowOutsideTheSet(t *testing.T) {
	fx := newFixture(t)
	ctx, user := t.Context(), newPerson()
	custom := limits.Set{twoHours}
	user.SpendLimits = &custom
	fx.users.EXPECT().ByID(ctx, user.ID).Return(user, nil)

	window := time.Hour
	_, err := fx.svc.Reset(ctx, newAdmin(), user.ID, &window)

	var bad *app.InvalidInputError
	require.ErrorAs(t, err, &bad, "reset")
	require.Equal(t, "windowMinutes", bad.Field, "field")
}

func TestResetOne(t *testing.T) {
	fx := newFixture(t)
	ctx, user := t.Context(), newPerson()
	custom := limits.Set{twoHours, oneDay}
	user.SpendLimits = &custom
	window := 2 * time.Hour

	fx.users.EXPECT().ByID(ctx, user.ID).Return(user, nil)
	fx.windows.EXPECT().Reset(ctx, user.ID, &window).Return(nil)
	fx.windows.EXPECT().Windows(ctx, user.ID).Return(nil, nil)
	events := fx.recordAudit()

	_, err := fx.svc.Reset(ctx, newAdmin(), user.ID, &window)
	require.NoError(t, err, "reset")
	require.Len(t, *events, 1, "audit events")
	require.Equal(t, "user.limits_reset", (*events)[0].Action, "action")
	require.Equal(t, map[string]any{"window_minutes": int64(120)}, (*events)[0].Detail, "detail")
}

func TestResetAll(t *testing.T) {
	fx := newFixture(t)
	ctx, user := t.Context(), newPerson()
	fx.users.EXPECT().ByID(ctx, user.ID).Return(user, nil)
	fx.windows.EXPECT().Reset(ctx, user.ID, (*time.Duration)(nil)).Return(nil)
	fx.windows.EXPECT().Windows(ctx, user.ID).Return(nil, nil)
	events := fx.recordAudit()

	_, err := fx.svc.Reset(ctx, newAdmin(), user.ID, nil)
	require.NoError(t, err, "reset")
	require.Len(t, *events, 1, "audit events")
	require.Equal(t, "user.limits_reset", (*events)[0].Action, "action")
	require.Equal(t, map[string]any{"window_minutes": "all"}, (*events)[0].Detail, "detail")
}

// An account inheriting the defaults sees them shortest window first, each with
// its live window, and no custom set.
func TestMineShowsTheEffectiveSet(t *testing.T) {
	fx := newFixture(t)
	ctx, user := t.Context(), newPerson()
	fx.settings.EXPECT().SpendLimitDefaults(ctx).Return(limits.Set{oneDay, twoHours}, nil)
	require.NoError(t, fx.svc.Load(ctx), "load")
	fx.windows.EXPECT().Windows(ctx, user.ID).Return([]limits.Window{
		{Length: 2 * time.Hour, StartedAt: frozen.Add(-time.Hour), SpentUSD: 4},
	}, nil)

	view, err := fx.svc.Mine(ctx, user)
	require.NoError(t, err, "mine")
	require.Nil(t, view.Custom, "custom")
	require.Equal(t, []limits.WindowState{
		{Rule: twoHours, StartedAt: frozen.Add(-time.Hour), ResetsAt: frozen.Add(time.Hour), SpentUSD: 4},
		{Rule: oneDay},
	}, view.Windows, "windows")
}
