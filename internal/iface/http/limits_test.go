package http

import (
	"net/http"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/domain/limits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// withDefaults makes set the global spend limits the service holds, as boot's
// Load reads them.
func (e *testEnv) withDefaults(set limits.Set) {
	e.t.Helper()
	e.settings.EXPECT().SpendLimitDefaults(mock.Anything).Return(set, nil).Once()
	require.NoError(e.t, e.deps.Limits.Load(e.t.Context()), "Load")
}

// The cabinet shows the rules in force, shortest window first, each with its
// live window or nulls when none is live, as a share of the limit; the amounts
// only while users may see costs. An account inheriting no defaults has none.
func TestGetMyLimits(t *testing.T) {
	t.Run("no limits", func(t *testing.T) {
		env := newEnv(t)
		user := person("p@example.com")
		env.windows.EXPECT().Windows(mock.Anything, user.ID).Return(nil, nil)

		rec := env.do(http.MethodGet, "/api/me/limits", "", withCookie(env.signedIn(user)))
		require.Equal(t, http.StatusOK, rec.Code, "status; body %s", rec.Body)
		assert.JSONEq(t, `{"windows":[]}`, rec.Body.String())
	})

	live := func(env *testEnv, user identity.User) {
		env.withDefaults(limits.Set{
			{Window: 7 * 24 * time.Hour, AmountUSD: 50}, {Window: 2 * time.Hour, AmountUSD: 10}, {Window: 24 * time.Hour, AmountUSD: 30},
		})
		env.windows.EXPECT().Windows(mock.Anything, user.ID).Return([]limits.Window{
			{Length: 2 * time.Hour, StartedAt: env.clock.Now().Add(-30 * time.Minute), SpentUSD: 10.5},
			{Length: 24 * time.Hour, StartedAt: env.clock.Now().Add(-time.Hour), SpentUSD: 12.34},
		}, nil)
	}

	t.Run("costs hidden: shares only", func(t *testing.T) {
		env := newEnv(t)
		user := person("p@example.com")
		live(env, user)

		rec := env.do(http.MethodGet, "/api/me/limits", "", withCookie(env.signedIn(user)))
		require.Equal(t, http.StatusOK, rec.Code, "status; body %s", rec.Body)
		assert.JSONEq(t, `{"windows":[
			{"windowMinutes":120,"spentPercent":100,
			 "startedAt":"2026-09-22T11:30:00Z","resetsAt":"2026-09-22T13:30:00Z","exhausted":true},
			{"windowMinutes":1440,"spentPercent":41,
			 "startedAt":"2026-09-22T11:00:00Z","resetsAt":"2026-09-23T11:00:00Z","exhausted":false},
			{"windowMinutes":10080,"spentPercent":0,"startedAt":null,"resetsAt":null,"exhausted":false}
		]}`, rec.Body.String())
	})

	t.Run("costs visible: amounts too", func(t *testing.T) {
		env := newEnv(t)
		env.withCostsVisible()

		user := person("p@example.com")
		live(env, user)

		rec := env.do(http.MethodGet, "/api/me/limits", "", withCookie(env.signedIn(user)))
		require.Equal(t, http.StatusOK, rec.Code, "status; body %s", rec.Body)
		assert.JSONEq(t, `{"windows":[
			{"windowMinutes":120,"spentPercent":100,"amountUsd":10,"spentUsd":10.5,
			 "startedAt":"2026-09-22T11:30:00Z","resetsAt":"2026-09-22T13:30:00Z","exhausted":true},
			{"windowMinutes":1440,"spentPercent":41,"amountUsd":30,"spentUsd":12.34,
			 "startedAt":"2026-09-22T11:00:00Z","resetsAt":"2026-09-23T11:00:00Z","exhausted":false},
			{"windowMinutes":10080,"spentPercent":0,"amountUsd":50,"spentUsd":0,"startedAt":null,"resetsAt":null,"exhausted":false}
		]}`, rec.Body.String())
	})
}

// Under spend limits, a model the policy admits but nobody priced is listed as
// unpriced rather than allowed, since the gate refuses it; the price list here
// is empty.
func TestMyModelsListUnpricedUnderLimits(t *testing.T) {
	env := newEnv(t)
	env.withDefaults(limits.Set{{Window: time.Hour, AmountUSD: 1}})
	env.catalog.EXPECT().Models().Return(map[string][]string{"claude": {"a"}})
	env.catalog.EXPECT().ProvidersFor("a").Return([]string{"claude"})
	env.catalog.EXPECT().KnownModel("a").Return("a", true)

	rule, err := access.ParseRule("claude:*")
	require.NoError(t, err, "ParseRule")

	user := person("p@example.com")
	user.Policy = access.Policy{rule}

	rec := env.do(http.MethodGet, "/api/me/models", "", withCookie(env.signedIn(user)))
	require.Equal(t, http.StatusOK, rec.Code, "status; body %s", rec.Body)
	assert.JSONEq(t, `{"providers":[{"name":"claude","models":[],"unpriced":["a"]}]}`, rec.Body.String())
}

// An invalid set is refused naming the entry and nothing is stored; a valid one
// is stored, audited, echoed, and is what the defaults read back as.
func TestReplaceDefaultLimits(t *testing.T) {
	for name, tc := range map[string]struct{ body, field string }{
		"repeated window": {`[{"windowMinutes":120,"amountUsd":10},{"windowMinutes":120,"amountUsd":30}]`, "[1].windowMinutes"},
		"window too long": {`[{"windowMinutes":525601,"amountUsd":10}]`, "[0].windowMinutes"},
		// Multiplied into a duration unchecked, this wraps to exactly one minute.
		"window overflowing a duration": {`[{"windowMinutes":9007199254740993,"amountUsd":10}]`, "[0].windowMinutes"},
		"amount zero":                   {`[{"windowMinutes":60,"amountUsd":0}]`, "[0].amountUsd"},
		"too many": {`[{"windowMinutes":1,"amountUsd":1},{"windowMinutes":2,"amountUsd":1},{"windowMinutes":3,"amountUsd":1},
			{"windowMinutes":4,"amountUsd":1},{"windowMinutes":5,"amountUsd":1},{"windowMinutes":6,"amountUsd":1},
			{"windowMinutes":7,"amountUsd":1},{"windowMinutes":8,"amountUsd":1},{"windowMinutes":9,"amountUsd":1},
			{"windowMinutes":10,"amountUsd":1},{"windowMinutes":11,"amountUsd":1}]`, "limits"},
	} {
		t.Run(name, func(t *testing.T) {
			env := newEnv(t)
			rec := env.do(http.MethodPut, "/api/admin/limits", tc.body, withCookie(env.signedIn(admin())))
			wantField(t, apiError(t, rec, http.StatusUnprocessableEntity, codeInvalidInput), tc.field)
		})
	}

	t.Run("valid", func(t *testing.T) {
		var events []app.AuditEvent

		env := newEnv(t, auditInto(&events))
		actor := admin()
		cookie := env.signedIn(actor)
		set := limits.Set{{Window: 2 * time.Hour, AmountUSD: 10.25}}
		env.settings.EXPECT().SetSpendLimitDefaults(mock.Anything, set, actor.ID, env.clock.Now()).Return(nil)
		env.windows.EXPECT().DropInherited(mock.Anything, []time.Duration{2 * time.Hour}).Return(nil)

		const body = `[{"windowMinutes":120,"amountUsd":10.25}]`

		rec := env.do(http.MethodPut, "/api/admin/limits", body, withCookie(cookie))
		require.Equal(t, http.StatusOK, rec.Code, "status; body %s", rec.Body)
		assert.JSONEq(t, body, rec.Body.String(), "echo")
		require.Len(t, events, 1, "audit events")
		assert.Equal(t, "limits.defaults_update", events[0].Action, "audit action")

		rec = env.do(http.MethodGet, "/api/admin/limits", "", withCookie(cookie))
		require.Equal(t, http.StatusOK, rec.Code, "status; body %s", rec.Body)
		assert.JSONEq(t, body, rec.Body.String(), "read back")
	})
}

// The mode decides whether limits is required: custom needs it (an empty list
// means no limits), default refuses it; a missing or unknown mode names mode.
func TestSetUserLimitsModes(t *testing.T) {
	path := func(u identity.User) string { return "/api/admin/users/" + u.ID.String() + "/limits" }

	for name, tc := range map[string]struct{ body, field string }{
		"custom without limits": {`{"mode":"custom"}`, "limits"},
		"default with limits":   {`{"mode":"default","limits":[]}`, "limits"},
		"unknown mode":          {`{"mode":"strict","limits":[]}`, "mode"},
		"missing mode":          {`{"limits":[]}`, "mode"},
		"invalid rule":          {`{"mode":"custom","limits":[{"windowMinutes":0,"amountUsd":1}]}`, "[0].windowMinutes"},
	} {
		t.Run(name, func(t *testing.T) {
			env := newEnv(t)
			rec := env.do(http.MethodPut, path(person("t@example.com")), tc.body, withCookie(env.signedIn(admin())))
			wantField(t, apiError(t, rec, http.StatusUnprocessableEntity, codeInvalidInput), tc.field)
		})
	}

	for name, tc := range map[string]struct {
		body   string
		custom *limits.Set
		want   string
	}{
		"custom with an empty list": {`{"mode":"custom","limits":[]}`, &limits.Set{}, `{"mode":"custom","custom":[],"windows":[]}`},
		"back to the defaults":      {`{"mode":"default"}`, nil, `{"mode":"default","custom":[],"windows":[]}`},
	} {
		t.Run(name, func(t *testing.T) {
			env := newEnv(t)
			target := person("t@example.com")
			env.users.EXPECT().ByID(mock.Anything, target.ID).Return(target, nil)
			env.users.EXPECT().UpdateSpendLimits(mock.Anything, target.ID, tc.custom).Return(nil)
			env.windows.EXPECT().Windows(mock.Anything, target.ID).Return(nil, nil)

			rec := env.do(http.MethodPut, path(target), tc.body, withCookie(env.signedIn(admin())))
			require.Equal(t, http.StatusOK, rec.Code, "status; body %s", rec.Body)
			assert.JSONEq(t, tc.want, rec.Body.String())
		})
	}

	t.Run("unknown account", func(t *testing.T) {
		env := newEnv(t)
		target := person("t@example.com")
		env.users.EXPECT().ByID(mock.Anything, target.ID).Return(identity.User{}, app.ErrNotFound)

		rec := env.do(http.MethodPut, path(target), `{"mode":"custom","limits":[]}`, withCookie(env.signedIn(admin())))
		apiError(t, rec, http.StatusNotFound, codeNotFound)
	})
}

// An administrator reads an account's own set with its live window as the
// cabinet shows it; an account that does not exist is not found.
func TestGetUserLimits(t *testing.T) {
	path := func(u identity.User) string { return "/api/admin/users/" + u.ID.String() + "/limits" }

	t.Run("custom with a live window", func(t *testing.T) {
		env := newEnv(t)
		target := person("t@example.com")
		target.SpendLimits = &limits.Set{{Window: time.Hour, AmountUSD: 5}}
		env.users.EXPECT().ByID(mock.Anything, target.ID).Return(target, nil)
		env.windows.EXPECT().Windows(mock.Anything, target.ID).Return([]limits.Window{
			{Length: time.Hour, StartedAt: env.clock.Now().Add(-15 * time.Minute), SpentUSD: 1.25},
		}, nil)

		rec := env.do(http.MethodGet, path(target), "", withCookie(env.signedIn(admin())))
		require.Equal(t, http.StatusOK, rec.Code, "status; body %s", rec.Body)
		assert.JSONEq(t, `{"mode":"custom","custom":[{"windowMinutes":60,"amountUsd":5}],"windows":[
			{"windowMinutes":60,"amountUsd":5,"spentUsd":1.25,"spentPercent":25,
			 "startedAt":"2026-09-22T11:45:00Z","resetsAt":"2026-09-22T12:45:00Z","exhausted":false}
		]}`, rec.Body.String())
	})

	t.Run("unknown account", func(t *testing.T) {
		env := newEnv(t)
		target := person("t@example.com")
		env.users.EXPECT().ByID(mock.Anything, target.ID).Return(identity.User{}, app.ErrNotFound)

		rec := env.do(http.MethodGet, path(target), "", withCookie(env.signedIn(admin())))
		apiError(t, rec, http.StatusNotFound, codeNotFound)
	})
}

// A reset names a window in force, or omits it to reset all; a window no rule
// in force has is refused before anything is deleted.
func TestResetUserLimits(t *testing.T) {
	twoHours := 2 * time.Hour

	for name, tc := range map[string]struct {
		body   string
		window *time.Duration
	}{
		"one window":  {`{"windowMinutes":120}`, &twoHours},
		"all windows": {`{}`, nil},
	} {
		t.Run(name, func(t *testing.T) {
			env := newEnv(t)
			target := person("t@example.com")
			target.SpendLimits = &limits.Set{{Window: twoHours, AmountUSD: 10}}
			env.users.EXPECT().ByID(mock.Anything, target.ID).Return(target, nil)
			env.windows.EXPECT().Reset(mock.Anything, target.ID, tc.window).Return(nil)
			env.windows.EXPECT().Windows(mock.Anything, target.ID).Return(nil, nil)

			rec := env.do(http.MethodPost, "/api/admin/users/"+target.ID.String()+"/limits/reset", tc.body,
				withCookie(env.signedIn(admin())))
			require.Equal(t, http.StatusOK, rec.Code, "status; body %s", rec.Body)
			assert.JSONEq(t, `{"mode":"custom","custom":[{"windowMinutes":120,"amountUsd":10}],"windows":[
				{"windowMinutes":120,"amountUsd":10,"spentUsd":0,"spentPercent":0,"startedAt":null,"resetsAt":null,"exhausted":false}
			]}`, rec.Body.String())
		})
	}

	t.Run("window not in force", func(t *testing.T) {
		env := newEnv(t)
		target := person("t@example.com")
		target.SpendLimits = &limits.Set{{Window: twoHours, AmountUSD: 10}}
		env.users.EXPECT().ByID(mock.Anything, target.ID).Return(target, nil)

		rec := env.do(http.MethodPost, "/api/admin/users/"+target.ID.String()+"/limits/reset", `{"windowMinutes":5}`,
			withCookie(env.signedIn(admin())))
		wantField(t, apiError(t, rec, http.StatusUnprocessableEntity, codeInvalidInput), "windowMinutes")
	})
}
