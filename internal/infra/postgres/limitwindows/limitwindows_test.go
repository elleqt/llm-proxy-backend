package limitwindows_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/domain/limits"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/limitwindows"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	pgusage "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/usage"
	pgusers "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/users"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSpendWindowRepo shares one container; every case owns its user.
func TestSpendWindowRepo(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.NewTestPool(t)
	users, ledger, windows := pgusers.New(pool), pgusage.New(pool), limitwindows.New(pool)
	t0 := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

	newUser := func(t *testing.T) uuid.UUID {
		t.Helper()

		u := identity.NewService(uuid.New(), "owner-"+uuid.NewString(), access.Policy{})
		require.NoError(t, users.Create(ctx, u), "create user")

		return u.ID
	}

	charge := func(t *testing.T, userID uuid.UUID, usd float64) {
		t.Helper()

		_, err := ledger.AppendBatch(ctx, []app.UsageEvent{{
			At: t0, UserID: userID, Provider: "claude", Model: "m1",
			Cost: app.UsageCost{InputUSD: usd, Priced: true},
		}})
		require.NoError(t, err, "charge")
	}

	// stored reads userID's windows keyed by length.
	stored := func(t *testing.T, userID uuid.UUID) map[time.Duration]limits.Window {
		t.Helper()

		got, err := windows.Windows(ctx, userID)
		require.NoError(t, err, "Windows")

		out := make(map[time.Duration]limits.Window, len(got))
		for _, w := range got {
			out[w.Length] = w
		}

		return out
	}

	t.Run("OpenStartsMissingWindows", func(t *testing.T) {
		u := newUser(t)

		require.NoError(t, windows.Open(ctx, u, []time.Duration{2 * time.Hour, 24 * time.Hour}, nil, t0), "Open")

		got := stored(t, u)
		require.Len(t, got, 2, "windows")

		for _, length := range []time.Duration{2 * time.Hour, 24 * time.Hour} {
			w, ok := got[length]
			require.True(t, ok, "window %s stored", length)
			assert.WithinDuration(t, t0, w.StartedAt, time.Microsecond, "started %s", length)
			assert.Zero(t, w.SpentUSD, "spent %s", length)
		}
	})

	t.Run("OpenRestartsOnlyExpiredRows", func(t *testing.T) {
		u := newUser(t)
		require.NoError(t, windows.Open(ctx, u, []time.Duration{2 * time.Hour, 24 * time.Hour}, nil, t0), "Open")
		charge(t, u, 3)

		later := t0.Add(2 * time.Hour)
		require.NoError(t, windows.Open(ctx, u, []time.Duration{2 * time.Hour, 24 * time.Hour}, nil, later), "reopen")

		got := stored(t, u)
		require.Len(t, got, 2, "windows")
		assert.WithinDuration(t, later, got[2*time.Hour].StartedAt, time.Microsecond, "2h restarted")
		assert.Zero(t, got[2*time.Hour].SpentUSD, "2h spent")
		assert.WithinDuration(t, t0, got[24*time.Hour].StartedAt, time.Microsecond, "24h untouched")
		assert.InDelta(t, 3.0, got[24*time.Hour].SpentUSD, 1e-9, "24h spent")
	})

	t.Run("ConcurrentOpensStartOnce", func(t *testing.T) {
		u := newUser(t)
		require.NoError(t, windows.Open(ctx, u, []time.Duration{2 * time.Hour}, nil, t0), "Open")

		first, second := t0.Add(3*time.Hour), t0.Add(3*time.Hour+time.Second)

		var wg sync.WaitGroup
		for _, at := range []time.Time{first, second} {
			wg.Go(func() {
				assert.NoError(t, windows.Open(ctx, u, []time.Duration{2 * time.Hour}, nil, at), "Open at %s", at)
			})
		}
		wg.Wait()

		// Whichever open ran first restarted the expired row; the other found it
		// live and left it. The charge follows both, so one window holds all of it.
		charge(t, u, 1)

		got := stored(t, u)
		require.Len(t, got, 1, "windows")

		w := got[2*time.Hour]
		assert.InDelta(t, 1.0, w.SpentUSD, 1e-9, "spent")

		startedFirst := w.StartedAt.Sub(first).Abs() < time.Microsecond
		startedSecond := w.StartedAt.Sub(second).Abs() < time.Microsecond
		assert.True(t, startedFirst || startedSecond, "started at one of the opens, got %s", w.StartedAt)
	})

	t.Run("OpenDropsOrphans", func(t *testing.T) {
		u := newUser(t)
		require.NoError(t, windows.Open(ctx, u, []time.Duration{2 * time.Hour, 5 * time.Hour}, nil, t0), "Open")

		require.NoError(t, windows.Open(ctx, u, nil, []time.Duration{5 * time.Hour}, t0.Add(time.Minute)), "drop")

		got := stored(t, u)
		require.Len(t, got, 1, "windows")
		assert.Contains(t, got, 2*time.Hour, "2h kept")
	})

	t.Run("ResetOneAndAll", func(t *testing.T) {
		u := newUser(t)
		require.NoError(t, windows.Open(ctx, u, []time.Duration{2 * time.Hour, 24 * time.Hour}, nil, t0), "Open")

		two := 2 * time.Hour
		require.NoError(t, windows.Reset(ctx, u, &two), "Reset 2h")

		got := stored(t, u)
		require.Len(t, got, 1, "windows after one reset")
		assert.Contains(t, got, 24*time.Hour, "24h kept")

		require.NoError(t, windows.Reset(ctx, u, nil), "Reset all")
		assert.Empty(t, stored(t, u), "windows after reset all")

		require.NoError(t, windows.Reset(ctx, u, &two), "Reset a missing window")
	})

	t.Run("RowsGoWithTheUser", func(t *testing.T) {
		u := newUser(t)
		require.NoError(t, windows.Open(ctx, u, []time.Duration{2 * time.Hour}, nil, t0), "Open")

		_, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, u)
		require.NoError(t, err, "delete user")

		assert.Empty(t, stored(t, u), "windows")
	})
}
