package usage_test

import (
	"context"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/limitwindows"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	pgtokens "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/tokens"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/usage"
	pgusers "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/users"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// TestUsageRepo shares one container; every case owns its user.
func TestUsageRepo(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.NewTestPool(t)
	users, tokens, windows := pgusers.New(pool), pgtokens.New(pool), limitwindows.New(pool)

	// A session zone with a half-hour offset: buckets truncated in it rather than
	// in UTC would start at :30 and on the wrong day.
	cfg := pool.Config().Copy()
	cfg.ConnConfig.RuntimeParams["timezone"] = "Asia/Kolkata"

	kolkata, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err, "pool")

	t.Cleanup(kolkata.Close)
	ledger := usage.New(kolkata)

	newOwner := func(t *testing.T) (identity.User, credentials.Token) {
		t.Helper()

		owner := identity.NewService(uuid.New(), "owner-"+uuid.NewString(), access.Policy{})
		require.NoError(t, users.Create(ctx, owner), "create user")

		tok, _, err := credentials.Generate(owner.ID, "key")
		require.NoError(t, err, "generate")
		require.NoError(t, tokens.Create(ctx, tok), "create token")

		return owner, tok
	}

	t.Run("AppendBatchRoundTripsEveryColumn", func(t *testing.T) {
		owner, tok := newOwner(t)

		want := app.UsageEvent{
			At: time.Date(2026, 9, 1, 10, 15, 30, 0, time.UTC), UserID: owner.ID, TokenID: tok.ID,
			Provider: "claude", Model: "claude-sonnet-5", Alias: "sonnet", Stream: true, ServiceTier: "priority",
			TokensInput: 1, TokensOutput: 2, TokensReasoning: 3, TokensCacheRead: 4, TokensCacheWrite: 5,
			TokensTotal: 15, BreakdownQuality: "complete", LatencyMS: 1500, TTFTMS: 300, StatusCode: 429,
			Failed: true, VendorAccountID: "claude-1.json",
			Cost: app.UsageCost{
				InputUSD: 0.5, OutputUSD: 1.25, CacheReadUSD: 0.125, CacheWriteUSD: 2,
				CacheSavingsUSD: -0.75, UnpricedTokens: 6, Priced: true,
			},
		}
		_, err := ledger.AppendBatch(ctx, []app.UsageEvent{want})
		require.NoError(t, err, "AppendBatch")

		var got app.UsageEvent

		err = pool.QueryRow(ctx, `SELECT at, user_id, token_id, provider, model, alias, stream, service_tier,
			tokens_input, tokens_output, tokens_reasoning, tokens_cache_read, tokens_cache_write, tokens_total,
			breakdown_quality, latency_ms, ttft_ms, status_code, failed, vendor_account_id,
			cost_input_usd, cost_output_usd, cost_cache_read_usd, cost_cache_write_usd, cache_savings_usd,
			unpriced_tokens, priced
			FROM usage_events WHERE user_id = $1`, owner.ID).Scan(
			&got.At, &got.UserID, &got.TokenID, &got.Provider, &got.Model, &got.Alias, &got.Stream, &got.ServiceTier,
			&got.TokensInput, &got.TokensOutput, &got.TokensReasoning, &got.TokensCacheRead, &got.TokensCacheWrite,
			&got.TokensTotal, &got.BreakdownQuality, &got.LatencyMS, &got.TTFTMS, &got.StatusCode, &got.Failed,
			&got.VendorAccountID, &got.Cost.InputUSD, &got.Cost.OutputUSD, &got.Cost.CacheReadUSD,
			&got.Cost.CacheWriteUSD, &got.Cost.CacheSavingsUSD, &got.Cost.UnpricedTokens, &got.Cost.Priced)
		require.NoError(t, err, "read back")

		// Deep equality on purpose, as before: the row normalized to UTC must match
		// want field for field, At's location included.
		got.At = got.At.UTC()
		require.Equal(t, want, got, "row")
	})

	t.Run("AppendBatchStoresUnknownPrincipalsAsNull", func(t *testing.T) {
		// One row unattributed, one naming a user and token that do not exist (a
		// deleted owner), one valid: the batch must keep all three.
		owner, tok := newOwner(t)
		model := "null-" + uuid.NewString()
		at := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)

		_, err := ledger.AppendBatch(ctx, []app.UsageEvent{
			{At: at, Provider: "claude", Model: model},
			{At: at, UserID: uuid.New(), TokenID: uuid.New(), Provider: "claude", Model: model},
			{At: at, UserID: owner.ID, TokenID: tok.ID, Provider: "claude", Model: model},
		})
		require.NoError(t, err, "AppendBatch")

		var nulls, attributed int

		err = pool.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE user_id IS NULL AND token_id IS NULL),
			count(*) FILTER (WHERE user_id = $2 AND token_id = $3)
			FROM usage_events WHERE model = $1`, model, owner.ID, tok.ID).Scan(&nulls, &attributed)
		require.NoError(t, err, "count")
		require.Equal(t, 2, nulls, "unattributed rows")
		require.Equal(t, 1, attributed, "attributed rows")
	})

	t.Run("AppendBatchWritesAllOrNothing", func(t *testing.T) {
		// The second row carries a NUL, which Postgres refuses in text: the
		// first row, already sent in the same batch, must not be kept.
		owner, tok := newOwner(t)
		at := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)

		_, err := ledger.AppendBatch(ctx, []app.UsageEvent{
			{At: at, UserID: owner.ID, TokenID: tok.ID, Provider: "claude", Model: "fine"},
			{At: at, UserID: owner.ID, TokenID: tok.ID, Provider: "claude", Model: "bad\x00model"},
		})
		require.Error(t, err, "AppendBatch accepted a row Postgres refuses")

		var count int

		err = pool.QueryRow(ctx, `SELECT count(*) FROM usage_events WHERE user_id = $1`, owner.ID).Scan(&count)
		require.NoError(t, err, "count")
		require.Zero(t, count, "rows of the failed batch were kept")
	})

	// spent reads userID's window spends keyed by length.
	spent := func(t *testing.T, userID uuid.UUID) map[time.Duration]float64 {
		t.Helper()

		got, err := windows.Windows(ctx, userID)
		require.NoError(t, err, "Windows")

		out := make(map[time.Duration]float64, len(got))
		for _, w := range got {
			out[w.Length] = w.SpentUSD
		}

		return out
	}
	openAt := time.Date(2026, 9, 4, 0, 0, 0, 0, time.UTC)

	t.Run("AppendBatchChargesEveryWindowOfItsOwner", func(t *testing.T) {
		a, aTok := newOwner(t)
		b, bTok := newOwner(t)
		require.NoError(t, windows.Open(ctx, a.ID, []time.Duration{2 * time.Hour, 24 * time.Hour}, nil, openAt), "open a")
		require.NoError(t, windows.Open(ctx, b.ID, []time.Duration{2 * time.Hour}, nil, openAt), "open b")

		ev := func(user, token uuid.UUID, usd float64, failed bool) app.UsageEvent {
			return app.UsageEvent{
				At: openAt, UserID: user, TokenID: token, Provider: "claude", Model: "m1", Failed: failed,
				Cost: app.UsageCost{InputUSD: usd, Priced: true},
			}
		}
		limited, err := ledger.AppendBatch(ctx, []app.UsageEvent{
			ev(a.ID, aTok.ID, 1.5, false),
			// A failed attempt spent its tokens: it counts against the limit too.
			ev(a.ID, aTok.ID, 0.25, true),
			ev(b.ID, bTok.ID, 2, false),
			ev(uuid.Nil, uuid.Nil, 9, false),
		})
		require.NoError(t, err, "AppendBatch")
		require.Equal(t, map[uuid.UUID]struct{}{a.ID: {}, b.ID: {}}, limited, "owners with windows")

		gotA := spent(t, a.ID)
		require.Len(t, gotA, 2, "a's windows")
		require.InDelta(t, 1.75, gotA[2*time.Hour], 1e-9, "a 2h")
		require.InDelta(t, 1.75, gotA[24*time.Hour], 1e-9, "a 24h")
		require.Equal(t, map[time.Duration]float64{2 * time.Hour: 2}, spent(t, b.ID), "b's windows")
	})

	t.Run("AppendBatchReportsOnlyOwnersWithWindows", func(t *testing.T) {
		c, cTok := newOwner(t)

		limited, err := ledger.AppendBatch(ctx, []app.UsageEvent{{
			At: openAt, UserID: c.ID, TokenID: cTok.ID, Provider: "claude", Model: "m1",
			Cost: app.UsageCost{InputUSD: 1, Priced: true},
		}})
		require.NoError(t, err, "AppendBatch")
		require.Empty(t, limited, "owners with windows")
	})

	t.Run("FailedBatchChargesNothing", func(t *testing.T) {
		owner, tok := newOwner(t)
		require.NoError(t, windows.Open(ctx, owner.ID, []time.Duration{2 * time.Hour}, nil, openAt), "open")

		limited, err := ledger.AppendBatch(ctx, []app.UsageEvent{
			{At: openAt, UserID: owner.ID, TokenID: tok.ID, Provider: "claude", Model: "m1", Cost: app.UsageCost{InputUSD: 2}},
			// cost_input_usd's CHECK refuses a negative cost. The owner still nets $1,
			// so a charge that escaped the batch's transaction would show.
			{At: openAt, UserID: owner.ID, TokenID: tok.ID, Provider: "claude", Model: "m1", Cost: app.UsageCost{InputUSD: -1}},
		})
		require.Error(t, err, "AppendBatch accepted a row Postgres refuses")
		require.Nil(t, limited, "owners of a failed batch")

		var count int

		err = pool.QueryRow(ctx, `SELECT count(*) FROM usage_events WHERE user_id = $1`, owner.ID).Scan(&count)
		require.NoError(t, err, "count")
		require.Zero(t, count, "rows of the failed batch were kept")
		require.Equal(t, map[time.Duration]float64{2 * time.Hour: 0}, spent(t, owner.ID), "window charged by a failed batch")
	})

	t.Run("SeriesForUserBucketsHoursByModel", func(t *testing.T) {
		owner, tok := newOwner(t)
		other, otherTok := newOwner(t)
		from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		to := from.Add(24 * time.Hour)
		ev := func(user, token uuid.UUID, at time.Time, model string, tokens int64) app.UsageEvent {
			return app.UsageEvent{At: at, UserID: user, TokenID: token, Provider: "claude", Model: model, TokensTotal: tokens}
		}
		failed := func(e app.UsageEvent) app.UsageEvent {
			e.Failed, e.StatusCode = true, 429

			return e
		}

		hourAt := func(hour, minute int) time.Time {
			return from.Add(time.Duration(hour)*time.Hour + time.Duration(minute)*time.Minute)
		}
		_, err := ledger.AppendBatch(ctx, []app.UsageEvent{
			ev(owner.ID, tok.ID, hourAt(10, 15), "m1", 10),
			ev(owner.ID, tok.ID, hourAt(10, 45), "m1", 5),
			// An attempt that failed after spending tokens, then retried on
			// another account (the 10:45 row): tokens count, the request does not.
			failed(ev(owner.ID, tok.ID, hourAt(10, 44), "m1", 3)),
			ev(owner.ID, tok.ID, hourAt(10, 30), "m2", 7),
			ev(owner.ID, tok.ID, hourAt(11, 5), "m1", 0), // served, no tokens reported
			// Only failed attempts that spent nothing: no point at all.
			failed(ev(owner.ID, tok.ID, hourAt(12, 10), "m2", 0)),
			ev(owner.ID, tok.ID, from, "m1", 1), // on from: in
			ev(owner.ID, tok.ID, to, "m1", 100), // on to: out
			ev(owner.ID, tok.ID, from.Add(-time.Second), "m1", 100),
			ev(other.ID, otherTok.ID, hourAt(10, 20), "m1", 100),
		})
		require.NoError(t, err, "AppendBatch")

		got, err := ledger.SeriesForUser(ctx, owner.ID, from, to)
		require.NoError(t, err, "SeriesForUser")

		want := app.UsageSeries{
			Bucket: app.UsageBucketHour,
			Totals: app.UsageTotals{Requests: 5, TokensTotal: 26},
			Points: []app.UsagePoint{
				{At: from, Model: "m1", Requests: 1, TokensTotal: 1},
				{At: hourAt(10, 0), Model: "m1", Requests: 2, TokensTotal: 18},
				{At: hourAt(10, 0), Model: "m2", Requests: 1, TokensTotal: 7},
				{At: hourAt(11, 0), Model: "m1", Requests: 1, TokensTotal: 0},
			},
		}
		require.Equal(t, want, got, "series")
	})

	// The series sums the cost each row stored; it prices nothing itself.
	t.Run("SeriesForUserSumsStoredCost", func(t *testing.T) {
		owner, tok := newOwner(t)
		from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

		ev := func(minute int, model string, c app.UsageCost) app.UsageEvent {
			return app.UsageEvent{
				At: from.Add(10*time.Hour + time.Duration(minute)*time.Minute), UserID: owner.ID, TokenID: tok.ID,
				Provider: "claude", Model: model, TokensTotal: 100, Cost: c,
			}
		}
		_, err := ledger.AppendBatch(ctx, []app.UsageEvent{
			ev(1, "m1", app.UsageCost{InputUSD: 1, OutputUSD: 2, CacheReadUSD: 0.25, CacheWriteUSD: 0.5, CacheSavingsUSD: 1.5, Priced: true}),
			ev(2, "m1", app.UsageCost{InputUSD: 0.5, CacheWriteUSD: 4, CacheSavingsUSD: -2, UnpricedTokens: 10, Priced: true}),
			ev(3, "m2", app.UsageCost{UnpricedTokens: 100}),
		})
		require.NoError(t, err, "AppendBatch")

		got, err := ledger.SeriesForUser(ctx, owner.ID, from, from.Add(24*time.Hour))
		require.NoError(t, err, "SeriesForUser")
		require.Len(t, got.Points, 2, "points")
		require.Equal(t, 8.25, got.Points[0].CostUSD, "m1 cost")
		require.Zero(t, got.Points[1].CostUSD, "m2 cost")

		want := app.UsageCost{
			InputUSD: 1.5, OutputUSD: 2, CacheReadUSD: 0.25, CacheWriteUSD: 4.5,
			CacheSavingsUSD: -0.5, UnpricedTokens: 110, Priced: true,
		}
		require.Equal(t, want, got.Totals.Cost, "totals cost")
	})

	t.Run("SeriesForUserBucketsDaysBeyondTwoDays", func(t *testing.T) {
		owner, tok := newOwner(t)
		from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		to := from.Add(7 * 24 * time.Hour)

		day := func(d, hour int) time.Time { return from.AddDate(0, 0, d).Add(time.Duration(hour) * time.Hour) }
		_, err := ledger.AppendBatch(ctx, []app.UsageEvent{
			// 20:00 UTC is already the next day in Kolkata.
			{At: day(0, 20), UserID: owner.ID, TokenID: tok.ID, Provider: "claude", Model: "m1", TokensTotal: 3},
			{At: day(0, 1), UserID: owner.ID, TokenID: tok.ID, Provider: "claude", Model: "m1", TokensTotal: 4},
			{At: day(2, 23), UserID: owner.ID, TokenID: tok.ID, Provider: "claude", Model: "m1", TokensTotal: 5},
		})
		require.NoError(t, err, "AppendBatch")

		got, err := ledger.SeriesForUser(ctx, owner.ID, from, to)
		require.NoError(t, err, "SeriesForUser")

		want := app.UsageSeries{
			Bucket: app.UsageBucketDay,
			Totals: app.UsageTotals{Requests: 3, TokensTotal: 12},
			Points: []app.UsagePoint{
				{At: day(0, 0), Model: "m1", Requests: 2, TokensTotal: 7},
				{At: day(2, 0), Model: "m1", Requests: 1, TokensTotal: 5},
			},
		}
		require.Equal(t, want, got, "series")
	})

	t.Run("SeriesForUserWithNoUsageIsEmpty", func(t *testing.T) {
		owner, _ := newOwner(t)
		from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

		got, err := ledger.SeriesForUser(ctx, owner.ID, from, from.Add(48*time.Hour))
		require.NoError(t, err, "SeriesForUser")
		require.Equal(t, app.UsageBucketHour, got.Bucket, "bucket")
		require.Zero(t, got.Totals, "totals")
		require.Empty(t, got.Points, "points")
	})
}
