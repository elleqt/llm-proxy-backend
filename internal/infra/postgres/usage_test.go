package postgres_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
)

// TestUsageRepo shares one container; every case owns its user.
func TestUsageRepo(t *testing.T) {
	ctx := context.Background()
	pool := pgtest.NewTestPool(t)
	users, tokens := postgres.NewUserRepo(pool), postgres.NewTokenRepo(pool)

	// A session zone with a half-hour offset: buckets truncated in it rather than
	// in UTC would start at :30 and on the wrong day.
	cfg := pool.Config().Copy()
	cfg.ConnConfig.RuntimeParams["timezone"] = "Asia/Kolkata"
	kolkata, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(kolkata.Close)
	ledger := postgres.NewUsageRepo(kolkata)

	newOwner := func(t *testing.T) (identity.User, credentials.Token) {
		t.Helper()
		owner := identity.NewService(uuid.New(), "owner-"+uuid.NewString(), access.Policy{})
		if err := users.Create(ctx, owner); err != nil {
			t.Fatalf("create user: %v", err)
		}
		tok, _, err := credentials.Generate(owner.ID, "key")
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		if err := tokens.Create(ctx, tok); err != nil {
			t.Fatalf("create token: %v", err)
		}
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
			Cost: app.UsageCost{InputUSD: 0.5, OutputUSD: 1.25, CacheReadUSD: 0.125, CacheWriteUSD: 2,
				CacheSavingsUSD: -0.75, UnpricedTokens: 6, Priced: true},
		}
		if err := ledger.AppendBatch(ctx, []app.UsageEvent{want}); err != nil {
			t.Fatalf("AppendBatch: %v", err)
		}
		var got app.UsageEvent
		if err := pool.QueryRow(ctx, `SELECT at, user_id, token_id, provider, model, alias, stream, service_tier,
			tokens_input, tokens_output, tokens_reasoning, tokens_cache_read, tokens_cache_write, tokens_total,
			breakdown_quality, latency_ms, ttft_ms, status_code, failed, vendor_account_id,
			cost_input_usd, cost_output_usd, cost_cache_read_usd, cost_cache_write_usd, cache_savings_usd,
			unpriced_tokens, priced
			FROM usage_events WHERE user_id = $1`, owner.ID).Scan(
			&got.At, &got.UserID, &got.TokenID, &got.Provider, &got.Model, &got.Alias, &got.Stream, &got.ServiceTier,
			&got.TokensInput, &got.TokensOutput, &got.TokensReasoning, &got.TokensCacheRead, &got.TokensCacheWrite,
			&got.TokensTotal, &got.BreakdownQuality, &got.LatencyMS, &got.TTFTMS, &got.StatusCode, &got.Failed,
			&got.VendorAccountID, &got.Cost.InputUSD, &got.Cost.OutputUSD, &got.Cost.CacheReadUSD,
			&got.Cost.CacheWriteUSD, &got.Cost.CacheSavingsUSD, &got.Cost.UnpricedTokens, &got.Cost.Priced); err != nil {
			t.Fatalf("read back: %v", err)
		}
		got.At = got.At.UTC()
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("row = %+v\nwant  %+v", got, want)
		}
	})

	t.Run("AppendBatchStoresUnknownPrincipalsAsNull", func(t *testing.T) {
		// One row unattributed, one naming a user and token that do not exist (a
		// deleted owner), one valid: the batch must keep all three.
		owner, tok := newOwner(t)
		model := "null-" + uuid.NewString()
		at := time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)
		err := ledger.AppendBatch(ctx, []app.UsageEvent{
			{At: at, Provider: "claude", Model: model},
			{At: at, UserID: uuid.New(), TokenID: uuid.New(), Provider: "claude", Model: model},
			{At: at, UserID: owner.ID, TokenID: tok.ID, Provider: "claude", Model: model},
		})
		if err != nil {
			t.Fatalf("AppendBatch: %v", err)
		}
		var nulls, attributed int
		if err := pool.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE user_id IS NULL AND token_id IS NULL),
			count(*) FILTER (WHERE user_id = $2 AND token_id = $3)
			FROM usage_events WHERE model = $1`, model, owner.ID, tok.ID).Scan(&nulls, &attributed); err != nil {
			t.Fatalf("count: %v", err)
		}
		if nulls != 2 || attributed != 1 {
			t.Fatalf("rows: %d unattributed, %d attributed; want 2 and 1", nulls, attributed)
		}
	})

	t.Run("AppendBatchWritesAllOrNothing", func(t *testing.T) {
		// The second row carries a NUL, which Postgres refuses in text: the
		// first row, already sent in the same batch, must not be kept.
		owner, tok := newOwner(t)
		at := time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)
		err := ledger.AppendBatch(ctx, []app.UsageEvent{
			{At: at, UserID: owner.ID, TokenID: tok.ID, Provider: "claude", Model: "fine"},
			{At: at, UserID: owner.ID, TokenID: tok.ID, Provider: "claude", Model: "bad\x00model"},
		})
		if err == nil {
			t.Fatal("AppendBatch accepted a row Postgres refuses")
		}
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM usage_events WHERE user_id = $1`, owner.ID).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		if n != 0 {
			t.Fatalf("%d rows of the failed batch were kept, want none", n)
		}
	})

	t.Run("SeriesForUserBucketsHoursByModel", func(t *testing.T) {
		owner, tok := newOwner(t)
		other, otherTok := newOwner(t)
		from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		to := from.Add(24 * time.Hour)
		ev := func(user, token uuid.UUID, at time.Time, model string, tokens int64) app.UsageEvent {
			return app.UsageEvent{At: at, UserID: user, TokenID: token, Provider: "claude", Model: model, TokensTotal: tokens}
		}
		failed := func(e app.UsageEvent) app.UsageEvent { e.Failed, e.StatusCode = true, 429; return e }
		h := func(hour, minute int) time.Time {
			return from.Add(time.Duration(hour)*time.Hour + time.Duration(minute)*time.Minute)
		}
		if err := ledger.AppendBatch(ctx, []app.UsageEvent{
			ev(owner.ID, tok.ID, h(10, 15), "m1", 10),
			ev(owner.ID, tok.ID, h(10, 45), "m1", 5),
			// An attempt that failed after spending tokens, then retried on
			// another account (the 10:45 row): tokens count, the request does not.
			failed(ev(owner.ID, tok.ID, h(10, 44), "m1", 3)),
			ev(owner.ID, tok.ID, h(10, 30), "m2", 7),
			ev(owner.ID, tok.ID, h(11, 5), "m1", 0), // served, no tokens reported
			// Only failed attempts that spent nothing: no point at all.
			failed(ev(owner.ID, tok.ID, h(12, 10), "m2", 0)),
			ev(owner.ID, tok.ID, from, "m1", 1), // on from: in
			ev(owner.ID, tok.ID, to, "m1", 100), // on to: out
			ev(owner.ID, tok.ID, from.Add(-time.Second), "m1", 100),
			ev(other.ID, otherTok.ID, h(10, 20), "m1", 100),
		}); err != nil {
			t.Fatalf("AppendBatch: %v", err)
		}

		got, err := ledger.SeriesForUser(ctx, owner.ID, from, to)
		if err != nil {
			t.Fatalf("SeriesForUser: %v", err)
		}
		want := app.UsageSeries{
			Bucket: app.UsageBucketHour,
			Totals: app.UsageTotals{Requests: 5, TokensTotal: 26},
			Points: []app.UsagePoint{
				{At: from, Model: "m1", Requests: 1, TokensTotal: 1},
				{At: h(10, 0), Model: "m1", Requests: 2, TokensTotal: 18},
				{At: h(10, 0), Model: "m2", Requests: 1, TokensTotal: 7},
				{At: h(11, 0), Model: "m1", Requests: 1, TokensTotal: 0},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("series = %+v\nwant     %+v", got, want)
		}
	})

	// The series sums the cost each row stored; it prices nothing itself.
	t.Run("SeriesForUserSumsStoredCost", func(t *testing.T) {
		owner, tok := newOwner(t)
		from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		ev := func(minute int, model string, c app.UsageCost) app.UsageEvent {
			return app.UsageEvent{At: from.Add(10*time.Hour + time.Duration(minute)*time.Minute), UserID: owner.ID, TokenID: tok.ID,
				Provider: "claude", Model: model, TokensTotal: 100, Cost: c}
		}
		if err := ledger.AppendBatch(ctx, []app.UsageEvent{
			ev(1, "m1", app.UsageCost{InputUSD: 1, OutputUSD: 2, CacheReadUSD: 0.25, CacheWriteUSD: 0.5, CacheSavingsUSD: 1.5, Priced: true}),
			ev(2, "m1", app.UsageCost{InputUSD: 0.5, CacheWriteUSD: 4, CacheSavingsUSD: -2, UnpricedTokens: 10, Priced: true}),
			ev(3, "m2", app.UsageCost{UnpricedTokens: 100}),
		}); err != nil {
			t.Fatalf("AppendBatch: %v", err)
		}
		got, err := ledger.SeriesForUser(ctx, owner.ID, from, from.Add(24*time.Hour))
		if err != nil {
			t.Fatalf("SeriesForUser: %v", err)
		}
		if len(got.Points) != 2 || got.Points[0].CostUSD != 8.25 || got.Points[1].CostUSD != 0 {
			t.Fatalf("points = %+v, want m1 at $8.25 and m2 at $0", got.Points)
		}
		want := app.UsageCost{InputUSD: 1.5, OutputUSD: 2, CacheReadUSD: 0.25, CacheWriteUSD: 4.5,
			CacheSavingsUSD: -0.5, UnpricedTokens: 110, Priced: true}
		if got.Totals.Cost != want {
			t.Fatalf("totals cost = %+v\nwant          %+v", got.Totals.Cost, want)
		}
	})

	t.Run("SeriesForUserBucketsDaysBeyondTwoDays", func(t *testing.T) {
		owner, tok := newOwner(t)
		from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		to := from.Add(7 * 24 * time.Hour)
		day := func(d, hour int) time.Time { return from.AddDate(0, 0, d).Add(time.Duration(hour) * time.Hour) }
		if err := ledger.AppendBatch(ctx, []app.UsageEvent{
			// 20:00 UTC is already the next day in Kolkata.
			{At: day(0, 20), UserID: owner.ID, TokenID: tok.ID, Provider: "claude", Model: "m1", TokensTotal: 3},
			{At: day(0, 1), UserID: owner.ID, TokenID: tok.ID, Provider: "claude", Model: "m1", TokensTotal: 4},
			{At: day(2, 23), UserID: owner.ID, TokenID: tok.ID, Provider: "claude", Model: "m1", TokensTotal: 5},
		}); err != nil {
			t.Fatalf("AppendBatch: %v", err)
		}

		got, err := ledger.SeriesForUser(ctx, owner.ID, from, to)
		if err != nil {
			t.Fatalf("SeriesForUser: %v", err)
		}
		want := app.UsageSeries{
			Bucket: app.UsageBucketDay,
			Totals: app.UsageTotals{Requests: 3, TokensTotal: 12},
			Points: []app.UsagePoint{
				{At: day(0, 0), Model: "m1", Requests: 2, TokensTotal: 7},
				{At: day(2, 0), Model: "m1", Requests: 1, TokensTotal: 5},
			},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("series = %+v\nwant     %+v", got, want)
		}
	})

	t.Run("SeriesForUserWithNoUsageIsEmpty", func(t *testing.T) {
		owner, _ := newOwner(t)
		from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
		got, err := ledger.SeriesForUser(ctx, owner.ID, from, from.Add(48*time.Hour))
		if err != nil {
			t.Fatalf("SeriesForUser: %v", err)
		}
		if got.Bucket != app.UsageBucketHour || got.Totals != (app.UsageTotals{}) || len(got.Points) != 0 {
			t.Fatalf("series = %+v, want hour buckets and nothing in them", got)
		}
	})
}
