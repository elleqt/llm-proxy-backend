package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UsageRepo is the consumption ledger.
type UsageRepo struct{ pool *pgxpool.Pool }

var _ app.UsageRepo = (*UsageRepo)(nil)

func NewUsageRepo(pool *pgxpool.Pool) *UsageRepo { return &UsageRepo{pool: pool} }

// appendUsage keeps an event whose owner or token no longer exists: user_id and
// token_id are foreign keys, and a request that raced its owner's deletion would
// otherwise fail its whole batch. The sub-selects bind NULL for an id that names no
// row, which is also how an unattributed event (uuid.Nil) is stored.
const appendUsage = `INSERT INTO usage_events (
	at, user_id, token_id, provider, model, alias, stream, service_tier,
	tokens_input, tokens_output, tokens_reasoning, tokens_cache_read, tokens_cache_write,
	tokens_total, breakdown_quality, latency_ms, ttft_ms, status_code, failed, vendor_account_id,
	cost_input_usd, cost_output_usd, cost_cache_read_usd, cost_cache_write_usd, cache_savings_usd,
	unpriced_tokens, priced)
VALUES ($1, (SELECT id FROM users WHERE id = $2), (SELECT id FROM api_tokens WHERE id = $3),
	$4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
	$21, $22, $23, $24, $25, $26, $27)`

// AppendBatch writes events in one round trip and one implicit transaction: every
// event or none.
func (r *UsageRepo) AppendBatch(ctx context.Context, events []app.UsageEvent) error {
	if len(events) == 0 {
		return nil
	}

	batch := &pgx.Batch{}
	for _, event := range events {
		batch.Queue(appendUsage,
			event.At.UTC(), NullUUID(event.UserID), NullUUID(event.TokenID), event.Provider, event.Model, event.Alias,
			event.Stream, event.ServiceTier, event.TokensInput, event.TokensOutput, event.TokensReasoning,
			event.TokensCacheRead, event.TokensCacheWrite, event.TokensTotal, event.BreakdownQuality,
			event.LatencyMS, event.TTFTMS, event.StatusCode, event.Failed, event.VendorAccountID,
			event.Cost.InputUSD, event.Cost.OutputUSD, event.Cost.CacheReadUSD, event.Cost.CacheWriteUSD,
			event.Cost.CacheSavingsUSD, event.Cost.UnpricedTokens, event.Cost.Priced)
	}

	if err := r.pool.SendBatch(ctx, batch).Close(); err != nil {
		return fmt.Errorf("postgres: append %d usage events: %w", len(events), err)
	}

	return nil
}

// seriesForUser buckets on UTC boundaries whatever the session time zone is: the
// two-argument date_trunc on a timestamptz truncates in the session's zone.
//
// requests counts served requests only. Upstream records one row per attempt, so
// a request retried on another account after a 429 leaves a failed row next to
// the served one; tokens still sum over every row, since they were spent. A
// bucket and model holding only failed attempts that spent nothing has no point.
//
// Cost sums what each row stored when it was recorded: nothing is priced here.
const seriesForUser = `SELECT date_trunc($4, at, 'UTC') AS bucket, model,
	count(*) FILTER (WHERE NOT failed) AS served, coalesce(sum(tokens_total), 0)::bigint AS tokens,
	sum(cost_input_usd), sum(cost_output_usd), sum(cost_cache_read_usd), sum(cost_cache_write_usd),
	sum(cache_savings_usd), sum(unpriced_tokens)::bigint, bool_or(priced)
FROM usage_events
WHERE user_id = $1 AND at >= $2 AND at < $3
GROUP BY bucket, model
HAVING count(*) FILTER (WHERE NOT failed) > 0 OR sum(tokens_total) > 0 OR sum(unpriced_tokens) > 0 OR bool_or(priced)
ORDER BY bucket, model`

// SeriesForUser aggregates userID's events in [from, to) per bucket and model; the
// bucket width is app.UsageBucketFor(from, to). Totals cover the same points.
func (r *UsageRepo) SeriesForUser(ctx context.Context, userID uuid.UUID, from, to time.Time) (app.UsageSeries, error) {
	series := app.UsageSeries{Bucket: app.UsageBucketFor(from, to)}

	rows, err := r.pool.Query(ctx, seriesForUser, userID, from.UTC(), to.UTC(), string(series.Bucket))
	if err != nil {
		return app.UsageSeries{}, fmt.Errorf("postgres: usage series: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			point app.UsagePoint
			cost  app.UsageCost
		)
		if err := rows.Scan(&point.At, &point.Model, &point.Requests, &point.TokensTotal,
			&cost.InputUSD, &cost.OutputUSD, &cost.CacheReadUSD, &cost.CacheWriteUSD,
			&cost.CacheSavingsUSD, &cost.UnpricedTokens, &cost.Priced); err != nil {
			return app.UsageSeries{}, fmt.Errorf("postgres: usage series: %w", err)
		}

		point.At = point.At.UTC()
		point.CostUSD = cost.TotalUSD()
		series.Points = append(series.Points, point)
		series.Totals.Requests += point.Requests
		series.Totals.TokensTotal += point.TokensTotal
		series.Totals.Cost.Add(cost)
	}

	if err := rows.Err(); err != nil {
		return app.UsageSeries{}, fmt.Errorf("postgres: usage series: %w", err)
	}

	return series, nil
}
