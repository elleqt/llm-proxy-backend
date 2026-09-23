package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/elleqt/llm-proxy-backend/internal/app"
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
	tokens_total, breakdown_quality, latency_ms, ttft_ms, status_code, failed, vendor_account_id)
VALUES ($1, (SELECT id FROM users WHERE id = $2), (SELECT id FROM api_tokens WHERE id = $3),
	$4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)`

// AppendBatch writes events in one round trip and one implicit transaction: every
// event or none.
func (r *UsageRepo) AppendBatch(ctx context.Context, events []app.UsageEvent) error {
	if len(events) == 0 {
		return nil
	}
	b := &pgx.Batch{}
	for _, e := range events {
		b.Queue(appendUsage,
			e.At.UTC(), nullUUID(e.UserID), nullUUID(e.TokenID), e.Provider, e.Model, e.Alias,
			e.Stream, e.ServiceTier, e.TokensInput, e.TokensOutput, e.TokensReasoning,
			e.TokensCacheRead, e.TokensCacheWrite, e.TokensTotal, e.BreakdownQuality,
			e.LatencyMS, e.TTFTMS, e.StatusCode, e.Failed, e.VendorAccountID)
	}
	if err := r.pool.SendBatch(ctx, b).Close(); err != nil {
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
const seriesForUser = `SELECT date_trunc($4, at, 'UTC') AS bucket, model,
	count(*) FILTER (WHERE NOT failed) AS served, coalesce(sum(tokens_total), 0)::bigint AS tokens
FROM usage_events
WHERE user_id = $1 AND at >= $2 AND at < $3
GROUP BY bucket, model
HAVING count(*) FILTER (WHERE NOT failed) > 0 OR coalesce(sum(tokens_total), 0) > 0
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
		var p app.UsagePoint
		if err := rows.Scan(&p.At, &p.Model, &p.Requests, &p.TokensTotal); err != nil {
			return app.UsageSeries{}, fmt.Errorf("postgres: usage series: %w", err)
		}
		p.At = p.At.UTC()
		series.Points = append(series.Points, p)
		series.Totals.Requests += p.Requests
		series.Totals.TokensTotal += p.TokensTotal
	}
	if err := rows.Err(); err != nil {
		return app.UsageSeries{}, fmt.Errorf("postgres: usage series: %w", err)
	}
	return series, nil
}
