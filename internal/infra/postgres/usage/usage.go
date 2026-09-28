// Package usage is the consumption ledger (app.UsageRepo).
package usage

import (
	"context"
	"fmt"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repo is the consumption ledger.
type Repo struct{ pool *pgxpool.Pool }

var _ app.UsageRepo = (*Repo)(nil)

func New(pool *pgxpool.Pool) *Repo { return &Repo{pool: pool} }

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

// lockWindows locks the owners' window rows before chargeWindows updates them.
// The UPDATE's join locks rows in whatever order its plan visits them; a
// concurrent limitwindows Open or Reset locking the same rows in another order
// could deadlock with it, and losing the charge would lose the whole ledger
// batch. Every statement that locks limit_windows rows takes them first by
// (user_id, window_minutes), so they queue instead. $1 is chargeWindows' $1.
const lockWindows = `SELECT 1 FROM limit_windows WHERE user_id = ANY($1::uuid[])
ORDER BY user_id, window_minutes FOR UPDATE`

// chargeWindows adds each owner's cost to every window row of that owner and
// names the owners that had one. $1 holds each owner once.
const chargeWindows = `UPDATE limit_windows w SET spent_usd = w.spent_usd + b.cost
FROM unnest($1::uuid[], $2::float8[]) AS b(user_id, cost)
WHERE w.user_id = b.user_id
RETURNING w.user_id`

// AppendBatch writes events in one round trip and one implicit transaction: every
// event or none. It also adds each attributed owner's summed cost
// (UsageCost.TotalUSD, failed attempts included: their tokens were spent) to every
// limit_windows row of that owner, in the same transaction, and returns the owners
// that had a row. A batch that fails writes neither.
func (r *Repo) AppendBatch(ctx context.Context, events []app.UsageEvent) (map[uuid.UUID]struct{}, error) {
	if len(events) == 0 {
		return map[uuid.UUID]struct{}{}, nil
	}

	batch := &pgx.Batch{}
	cost := map[uuid.UUID]float64{}

	for _, event := range events {
		batch.Queue(appendUsage,
			event.At.UTC(), postgres.NullUUID(event.UserID), postgres.NullUUID(event.TokenID), event.Provider, event.Model, event.Alias,
			event.Stream, event.ServiceTier, event.TokensInput, event.TokensOutput, event.TokensReasoning,
			event.TokensCacheRead, event.TokensCacheWrite, event.TokensTotal, event.BreakdownQuality,
			event.LatencyMS, event.TTFTMS, event.StatusCode, event.Failed, event.VendorAccountID,
			event.Cost.InputUSD, event.Cost.OutputUSD, event.Cost.CacheReadUSD, event.Cost.CacheWriteUSD,
			event.Cost.CacheSavingsUSD, event.Cost.UnpricedTokens, event.Cost.Priced)

		if event.UserID != uuid.Nil {
			cost[event.UserID] += event.Cost.TotalUSD()
		}
	}

	owners, sums := make([]uuid.UUID, 0, len(cost)), make([]float64, 0, len(cost))
	for id, sum := range cost {
		owners, sums = append(owners, id), append(sums, sum)
	}

	if len(owners) > 0 {
		batch.Queue(lockWindows, owners)
		batch.Queue(chargeWindows, owners, sums)
	}
	// One batch is one implicit transaction: a failing statement rolls back the
	// ledger rows and the charges together.
	results := r.pool.SendBatch(ctx, batch)

	limited, err := readBatch(results, len(events), len(owners) > 0)
	if closeErr := results.Close(); err == nil {
		err = closeErr
	}

	if err != nil {
		return nil, fmt.Errorf("postgres: append %d usage events: %w", len(events), err)
	}

	return limited, nil
}

// readBatch consumes the inserts' results, the window lock, then the charge's
// returned owners.
func readBatch(results pgx.BatchResults, inserts int, charged bool) (map[uuid.UUID]struct{}, error) {
	for range inserts {
		if _, err := results.Exec(); err != nil {
			return nil, fmt.Errorf("postgres: insert usage event: %w", err)
		}
	}

	limited := map[uuid.UUID]struct{}{}
	if !charged {
		return limited, nil
	}

	if _, err := results.Exec(); err != nil {
		return nil, fmt.Errorf("postgres: lock limit windows: %w", err)
	}

	rows, err := results.Query()
	if err != nil {
		return nil, fmt.Errorf("postgres: charge limit windows: %w", err)
	}

	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("postgres: read charged owners: %w", err)
	}

	for _, id := range ids {
		limited[id] = struct{}{}
	}

	return limited, nil
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
func (r *Repo) SeriesForUser(ctx context.Context, userID uuid.UUID, from, to time.Time) (app.UsageSeries, error) {
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
