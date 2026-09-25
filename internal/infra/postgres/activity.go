package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ActivityRepo reads one account's recent history for the administration screens.
// It only reads: the usage ledger is written by the usage sink and the audit log by
// AuditSink, each through its own type.
type ActivityRepo struct{ pool *pgxpool.Pool }

var _ app.ActivityRepo = (*ActivityRepo)(nil)

func NewActivityRepo(pool *pgxpool.Pool) *ActivityRepo { return &ActivityRepo{pool: pool} }

// RecentUsage reads through usage_events_user_at_idx. The id breaks ties between
// requests recorded in the same microsecond, so a page is stable.
func (r *ActivityRepo) RecentUsage(ctx context.Context, userID uuid.UUID, limit int) ([]app.UsageEvent, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT at, user_id, token_id, provider, model, alias, stream, service_tier,
		        tokens_input, tokens_output, tokens_reasoning, tokens_cache_read,
		        tokens_cache_write, tokens_total, breakdown_quality, latency_ms, ttft_ms,
		        status_code, failed, vendor_account_id, cost_input_usd, cost_output_usd,
		        cost_cache_read_usd, cost_cache_write_usd, cache_savings_usd, unpriced_tokens, priced
		 FROM usage_events WHERE user_id = $1
		 ORDER BY at DESC, id DESC LIMIT $2`, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: recent usage: %w", err)
	}

	scanned, err := pgx.CollectRows(rows, pgx.RowToStructByName[usageEventRow])
	if err != nil {
		return nil, fmt.Errorf("postgres: recent usage: %w", err)
	}

	events := make([]app.UsageEvent, len(scanned))
	for i, row := range scanned {
		events[i] = row.event()
	}

	return events, nil
}

// usageEventRow is one usage_events row as RecentUsage selects it.
type usageEventRow struct {
	At                time.Time  `db:"at"`
	UserID            uuid.UUID  `db:"user_id"`
	TokenID           *uuid.UUID `db:"token_id"`
	Provider          string     `db:"provider"`
	Model             string     `db:"model"`
	Alias             string     `db:"alias"`
	Stream            bool       `db:"stream"`
	ServiceTier       string     `db:"service_tier"`
	TokensInput       int64      `db:"tokens_input"`
	TokensOutput      int64      `db:"tokens_output"`
	TokensReasoning   int64      `db:"tokens_reasoning"`
	TokensCacheRead   int64      `db:"tokens_cache_read"`
	TokensCacheWrite  int64      `db:"tokens_cache_write"`
	TokensTotal       int64      `db:"tokens_total"`
	BreakdownQuality  string     `db:"breakdown_quality"`
	LatencyMS         int        `db:"latency_ms"`
	TTFTMS            int        `db:"ttft_ms"`
	StatusCode        int        `db:"status_code"`
	Failed            bool       `db:"failed"`
	VendorAccountID   string     `db:"vendor_account_id"`
	CostInputUSD      float64    `db:"cost_input_usd"`
	CostOutputUSD     float64    `db:"cost_output_usd"`
	CostCacheReadUSD  float64    `db:"cost_cache_read_usd"`
	CostCacheWriteUSD float64    `db:"cost_cache_write_usd"`
	CacheSavingsUSD   float64    `db:"cache_savings_usd"`
	UnpricedTokens    int64      `db:"unpriced_tokens"`
	Priced            bool       `db:"priced"`
}

func (row usageEventRow) event() app.UsageEvent {
	event := app.UsageEvent{
		At:               row.At,
		UserID:           row.UserID,
		Provider:         row.Provider,
		Model:            row.Model,
		Alias:            row.Alias,
		Stream:           row.Stream,
		ServiceTier:      row.ServiceTier,
		TokensInput:      row.TokensInput,
		TokensOutput:     row.TokensOutput,
		TokensReasoning:  row.TokensReasoning,
		TokensCacheRead:  row.TokensCacheRead,
		TokensCacheWrite: row.TokensCacheWrite,
		TokensTotal:      row.TokensTotal,
		BreakdownQuality: row.BreakdownQuality,
		LatencyMS:        row.LatencyMS,
		TTFTMS:           row.TTFTMS,
		StatusCode:       row.StatusCode,
		Failed:           row.Failed,
		VendorAccountID:  row.VendorAccountID,
		Cost: app.UsageCost{
			InputUSD:        row.CostInputUSD,
			OutputUSD:       row.CostOutputUSD,
			CacheReadUSD:    row.CostCacheReadUSD,
			CacheWriteUSD:   row.CostCacheWriteUSD,
			CacheSavingsUSD: row.CacheSavingsUSD,
			UnpricedTokens:  row.UnpricedTokens,
			Priced:          row.Priced,
		},
	}
	// A token deleted since is NULL here; the event models "no token" as uuid.Nil.
	if row.TokenID != nil {
		event.TokenID = *row.TokenID
	}

	return event
}

// RecentAudit returns what userID did and what was done to it: rows it is the actor
// of, rows whose target is the account (sign-ins, password changes, administrator
// edits) and rows about its tokens, which name the owner in the detail.
func (r *ActivityRepo) RecentAudit(ctx context.Context, userID uuid.UUID, limit int) ([]app.AuditEvent, error) {
	// Two parameters rather than one cast two ways: a single $1 compared with a uuid
	// column and cast to text leaves its type to the planner's inference order.
	rows, err := r.pool.Query(ctx,
		`SELECT at, actor_user_id, action, target, detail, ip, user_agent
		 FROM audit_events
		 WHERE actor_user_id = $1 OR target = $2 OR detail->>'owner_id' = $2
		 ORDER BY at DESC, id DESC LIMIT $3`, userID, userID.String(), limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: recent audit: %w", err)
	}

	scanned, err := pgx.CollectRows(rows, pgx.RowToStructByName[auditEventRow])
	if err != nil {
		return nil, fmt.Errorf("postgres: recent audit: %w", err)
	}

	events := make([]app.AuditEvent, 0, len(scanned))

	for _, row := range scanned {
		event, err := row.event()
		if err != nil {
			return nil, err
		}

		events = append(events, event)
	}

	return events, nil
}

// auditEventRow is one audit_events row as RecentAudit selects it.
type auditEventRow struct {
	At        time.Time  `db:"at"`
	ActorID   *uuid.UUID `db:"actor_user_id"`
	Action    string     `db:"action"`
	Target    string     `db:"target"`
	Detail    []byte     `db:"detail"`
	IP        string     `db:"ip"`
	UserAgent string     `db:"user_agent"`
}

func (row auditEventRow) event() (app.AuditEvent, error) {
	event := app.AuditEvent{At: row.At, Action: row.Action, Target: row.Target, IP: row.IP, UserAgent: row.UserAgent}
	// A system action, or an actor deleted since, is NULL; the event models "no
	// actor" as uuid.Nil, as AuditSink.Record does on the way in.
	if row.ActorID != nil {
		event.ActorID = *row.ActorID
	}

	if err := json.Unmarshal(row.Detail, &event.Detail); err != nil {
		return app.AuditEvent{}, fmt.Errorf("postgres: audit detail: %w", err)
	}

	return event, nil
}
