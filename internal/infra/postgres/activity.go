package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/elleqt/llm-proxy-backend/internal/app"
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
		        status_code, failed, vendor_account_id
		 FROM usage_events WHERE user_id = $1
		 ORDER BY at DESC, id DESC LIMIT $2`, userID, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (app.UsageEvent, error) {
		var (
			e       app.UsageEvent
			tokenID *uuid.UUID
		)
		err := row.Scan(&e.At, &e.UserID, &tokenID, &e.Provider, &e.Model, &e.Alias, &e.Stream,
			&e.ServiceTier, &e.TokensInput, &e.TokensOutput, &e.TokensReasoning,
			&e.TokensCacheRead, &e.TokensCacheWrite, &e.TokensTotal, &e.BreakdownQuality,
			&e.LatencyMS, &e.TTFTMS, &e.StatusCode, &e.Failed, &e.VendorAccountID)
		// A token deleted since is NULL here; the event models "no token" as uuid.Nil.
		if tokenID != nil {
			e.TokenID = *tokenID
		}
		return e, err
	})
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
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (app.AuditEvent, error) {
		var (
			e      app.AuditEvent
			actor  *uuid.UUID
			detail []byte
		)
		if err := row.Scan(&e.At, &actor, &e.Action, &e.Target, &detail, &e.IP, &e.UserAgent); err != nil {
			return app.AuditEvent{}, err
		}
		// A system action, or an actor deleted since, is NULL; the event models "no
		// actor" as uuid.Nil, as AuditSink.Record does on the way in.
		if actor != nil {
			e.ActorID = *actor
		}
		if err := json.Unmarshal(detail, &e.Detail); err != nil {
			return app.AuditEvent{}, fmt.Errorf("postgres: audit detail: %w", err)
		}
		return e, nil
	})
}
