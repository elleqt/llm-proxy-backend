package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

// AuditSink appends to the audit log. Append-only by construction: this type offers
// no update and no delete, because the value of the log is that a row cannot be
// rewritten after the fact.
type AuditSink struct{ pool *pgxpool.Pool }

var _ app.AuditSink = (*AuditSink)(nil)

func NewAuditSink(pool *pgxpool.Pool) *AuditSink { return &AuditSink{pool: pool} }

func (s *AuditSink) Record(ctx context.Context, e app.AuditEvent) error {
	return insertAudit(ctx, s.pool, e)
}

// insertAudit is the one INSERT into audit_events. A change that must be recorded
// in the same transaction as itself writes its record through this with the
// transaction, rather than through the sink.
func insertAudit(ctx context.Context, q execer, e app.AuditEvent) error {
	detail, err := json.Marshal(e.Detail)
	if err != nil {
		return fmt.Errorf("postgres: audit detail: %w", err)
	}
	// A nil map marshals to "null"; the column is jsonb NOT NULL DEFAULT '{}', and a
	// JSON null would make every consumer of detail handle a second empty shape.
	if e.Detail == nil {
		detail = []byte(`{}`)
	}
	at := e.At
	if at.IsZero() {
		at = time.Now()
	}
	_, err = q.Exec(ctx,
		`INSERT INTO audit_events (at, actor_user_id, action, target, detail, ip, user_agent)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		at.UTC(), nullUUID(e.ActorID), e.Action, e.Target, detail, e.IP, e.UserAgent)
	return err
}

// nullUUID binds the zero UUID as SQL NULL. actor_user_id carries a foreign key to
// users, and actions the system takes on its own behalf — scheduled pruning, startup
// bootstrap — have no actor; binding uuid.Nil literally would fail the key and lose
// the record of exactly those events.
func nullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
