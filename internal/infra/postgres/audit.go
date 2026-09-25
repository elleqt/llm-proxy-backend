package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditSink appends to the audit log. Append-only by construction: this type offers
// no update and no delete, because the value of the log is that a row cannot be
// rewritten after the fact.
type AuditSink struct{ pool *pgxpool.Pool }

var _ app.AuditSink = (*AuditSink)(nil)

func NewAuditSink(pool *pgxpool.Pool) *AuditSink { return &AuditSink{pool: pool} }

func (s *AuditSink) Record(ctx context.Context, event app.AuditEvent) error {
	return insertAudit(ctx, s.pool, event)
}

// insertAudit is the one INSERT into audit_events. A change that must be recorded
// in the same transaction as itself writes its record through this with the
// transaction, rather than through the sink.
func insertAudit(ctx context.Context, db execer, event app.AuditEvent) error {
	detail, err := json.Marshal(event.Detail)
	if err != nil {
		return fmt.Errorf("postgres: audit detail: %w", err)
	}
	// A nil map marshals to "null"; the column is jsonb NOT NULL DEFAULT '{}', and a
	// JSON null would make every consumer of detail handle a second empty shape.
	if event.Detail == nil {
		detail = []byte(`{}`)
	}

	at := event.At
	if at.IsZero() {
		at = time.Now()
	}

	if _, err := db.Exec(ctx,
		`INSERT INTO audit_events (at, actor_user_id, action, target, detail, ip, user_agent)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		at.UTC(), nullUUID(event.ActorID), event.Action, event.Target, detail, event.IP, event.UserAgent); err != nil {
		return fmt.Errorf("postgres: insert audit event: %w", err)
	}

	return nil
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
