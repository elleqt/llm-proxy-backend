// Package audit appends to the audit log (app.AuditSink).
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sink appends to the audit log. Append-only by construction: this type offers
// no update and no delete, because the value of the log is that a row cannot be
// rewritten after the fact.
type Sink struct{ pool *pgxpool.Pool }

var _ app.AuditSink = (*Sink)(nil)

func New(pool *pgxpool.Pool) *Sink { return &Sink{pool: pool} }

func (s *Sink) Record(ctx context.Context, event app.AuditEvent) error {
	return Insert(ctx, s.pool, event)
}

// Insert is the one INSERT into audit_events. A change that must be recorded
// in the same transaction as itself writes its record through this with the
// transaction, rather than through the sink.
func Insert(ctx context.Context, db postgres.Execer, event app.AuditEvent) error {
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
		at.UTC(), postgres.NullUUID(event.ActorID), event.Action, event.Target, detail, event.IP, event.UserAgent); err != nil {
		return fmt.Errorf("postgres: insert audit event: %w", err)
	}

	return nil
}
