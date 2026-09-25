package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// Execer is what a single statement needs: the pool, or a transaction when the
// statement is one of several that must commit together.
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// NullString binds an empty string as SQL NULL.
//
// users.email is nullable and uniqueness is enforced by users_email_lower_key, a
// unique index over lower(email); identity.NewService leaves Email empty. Postgres
// allows any number of NULLs in a unique index but only one empty string, so
// persisting the zero value would let exactly one service account exist and fail
// every one after it on a column the caller never set.
func NullString(s string) *string {
	if s == "" {
		return nil
	}

	return &s
}

// NullUUID binds the zero UUID as SQL NULL. actor_user_id carries a foreign key to
// users, and actions the system takes on its own behalf — scheduled pruning, startup
// bootstrap — have no actor; binding uuid.Nil literally would fail the key and lose
// the record of exactly those events.
func NullUUID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}

	return &id
}
