// Package passwords stores password hashes, permanent or temporary (app.PasswordRepo).
package passwords

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Repo struct{ pool *pgxpool.Pool }

var _ app.PasswordRepo = (*Repo)(nil)

func New(pool *pgxpool.Pool) *Repo { return &Repo{pool: pool} }

// Set stores a password hash, replacing any previous one. It upserts because setting
// a password and changing it are the same operation from the caller's side, and a
// separate "has one already?" read would be a race between two admins.
//
// expiresAt is nil for a permanent password and non-nil for a temporary one.
func (r *Repo) Set(ctx context.Context, userID uuid.UUID, hash string, expiresAt *time.Time) error {
	return Upsert(ctx, r.pool, userID, hash, expiresAt)
}

func Upsert(ctx context.Context, q postgres.Execer, userID uuid.UUID, hash string, expiresAt *time.Time) error {
	if _, err := q.Exec(ctx,
		`INSERT INTO user_passwords (user_id, hash, expires_at, updated_at)
		 VALUES ($1, $2, $3, now())
		 ON CONFLICT (user_id) DO UPDATE
		   SET hash = EXCLUDED.hash, expires_at = EXCLUDED.expires_at, updated_at = now()`,
		userID, hash, expiresAt); err != nil {
		return fmt.Errorf("postgres: set password: %w", err)
	}

	return nil
}

// Get returns app.ErrNotFound when the user has no password at all — the normal state
// of a service account or an IdP-only person, and never the same thing as a wrong one.
func (r *Repo) Get(ctx context.Context, userID uuid.UUID) (string, *time.Time, error) {
	var (
		hash      string
		expiresAt *time.Time
	)

	err := r.pool.QueryRow(ctx,
		`SELECT hash, expires_at FROM user_passwords WHERE user_id = $1`, userID).
		Scan(&hash, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, app.ErrNotFound
	}

	if err != nil {
		return "", nil, fmt.Errorf("postgres: get password: %w", err)
	}

	return hash, expiresAt, nil
}
