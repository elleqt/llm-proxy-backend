// Package tokens stores API tokens, by the SHA-256 hash of their secret (app.TokenRepo).
package tokens

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// tokenColumns is the SELECT projection of api_tokens; it holds column names, not a
// credential.
//
//nolint:gosec // G101 false positive: a column list that merely mentions "hash".
const tokenColumns = `id, user_id, label, hash, prefix, created_at, last_used_at,
	revoked_at, revoked_by`

type Repo struct{ pool *pgxpool.Pool }

var _ app.TokenRepo = (*Repo)(nil)

func New(pool *pgxpool.Pool) *Repo { return &Repo{pool: pool} }

// Create enforces app.MaxLiveTokensPerOwner. The owner's row is locked first, so
// creates for one owner run one at a time: under READ COMMITTED each statement sees
// what committed before it began, so the count that follows the lock includes every
// token a create that held the lock before this one wrote. An unknown owner is
// app.ErrNotFound.
func (r *Repo) Create(ctx context.Context, token credentials.Token) error {
	err := pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		var owner uuid.UUID

		err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id = $1 FOR NO KEY UPDATE`, token.UserID).Scan(&owner)
		if errors.Is(err, pgx.ErrNoRows) {
			return app.ErrNotFound
		}

		if err != nil {
			return fmt.Errorf("postgres: lock token owner: %w", err)
		}

		var live int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM api_tokens WHERE user_id = $1 AND revoked_at IS NULL`, token.UserID).Scan(&live); err != nil {
			return fmt.Errorf("postgres: count live tokens: %w", err)
		}

		if live >= app.MaxLiveTokensPerOwner {
			return app.ErrTokenLimit
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO api_tokens (id, user_id, label, hash, prefix, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			token.ID, token.UserID, token.Label, token.Hash, token.Prefix, token.CreatedAt.UTC()); err != nil {
			return fmt.Errorf("postgres: insert token: %w", err)
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("postgres: create token: %w", err)
	}

	return nil
}

// ByID loads a token the caller already knows the identity of — the revoke path,
// which must read the row to check ownership before it writes.
func (r *Repo) ByID(ctx context.Context, id uuid.UUID) (credentials.Token, error) {
	return scanToken(r.pool.QueryRow(ctx,
		`SELECT `+tokenColumns+` FROM api_tokens WHERE id = $1`, id))
}

// ByHash resolves a presented secret's hash. The hash is the only lookup key for
// authentication: prefix is a seven-character display aid and collides freely once a
// deployment holds a few thousand tokens, so resolving by it would authenticate the
// wrong account.
func (r *Repo) ByHash(ctx context.Context, hash string) (credentials.Token, error) {
	return scanToken(r.pool.QueryRow(ctx,
		`SELECT `+tokenColumns+` FROM api_tokens WHERE hash = $1`, hash))
}

// scanToken is the single reader of tokenColumns, so the projection and the scan
// cannot drift apart between the two lookups.
func scanToken(row pgx.Row) (credentials.Token, error) {
	var token credentials.Token

	err := row.Scan(&token.ID, &token.UserID, &token.Label, &token.Hash, &token.Prefix, &token.CreatedAt,
		&token.LastUsedAt, &token.RevokedAt, &token.RevokedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return credentials.Token{}, app.ErrNotFound
	}

	if err != nil {
		return credentials.Token{}, fmt.Errorf("postgres: scan token: %w", err)
	}

	return token, nil
}

func (r *Repo) ListByUser(ctx context.Context, userID uuid.UUID) ([]credentials.Token, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+tokenColumns+` FROM api_tokens WHERE user_id = $1 ORDER BY created_at DESC`,
		userID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list tokens: %w", err)
	}
	defer rows.Close()

	var out []credentials.Token

	for rows.Next() {
		var token credentials.Token
		if err := rows.Scan(&token.ID, &token.UserID, &token.Label, &token.Hash, &token.Prefix, &token.CreatedAt,
			&token.LastUsedAt, &token.RevokedAt, &token.RevokedBy); err != nil {
			return nil, fmt.Errorf("postgres: scan token: %w", err)
		}

		out = append(out, token)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: list tokens: %w", err)
	}

	return out, nil
}

// Save persists the mutable half of a token: its label and its revocation. The hash,
// prefix and owner are fixed at creation and are deliberately not updatable.
func (r *Repo) Save(ctx context.Context, token credentials.Token) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE api_tokens SET label = $2, revoked_at = $3, revoked_by = $4 WHERE id = $1`,
		token.ID, token.Label, token.RevokedAt, token.RevokedBy)
	if err != nil {
		return fmt.Errorf("postgres: save token: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return app.ErrNotFound
	}

	return nil
}

// TouchLastUsed is a best-effort stamp written on the proxy hot path; a token deleted
// mid-request is not worth failing the request over, so a zero row count is accepted.
// The stamp never moves backwards: stamps can arrive out of order, and GREATEST
// ignores a NULL.
func (r *Repo) TouchLastUsed(ctx context.Context, id uuid.UUID, at time.Time) error {
	if _, err := r.pool.Exec(ctx,
		`UPDATE api_tokens SET last_used_at = GREATEST(last_used_at, $2) WHERE id = $1`, id, at.UTC()); err != nil {
		return fmt.Errorf("postgres: touch token last used: %w", err)
	}

	return nil
}
