package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
)

const tokenColumns = `id, user_id, label, hash, prefix, created_at, last_used_at,
	revoked_at, revoked_by`

type TokenRepo struct{ pool *pgxpool.Pool }

var _ app.TokenRepo = (*TokenRepo)(nil)

func NewTokenRepo(pool *pgxpool.Pool) *TokenRepo { return &TokenRepo{pool: pool} }

// Create enforces app.MaxLiveTokensPerOwner. The owner's row is locked first, so
// creates for one owner run one at a time: under READ COMMITTED each statement sees
// what committed before it began, so the count that follows the lock includes every
// token a create that held the lock before this one wrote. An unknown owner is
// app.ErrNotFound.
func (r *TokenRepo) Create(ctx context.Context, t credentials.Token) error {
	return pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		var owner uuid.UUID
		err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id = $1 FOR NO KEY UPDATE`, t.UserID).Scan(&owner)
		if errors.Is(err, pgx.ErrNoRows) {
			return app.ErrNotFound
		}
		if err != nil {
			return err
		}
		var live int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM api_tokens WHERE user_id = $1 AND revoked_at IS NULL`, t.UserID).Scan(&live); err != nil {
			return err
		}
		if live >= app.MaxLiveTokensPerOwner {
			return app.ErrTokenLimit
		}
		_, err = tx.Exec(ctx,
			`INSERT INTO api_tokens (id, user_id, label, hash, prefix, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			t.ID, t.UserID, t.Label, t.Hash, t.Prefix, t.CreatedAt.UTC())
		return err
	})
}

// ByID loads a token the caller already knows the identity of — the revoke path,
// which must read the row to check ownership before it writes.
func (r *TokenRepo) ByID(ctx context.Context, id uuid.UUID) (credentials.Token, error) {
	return scanToken(r.pool.QueryRow(ctx,
		`SELECT `+tokenColumns+` FROM api_tokens WHERE id = $1`, id))
}

// ByHash resolves a presented secret's hash. The hash is the only lookup key for
// authentication: prefix is a seven-character display aid and collides freely once a
// deployment holds a few thousand tokens, so resolving by it would authenticate the
// wrong account.
func (r *TokenRepo) ByHash(ctx context.Context, hash string) (credentials.Token, error) {
	return scanToken(r.pool.QueryRow(ctx,
		`SELECT `+tokenColumns+` FROM api_tokens WHERE hash = $1`, hash))
}

// scanToken is the single reader of tokenColumns, so the projection and the scan
// cannot drift apart between the two lookups.
func scanToken(row pgx.Row) (credentials.Token, error) {
	var t credentials.Token
	err := row.Scan(&t.ID, &t.UserID, &t.Label, &t.Hash, &t.Prefix, &t.CreatedAt,
		&t.LastUsedAt, &t.RevokedAt, &t.RevokedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return credentials.Token{}, app.ErrNotFound
	}
	if err != nil {
		return credentials.Token{}, err
	}
	return t, nil
}

func (r *TokenRepo) ListByUser(ctx context.Context, userID uuid.UUID) ([]credentials.Token, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT `+tokenColumns+` FROM api_tokens WHERE user_id = $1 ORDER BY created_at DESC`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []credentials.Token
	for rows.Next() {
		var t credentials.Token
		if err := rows.Scan(&t.ID, &t.UserID, &t.Label, &t.Hash, &t.Prefix, &t.CreatedAt,
			&t.LastUsedAt, &t.RevokedAt, &t.RevokedBy); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Save persists the mutable half of a token: its label and its revocation. The hash,
// prefix and owner are fixed at creation and are deliberately not updatable.
func (r *TokenRepo) Save(ctx context.Context, t credentials.Token) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE api_tokens SET label = $2, revoked_at = $3, revoked_by = $4 WHERE id = $1`,
		t.ID, t.Label, t.RevokedAt, t.RevokedBy)
	if err != nil {
		return err
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
func (r *TokenRepo) TouchLastUsed(ctx context.Context, id uuid.UUID, at time.Time) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE api_tokens SET last_used_at = GREATEST(last_used_at, $2) WHERE id = $1`, id, at.UTC())
	return err
}
