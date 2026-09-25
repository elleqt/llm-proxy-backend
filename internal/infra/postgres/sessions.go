package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The sessions.id column holds the SHA-256 of the session id, never the id itself.
// The name is the schema's; what goes in it is decided here and in app.SignIn, which
// are the only two places that know both halves.
//
// There is no restriction column in this projection because there is none in the
// table: whether a session is restricted is read from the user at every request.
const sessionColumns = `id, user_id, ip, user_agent, created_at, expires_at`

type SessionRepo struct{ pool *pgxpool.Pool }

var _ app.SessionRepo = (*SessionRepo)(nil)

func NewSessionRepo(pool *pgxpool.Pool) *SessionRepo { return &SessionRepo{pool: pool} }

// Create writes the session. Session.ID — the plaintext — is not in the projection
// and could not be persisted by accident even if a caller left it set. Neither is
// Session.Restricted, which is derived and has no column to land in.
func (r *SessionRepo) Create(ctx context.Context, session app.Session) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO sessions (`+sessionColumns+`)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		session.IDHash, session.UserID, session.IP, session.UserAgent, session.CreatedAt, session.ExpiresAt)

	return asConflict(err)
}

// ByHash resolves a live session.
//
// The expiry is part of the predicate rather than something the caller checks after
// the fact, and it is compared against the database's now() rather than the
// application's. An expired session is therefore not a stale row that some process
// might decide is still fresh: to every reader it simply does not exist, and a server
// whose clock has drifted cannot resurrect it.
//
// The Restricted field of the result is always false. It is not this repository's to
// answer — the caller derives it from the user.
func (r *SessionRepo) ByHash(ctx context.Context, idHash string) (app.Session, error) {
	var session app.Session

	err := r.pool.QueryRow(ctx,
		`SELECT `+sessionColumns+`
		 FROM sessions WHERE id = $1 AND expires_at > now()`, idHash).
		Scan(&session.IDHash, &session.UserID, &session.IP, &session.UserAgent, &session.CreatedAt, &session.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return app.Session{}, app.ErrNotFound
	}

	if err != nil {
		return app.Session{}, fmt.Errorf("postgres: session by hash: %w", err)
	}

	return session, nil
}

// Delete ends a session. A session that is already gone is the state the caller
// wanted, so a zero row count is success: sign-out must not fail because the row
// expired a second earlier.
func (r *SessionRepo) Delete(ctx context.Context, idHash string) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, idHash); err != nil {
		return fmt.Errorf("postgres: delete session: %w", err)
	}

	return nil
}

// DeleteByUser ends every session userID holds. Blocking a user and resetting their
// password call it: the sessions table is the only place a cookie is still honoured,
// so a row left here would outlive the decision that should have ended it. A user
// with no session is the state the caller wanted, not an error.
func (r *SessionRepo) DeleteByUser(ctx context.Context, userID uuid.UUID) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("postgres: delete user sessions: %w", err)
	}

	return nil
}

// DeleteByUserExcept ends every session userID holds but the one keyed keepHash: a
// password change signs out everyone holding the account's cookies except the person
// who changed it.
func (r *SessionRepo) DeleteByUserExcept(ctx context.Context, userID uuid.UUID, keepHash string) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1 AND id <> $2`, userID, keepHash); err != nil {
		return fmt.Errorf("postgres: delete other user sessions: %w", err)
	}

	return nil
}
