package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

type LoginAttemptRepo struct{ pool *pgxpool.Pool }

var _ app.LoginAttemptRepo = (*LoginAttemptRepo)(nil)

func NewLoginAttemptRepo(pool *pgxpool.Pool) *LoginAttemptRepo {
	return &LoginAttemptRepo{pool: pool}
}

// Failures reports the consecutive failure count and the lockout expiry, if any.
//
// An address with no row has never failed, which is a fact and not a lookup failure:
// it returns (0, nil, nil) rather than app.ErrNotFound, so the throttle does not have
// to special-case the first attempt of every sign-in.
//
// The address is lower-cased on both read and write so that varying the capitalisation
// of an email cannot be used to reset the counter.
func (r *LoginAttemptRepo) Failures(ctx context.Context, email string) (int, *time.Time, error) {
	var (
		count       int
		lockedUntil *time.Time
	)
	err := r.pool.QueryRow(ctx,
		`SELECT failures, locked_until FROM login_attempts WHERE email = lower($1)`, email).
		Scan(&count, &lockedUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, nil
	}
	if err != nil {
		return 0, nil, err
	}
	return count, lockedUntil, nil
}

// Charge is one statement, so the row lock ON CONFLICT takes is what serialises
// concurrent attempts against one address: each sees the count its own increment
// produced, and a burst cannot slip past the limit between a read and a write.
//
// Every SET expression reads the row as it was before this statement, which is what
// lets the cases of the port contract be decided on the old row. The lock window's
// length is lockUntil - now, so "the last attempt is older than one window" needs no
// extra parameter.
func (r *LoginAttemptRepo) Charge(ctx context.Context, email string, maxFailures int, now, lockUntil time.Time) (int, *time.Time, error) {
	var (
		count       int
		lockedUntil *time.Time
	)
	err := r.pool.QueryRow(ctx,
		`INSERT INTO login_attempts AS a (email, failures, locked_until, last_failure_at)
		 VALUES (lower($1), 1, CASE WHEN $2::integer <= 1 THEN $4::timestamptz END, $3::timestamptz)
		 ON CONFLICT (email) DO UPDATE SET
		   failures = CASE
		     WHEN a.locked_until > $3::timestamptz THEN a.failures + 1
		     WHEN a.locked_until <= $3::timestamptz
		       OR a.last_failure_at <= $3::timestamptz - ($4::timestamptz - $3::timestamptz) THEN 1
		     ELSE a.failures + 1
		   END,
		   locked_until = CASE
		     WHEN a.locked_until > $3::timestamptz THEN a.locked_until
		     WHEN a.locked_until <= $3::timestamptz
		       OR a.last_failure_at <= $3::timestamptz - ($4::timestamptz - $3::timestamptz)
		       THEN CASE WHEN $2::integer <= 1 THEN $4::timestamptz END
		     WHEN a.failures + 1 >= $2::integer THEN $4::timestamptz
		   END,
		   last_failure_at = $3::timestamptz
		 RETURNING failures, locked_until`,
		email, maxFailures, now, lockUntil).
		Scan(&count, &lockedUntil)
	if err != nil {
		return 0, nil, err
	}
	return count, lockedUntil, nil
}

// Clear forgets an address after a successful sign-in, dropping both the count and any
// lockout.
func (r *LoginAttemptRepo) Clear(ctx context.Context, email string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM login_attempts WHERE email = lower($1)`, email)
	return err
}
