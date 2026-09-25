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

type IdentityRepo struct{ pool *pgxpool.Pool }

var _ app.IdentityRepo = (*IdentityRepo)(nil)

func NewIdentityRepo(pool *pgxpool.Pool) *IdentityRepo { return &IdentityRepo{pool: pool} }

// BySubject resolves an already-linked federated identity. Issuer and subject are
// matched exactly: both are opaque provider-issued strings, and normalising them
// would let two different subjects collapse onto one account.
func (r *IdentityRepo) BySubject(ctx context.Context, issuer, subject string) (uuid.UUID, error) {
	var id uuid.UUID

	err := r.pool.QueryRow(ctx,
		`SELECT user_id FROM user_identities WHERE issuer = $1 AND subject = $2`,
		issuer, subject).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, app.ErrNotFound
	}

	if err != nil {
		return uuid.Nil, fmt.Errorf("postgres: identity by subject: %w", err)
	}

	return id, nil
}

// Link binds a provider subject to a local account. A plain INSERT on purpose: the
// primary key is (issuer, subject), so a second link for the same subject is a
// conflict the caller must see rather than a silent reassignment of the identity to
// a different account.
//
// That conflict comes back as app.ErrConflict. The OIDC flow has to tell "this
// subject is already linked" from a transport failure, and it cannot reach for the
// driver's error type to do it.
func (r *IdentityRepo) Link(ctx context.Context, userID uuid.UUID, issuer, subject string) error {
	_, err := r.pool.Exec(ctx,
		`INSERT INTO user_identities (user_id, issuer, subject) VALUES ($1, $2, $3)`,
		userID, issuer, subject)

	return AsConflict(err)
}

// PendingByEmail finds the account an administrator pre-provisioned for an address
// that has not signed in yet. An expired invitation is not returned: an unbounded
// pending row would let anyone who later controls the address claim the account.
// Email matching is case-insensitive because an address is one mailbox regardless of
// how the provider capitalises it.
func (r *IdentityRepo) PendingByEmail(ctx context.Context, issuer, email string) (uuid.UUID, error) {
	var id uuid.UUID

	err := r.pool.QueryRow(ctx,
		`SELECT user_id FROM pending_identities
		 WHERE issuer = $1 AND lower(expected_email) = lower($2) AND expires_at > now()`,
		issuer, email).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, app.ErrNotFound
	}

	if err != nil {
		return uuid.Nil, fmt.Errorf("postgres: pending identity by email: %w", err)
	}

	return id, nil
}

// ConsumePending removes the invitation once it has been redeemed. Deleting a row
// that is already gone is not an error: the call is the tail of a link operation that
// may legitimately be retried.
func (r *IdentityRepo) ConsumePending(ctx context.Context, userID uuid.UUID) error {
	if _, err := r.pool.Exec(ctx, `DELETE FROM pending_identities WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("postgres: consume pending identity: %w", err)
	}

	return nil
}

// Invite writes an invitation in its own transaction; see WriteInvitation.
func (r *IdentityRepo) Invite(ctx context.Context, userID uuid.UUID, inv app.Invitation) error {
	if err := pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error { return WriteInvitation(ctx, tx, userID, inv) }); err != nil {
		return fmt.Errorf("postgres: invite: %w", err)
	}

	return nil
}

// WriteInvitation writes an invitation, replacing whatever stood in its way:
//
//   - any invitation for the same address at the same issuer, expired or not and
//     whoever it was for. pending_identities_issuer_email_lower_key allows one per
//     (issuer, lower(email)), and an old one is stale by definition: the address now
//     belongs to the account being invited;
//   - any invitation userID already holds (user_id is the primary key).
//
// An account that already has an identity link gets none: the insert admits the row
// only while no link exists, and app.ErrAlreadyLinked rolls the deletes back with
// it. A live invitation beside a working link would be redeemable a second time, by
// a second subject.
//
// The issuer is stored exactly as given. PendingByEmail matches it byte for byte, so
// a normalised copy — a trailing slash added or dropped — would be an invitation no
// sign-in can ever redeem. Two invitations for one address racing each other: the
// loser's insert violates the unique index and comes back as app.ErrConflict.
func WriteInvitation(ctx context.Context, tx pgx.Tx, userID uuid.UUID, inv app.Invitation) error {
	if _, err := tx.Exec(ctx,
		`DELETE FROM pending_identities
		 WHERE user_id = $1 OR (issuer = $2 AND lower(expected_email) = lower($3))`,
		userID, inv.Issuer, inv.Email); err != nil {
		return fmt.Errorf("postgres: delete stale invitations: %w", err)
	}

	tag, err := tx.Exec(ctx,
		`INSERT INTO pending_identities (user_id, issuer, expected_email, expires_at)
		 SELECT $1::uuid, $2::text, $3::text, $4::timestamptz
		 WHERE NOT EXISTS (SELECT 1 FROM user_identities WHERE user_id = $1)`,
		userID, inv.Issuer, inv.Email, inv.ExpiresAt.UTC())
	if err != nil {
		return AsConflict(err)
	}

	if tag.RowsAffected() == 0 {
		return app.ErrAlreadyLinked
	}

	return nil
}
