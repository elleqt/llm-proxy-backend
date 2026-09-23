package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

// userColumns is the one place the projection is written. Scanning is shared by
// ByID and ByEmail, so a column added here and forgotten in scanUser is a compile
// error rather than a silently short row.
const userColumns = `id, kind, email, display_name, role, status, policy,
	policy_managed_by, must_change_password, last_seen_at, created_at`

type UserRepo struct{ pool *pgxpool.Pool }

var _ app.UserRepo = (*UserRepo)(nil)

func NewUserRepo(pool *pgxpool.Pool) *UserRepo { return &UserRepo{pool: pool} }

func (r *UserRepo) Create(ctx context.Context, u identity.User) error {
	return insertUser(ctx, r.pool, u)
}

// execer is what a single statement needs: the pool, or a transaction when the
// statement is one of several that must commit together.
type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func insertUser(ctx context.Context, q execer, u identity.User) error {
	policy, err := encodePolicy(u.Policy)
	if err != nil {
		return err
	}
	// created_at is NOT NULL DEFAULT now(). Binding a zero CreatedAt literally would
	// store year 1 for any caller that forgot to set it; binding NULL lets the column
	// default apply, which is the value such a caller meant.
	var createdAt *time.Time
	if !u.CreatedAt.IsZero() {
		utc := u.CreatedAt.UTC()
		createdAt = &utc
	}
	_, err = q.Exec(ctx,
		`INSERT INTO users (id, kind, email, display_name, role, status, policy,
		                    policy_managed_by, must_change_password, last_seen_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, COALESCE($11, now()))`,
		u.ID, string(u.Kind), nullString(u.Email), u.DisplayName, string(u.Role),
		string(u.Status), policy, string(u.PolicySource), u.MustChangePassword,
		u.LastSeenAt, createdAt)
	// A duplicate email — including one differing only in case, which the
	// users_email_lower_key index catches — is a conflict the caller must be able to
	// recognise, not an opaque driver failure.
	return asConflict(err)
}

// CreateAccount commits the user, its first credential and the audit record of its
// creation in one transaction. A failure at any step rolls back every earlier one,
// so a retry of the same request finds nothing in its way: no half-made account
// holding the address, and no account the audit log does not know about.
func (r *UserRepo) CreateAccount(ctx context.Context, a app.NewAccount) error {
	return pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		if err := insertUser(ctx, tx, a.User); err != nil {
			return err
		}
		if a.Password != nil {
			if err := setPassword(ctx, tx, a.User.ID, a.Password.Hash, a.Password.ExpiresAt); err != nil {
				return err
			}
		}
		if a.Invitation != nil {
			if err := invite(ctx, tx, a.User.ID, *a.Invitation); err != nil {
				return err
			}
		}
		return insertAudit(ctx, tx, a.Audit)
	})
}

func (r *UserRepo) ByID(ctx context.Context, id uuid.UUID) (identity.User, error) {
	return scanUser(r.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id))
}

// ByEmail matches case-insensitively: an address differing only in case is the same
// mailbox, and a sign-in form that capitalises the first letter must not create or
// miss an account.
func (r *UserRepo) ByEmail(ctx context.Context, email string) (identity.User, error) {
	return scanUser(r.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE lower(email) = lower($1)`, email))
}

// AdminExists counts a blocked administrator too: blocking the only one is an
// operator's decision, and a restart must not answer it by minting a fresh one.
func (r *UserRepo) AdminExists(ctx context.Context) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM users WHERE role = $1)`, string(identity.RoleAdmin)).
		Scan(&exists)
	return exists, err
}

// UpdatePolicy reports app.ErrNotFound when no such user exists. An administrator
// editing a policy must learn that the edit landed nowhere; a silent no-op here
// would read as success in the admin UI.
func (r *UserRepo) UpdatePolicy(ctx context.Context, id uuid.UUID, p access.Policy) error {
	policy, err := encodePolicy(p)
	if err != nil {
		return err
	}
	tag, err := r.pool.Exec(ctx, `UPDATE users SET policy = $2 WHERE id = $1`, id, policy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return app.ErrNotFound
	}
	return nil
}

// TouchLastSeen is a best-effort liveness stamp on the request path: a user deleted
// between authentication and this call is not an error worth failing a request over,
// so a zero row count is accepted. The stamp never moves backwards: stamps can
// arrive out of order, and GREATEST ignores a NULL.
func (r *UserRepo) TouchLastSeen(ctx context.Context, id uuid.UUID, at time.Time) error {
	_, err := r.pool.Exec(ctx, `UPDATE users SET last_seen_at = GREATEST(last_seen_at, $2) WHERE id = $1`, id, at.UTC())
	return err
}

// SetMustChangePassword writes that column and nothing else.
//
// It is its own statement rather than a field of SaveIdentityState because the two
// have different owners: this one is set when an administrator issues a temporary
// password and cleared when the user changes it, and it must survive every federated
// login in between. An unknown user is app.ErrNotFound — a restriction that was never
// applied, or never lifted, cannot be allowed to read as success.
func (r *UserRepo) SetMustChangePassword(ctx context.Context, id uuid.UUID, must bool) error {
	tag, err := r.pool.Exec(ctx, `UPDATE users SET must_change_password = $2 WHERE id = $1`, id, must)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return app.ErrNotFound
	}
	return nil
}

// SaveIdentityState writes back exactly the fields an IdP login owns: the recomputed
// policy, its source, and the display name and email the provider asserts.
//
// Role, status and must_change_password are deliberately absent. They are
// administrator decisions — an operator who blocks or promotes a federated user must
// not have that undone by the user's next login.
func (r *UserRepo) SaveIdentityState(ctx context.Context, u identity.User) error {
	policy, err := encodePolicy(u.Policy)
	if err != nil {
		return err
	}
	tag, err := r.pool.Exec(ctx,
		`UPDATE users
		 SET policy = $2, policy_managed_by = $3, email = $4, display_name = $5
		 WHERE id = $1`,
		u.ID, policy, string(u.PolicySource), nullString(u.Email), u.DisplayName)
	// The fourth 23505-capable boundary, and the one on the hot login path: an IdP
	// that reasserts an address a local account already holds is a conflict the
	// federated-login flow has to recognise, not an opaque driver error.
	if err != nil {
		return asConflict(err)
	}
	if tag.RowsAffected() == 0 {
		return app.ErrNotFound
	}
	return nil
}

// UpdateAdminState writes the administrator-owned columns ch sets, each through
// COALESCE, so a column the edit does not name keeps whatever is stored now rather
// than a copy the caller read earlier. Two concurrent edits of different fields both
// land. Email and must_change_password are not writable here at all: the first is
// the sign-in address, the second has its own writer.
//
// The IdP lock is part of the statement: with RefuseIdPPolicy a policy change
// matches no row while the stored policy is idp-managed, so a login that made it
// idp-managed a moment ago cannot be overwritten by an edit checked against an older
// read.
func (r *UserRepo) UpdateAdminState(ctx context.Context, id uuid.UUID, ch app.AdminChange) error {
	var policy []byte
	if ch.Policy != nil {
		var err error
		if policy, err = encodePolicy(*ch.Policy); err != nil {
			return err
		}
	}
	tag, err := r.pool.Exec(ctx,
		`UPDATE users SET
		   display_name      = COALESCE($2, display_name),
		   role              = COALESCE($3, role),
		   status            = COALESCE($4, status),
		   policy            = COALESCE($5::jsonb, policy),
		   policy_managed_by = CASE WHEN $5::jsonb IS NULL THEN policy_managed_by ELSE 'local' END
		 WHERE id = $1
		   AND NOT ($6 AND $5::jsonb IS NOT NULL AND policy_managed_by = 'idp')`,
		id, ch.DisplayName, (*string)(ch.Role), (*string)(ch.Status), policy, ch.RefuseIdPPolicy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	var exists bool
	if err := r.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)`, id).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return app.ErrPolicyManagedByIDP
	}
	return app.ErrNotFound
}

// userViewQuery is the user projection plus what the administration screens show
// about sign-in, computed in one place so List and View report it identically.
//
// Only a way in that works counts: a temporary password past its expiry admits
// nobody, and neither does an invitation until it is claimed. Listing either as a
// sign-in method would hide that the person has no way in at all.
const userViewQuery = `SELECT ` + userColumns + `, has_password, has_link, invitation_expires_at FROM (
	SELECT u.*,
	       EXISTS (SELECT 1 FROM user_passwords p
	               WHERE p.user_id = u.id AND (p.expires_at IS NULL OR p.expires_at > now())) AS has_password,
	       EXISTS (SELECT 1 FROM user_identities i WHERE i.user_id = u.id) AS has_link,
	       (SELECT pi.expires_at FROM pending_identities pi WHERE pi.user_id = u.id) AS invitation_expires_at
	FROM users u) v `

// List returns every account, oldest first. The id breaks ties between accounts
// created in the same microsecond, so the order is stable.
func (r *UserRepo) List(ctx context.Context) ([]app.UserView, error) {
	rows, err := r.pool.Query(ctx, userViewQuery+`ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	views, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (app.UserView, error) { return scanView(row) })
	if views == nil {
		views = []app.UserView{}
	}
	return views, err
}

func (r *UserRepo) View(ctx context.Context, id uuid.UUID) (app.UserView, error) {
	return scanView(r.pool.QueryRow(ctx, userViewQuery+`WHERE id = $1`, id))
}

func scanView(row pgx.Row) (app.UserView, error) {
	var (
		hasPassword, hasLink bool
		invitation           *time.Time
	)
	u, err := scanUser(row, &hasPassword, &hasLink, &invitation)
	if err != nil {
		return app.UserView{}, err
	}
	v := app.UserView{User: u, SignIn: []app.SignInMethod{}}
	if hasPassword {
		v.SignIn = append(v.SignIn, app.SignInPassword)
	}
	if hasLink {
		v.SignIn = append(v.SignIn, app.SignInOIDC)
	} else {
		// A linked account has nothing left to claim: an invitation row beside a
		// link is not something the administrator can act on.
		v.InvitationExpiresAt = invitation
	}
	return v, nil
}

// scanUser reads userColumns, followed by whatever extra columns the query selects
// after them.
func scanUser(row pgx.Row, extra ...any) (identity.User, error) {
	var (
		u      identity.User
		kind   string
		email  *string
		role   string
		status string
		policy []byte
		source string
	)
	dest := append([]any{&u.ID, &kind, &email, &u.DisplayName, &role, &status, &policy,
		&source, &u.MustChangePassword, &u.LastSeenAt, &u.CreatedAt}, extra...)
	err := row.Scan(dest...)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.User{}, app.ErrNotFound
	}
	if err != nil {
		return identity.User{}, err
	}
	u.Kind, u.Role, u.Status = identity.Kind(kind), identity.Role(role), identity.Status(status)
	u.PolicySource = identity.PolicySource(source)
	// A service account stores NULL; the domain models "no email" as the empty string.
	if email != nil {
		u.Email = *email
	}
	if u.Policy, err = decodePolicy(policy); err != nil {
		return identity.User{}, err
	}
	return u, nil
}

// nullString binds an empty string as SQL NULL.
//
// users.email is nullable and uniqueness is enforced by users_email_lower_key, a
// unique index over lower(email); identity.NewService leaves Email empty. Postgres
// allows any number of NULLs in a unique index but only one empty string, so
// persisting the zero value would let exactly one service account exist and fail
// every one after it on a column the caller never set.
func nullString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// encodePolicy renders a policy as the JSON array of rule strings the column holds.
// A nil policy becomes "[]", never "null", so the stored shape does not depend on
// whether the caller built an empty slice or left it nil.
func encodePolicy(p access.Policy) ([]byte, error) {
	rules := make([]string, 0, len(p))
	for _, r := range p {
		rules = append(rules, r.String())
	}
	out, err := json.Marshal(rules)
	if err != nil {
		return nil, fmt.Errorf("postgres: encode policy: %w", err)
	}
	return out, nil
}

// decodePolicy parses every stored rule through access.ParseRule.
//
// Two reasons it must not shortcut to a literal access.Rule: only ParseRule fills the
// compiled-pattern cache that the per-request authorisation check depends on, and a
// rule that fails to parse is a loss of access the operator granted. Dropping the bad
// element would quietly narrow the allow-list, so the whole read fails instead.
func decodePolicy(raw []byte) (access.Policy, error) {
	var rules []string
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, fmt.Errorf("postgres: decode policy: %w", err)
	}
	if len(rules) == 0 {
		return nil, nil
	}
	p := make(access.Policy, 0, len(rules))
	for _, s := range rules {
		rule, err := access.ParseRule(s)
		if err != nil {
			return nil, fmt.Errorf("postgres: decode policy: %w", err)
		}
		p = append(p, rule)
	}
	return p, nil
}
