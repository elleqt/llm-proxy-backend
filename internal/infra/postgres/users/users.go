// Package users stores accounts and the identity state they carry (app.UserRepo).
package users

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	pgaudit "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/audit"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/identities"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/passwords"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// userColumns is the one place the projection is written, and userRow mirrors it:
// ByID and ByEmail scan it in order (scanUser), List and View by column name. A
// column added here and not there fails every read rather than silently dropping a
// field.
const userColumns = `id, kind, email, display_name, role, status, policy,
	policy_managed_by, must_change_password, last_seen_at, created_at`

type Repo struct{ pool *pgxpool.Pool }

var _ app.UserRepo = (*Repo)(nil)

func New(pool *pgxpool.Pool) *Repo { return &Repo{pool: pool} }

func (r *Repo) Create(ctx context.Context, u identity.User) error {
	return insertUser(ctx, r.pool, u)
}

func insertUser(ctx context.Context, db postgres.Execer, user identity.User) error {
	policy, err := encodePolicy(user.Policy)
	if err != nil {
		return err
	}
	// created_at is NOT NULL DEFAULT now(). Binding a zero CreatedAt literally would
	// store year 1 for any caller that forgot to set it; binding NULL lets the column
	// default apply, which is the value such a caller meant.
	var createdAt *time.Time

	if !user.CreatedAt.IsZero() {
		utc := user.CreatedAt.UTC()
		createdAt = &utc
	}

	_, err = db.Exec(ctx,
		`INSERT INTO users (id, kind, email, display_name, role, status, policy,
		                    policy_managed_by, must_change_password, last_seen_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, COALESCE($11, now()))`,
		user.ID, string(user.Kind), postgres.NullString(user.Email), user.DisplayName, string(user.Role),
		string(user.Status), policy, string(user.PolicySource), user.MustChangePassword,
		user.LastSeenAt, createdAt)
	// A duplicate email — including one differing only in case, which the
	// users_email_lower_key index catches — is a conflict the caller must be able to
	// recognise, not an opaque driver failure.
	return postgres.AsConflict(err)
}

// CreateAccount commits the user, its first credential and the audit record of its
// creation in one transaction. A failure at any step rolls back every earlier one,
// so a retry of the same request finds nothing in its way: no half-made account
// holding the address, and no account the audit log does not know about.
func (r *Repo) CreateAccount(ctx context.Context, account app.NewAccount) error {
	if err := pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		if err := insertUser(ctx, tx, account.User); err != nil {
			return err
		}

		if account.Password != nil {
			if err := passwords.Upsert(ctx, tx, account.User.ID, account.Password.Hash, account.Password.ExpiresAt); err != nil {
				return err
			}
		}

		if account.Invitation != nil {
			if err := identities.WriteInvitation(ctx, tx, account.User.ID, *account.Invitation); err != nil {
				return err
			}
		}

		return pgaudit.Insert(ctx, tx, account.Audit)
	}); err != nil {
		return fmt.Errorf("postgres: create account: %w", err)
	}

	return nil
}

func (r *Repo) ByID(ctx context.Context, id uuid.UUID) (identity.User, error) {
	return scanUser(r.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id))
}

// ByEmail matches case-insensitively: an address differing only in case is the same
// mailbox, and a sign-in form that capitalises the first letter must not create or
// miss an account.
func (r *Repo) ByEmail(ctx context.Context, email string) (identity.User, error) {
	return scanUser(r.pool.QueryRow(ctx,
		`SELECT `+userColumns+` FROM users WHERE lower(email) = lower($1)`, email))
}

// AdminExists counts a blocked administrator too: blocking the only one is an
// operator's decision, and a restart must not answer it by minting a fresh one.
func (r *Repo) AdminExists(ctx context.Context) (bool, error) {
	var exists bool

	if err := r.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM users WHERE role = $1)`, string(identity.RoleAdmin)).
		Scan(&exists); err != nil {
		return false, fmt.Errorf("postgres: admin exists: %w", err)
	}

	return exists, nil
}

// UpdatePolicy reports app.ErrNotFound when no such user exists. An administrator
// editing a policy must learn that the edit landed nowhere; a silent no-op here
// would read as success in the admin UI.
func (r *Repo) UpdatePolicy(ctx context.Context, id uuid.UUID, p access.Policy) error {
	policy, err := encodePolicy(p)
	if err != nil {
		return err
	}

	tag, err := r.pool.Exec(ctx, `UPDATE users SET policy = $2 WHERE id = $1`, id, policy)
	if err != nil {
		return fmt.Errorf("postgres: update policy: %w", err)
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
func (r *Repo) TouchLastSeen(ctx context.Context, id uuid.UUID, at time.Time) error {
	if _, err := r.pool.Exec(ctx,
		`UPDATE users SET last_seen_at = GREATEST(last_seen_at, $2) WHERE id = $1`, id, at.UTC()); err != nil {
		return fmt.Errorf("postgres: touch last seen: %w", err)
	}

	return nil
}

// SetMustChangePassword writes that column and nothing else.
//
// It is its own statement rather than a field of SaveIdentityState because the two
// have different owners: this one is set when an administrator issues a temporary
// password and cleared when the user changes it, and it must survive every federated
// login in between. An unknown user is app.ErrNotFound — a restriction that was never
// applied, or never lifted, cannot be allowed to read as success.
func (r *Repo) SetMustChangePassword(ctx context.Context, id uuid.UUID, must bool) error {
	tag, err := r.pool.Exec(ctx, `UPDATE users SET must_change_password = $2 WHERE id = $1`, id, must)
	if err != nil {
		return fmt.Errorf("postgres: set must change password: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return app.ErrNotFound
	}

	return nil
}

// FillDisplayName names an account that has no name. The emptiness test is part of
// the statement, so a name an administrator sets concurrently is not replaced.
func (r *Repo) FillDisplayName(ctx context.Context, id uuid.UUID, name string) (bool, error) {
	tag, err := r.pool.Exec(ctx,
		`UPDATE users SET display_name = $2 WHERE id = $1 AND display_name = ''`, id, name)
	if err != nil {
		return false, fmt.Errorf("postgres: fill display name: %w", err)
	}

	if tag.RowsAffected() == 1 {
		return true, nil
	}

	var exists bool
	if err := r.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)`, id).Scan(&exists); err != nil {
		return false, fmt.Errorf("postgres: fill display name: %w", err)
	}

	if !exists {
		return false, app.ErrNotFound
	}

	return false, nil
}

// SaveIdentityState writes back exactly the fields an IdP login owns: the recomputed
// policy, its source, and the email the provider asserts. The display name is not
// among them: FillDisplayName sets it once, and an administrator owns it after.
//
// Role, status and must_change_password are deliberately absent. They are
// administrator decisions — an operator who blocks or promotes a federated user must
// not have that undone by the user's next login.
func (r *Repo) SaveIdentityState(ctx context.Context, user identity.User) error {
	policy, err := encodePolicy(user.Policy)
	if err != nil {
		return err
	}

	tag, err := r.pool.Exec(ctx,
		`UPDATE users
		 SET policy = $2, policy_managed_by = $3, email = $4
		 WHERE id = $1`,
		user.ID, policy, string(user.PolicySource), postgres.NullString(user.Email))
	// The fourth 23505-capable boundary, and the one on the hot login path: an IdP
	// that reasserts an address a local account already holds is a conflict the
	// federated-login flow has to recognise, not an opaque driver error.
	if err != nil {
		return postgres.AsConflict(err)
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
// The IdP lock is part of the statement: with RefuseIDPPolicy a policy change
// matches no row while the stored policy is idp-managed, so a login that made it
// idp-managed a moment ago cannot be overwritten by an edit checked against an older
// read.
func (r *Repo) UpdateAdminState(ctx context.Context, id uuid.UUID, ch app.AdminChange) error {
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
		id, ch.DisplayName, (*string)(ch.Role), (*string)(ch.Status), policy, ch.RefuseIDPPolicy)
	if err != nil {
		return fmt.Errorf("postgres: update admin state: %w", err)
	}

	if tag.RowsAffected() > 0 {
		return nil
	}

	var exists bool
	if err := r.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)`, id).Scan(&exists); err != nil {
		return fmt.Errorf("postgres: update admin state: %w", err)
	}

	if exists {
		return app.ErrPolicyManagedByIDP
	}

	return app.ErrNotFound
}

// Unblock writes the status and the audit record in one transaction, so no unblock
// ever stands without its record.
func (r *Repo) Unblock(ctx context.Context, id uuid.UUID, audit app.AuditEvent) error {
	if err := pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE users SET status = 'active' WHERE id = $1`, id)
		if err != nil {
			return fmt.Errorf("postgres: activate user: %w", err)
		}

		if tag.RowsAffected() == 0 {
			return app.ErrNotFound
		}

		return pgaudit.Insert(ctx, tx, audit)
	}); err != nil {
		return fmt.Errorf("postgres: unblock user: %w", err)
	}

	return nil
}

// userViewQuery is the user projection plus what the administration screens show
// about sign-in, computed in one place so List and View report it identically.
//
// Only a way in that works counts: a temporary password past its expiry admits
// nobody, and neither does an invitation until it is claimed. Listing either as a
// sign-in method would hide that the person has no way in at all.
//
//nolint:unqueryvet // The outer SELECT names every column; u.* only carries users through the subquery.
const userViewQuery = `SELECT ` + userColumns + `, has_password, has_link, invitation_expires_at FROM (
	SELECT u.*,
	       EXISTS (SELECT 1 FROM user_passwords p
	               WHERE p.user_id = u.id AND (p.expires_at IS NULL OR p.expires_at > now())) AS has_password,
	       EXISTS (SELECT 1 FROM user_identities i WHERE i.user_id = u.id) AS has_link,
	       (SELECT pi.expires_at FROM pending_identities pi WHERE pi.user_id = u.id) AS invitation_expires_at
	FROM users u) v `

// List returns every account, oldest first. The id breaks ties between accounts
// created in the same microsecond, so the order is stable.
func (r *Repo) List(ctx context.Context) ([]app.UserView, error) {
	rows, err := r.pool.Query(ctx, userViewQuery+`ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list users: %w", err)
	}

	scanned, err := pgx.CollectRows(rows, pgx.RowToStructByName[userViewRow])
	if err != nil {
		return nil, fmt.Errorf("postgres: list users: %w", err)
	}
	// Never nil: no accounts is an empty list, not an absent one.
	views := make([]app.UserView, 0, len(scanned))

	for _, row := range scanned {
		view, err := row.view()
		if err != nil {
			return nil, err
		}

		views = append(views, view)
	}

	return views, nil
}

func (r *Repo) View(ctx context.Context, id uuid.UUID) (app.UserView, error) {
	rows, err := r.pool.Query(ctx, userViewQuery+`WHERE id = $1`, id)
	if err != nil {
		return app.UserView{}, fmt.Errorf("postgres: view user: %w", err)
	}

	row, err := pgx.CollectExactlyOneRow(rows, pgx.RowToStructByName[userViewRow])
	if errors.Is(err, pgx.ErrNoRows) {
		return app.UserView{}, app.ErrNotFound
	}

	if err != nil {
		return app.UserView{}, fmt.Errorf("postgres: view user: %w", err)
	}

	return row.view()
}

// userRow is one users row as userColumns selects it.
type userRow struct {
	ID                 uuid.UUID  `db:"id"`
	Kind               string     `db:"kind"`
	Email              *string    `db:"email"`
	DisplayName        string     `db:"display_name"`
	Role               string     `db:"role"`
	Status             string     `db:"status"`
	Policy             []byte     `db:"policy"`
	PolicyManagedBy    string     `db:"policy_managed_by"`
	MustChangePassword bool       `db:"must_change_password"`
	LastSeenAt         *time.Time `db:"last_seen_at"`
	CreatedAt          time.Time  `db:"created_at"`
}

func (row userRow) user() (identity.User, error) {
	user := identity.User{
		ID:                 row.ID,
		Kind:               identity.Kind(row.Kind),
		DisplayName:        row.DisplayName,
		Role:               identity.Role(row.Role),
		Status:             identity.Status(row.Status),
		PolicySource:       identity.PolicySource(row.PolicyManagedBy),
		MustChangePassword: row.MustChangePassword,
		LastSeenAt:         row.LastSeenAt,
		CreatedAt:          row.CreatedAt,
	}
	// A service account stores NULL; the domain models "no email" as the empty string.
	if row.Email != nil {
		user.Email = *row.Email
	}

	policy, err := decodePolicy(row.Policy)
	if err != nil {
		return identity.User{}, err
	}

	user.Policy = policy

	return user, nil
}

// userViewRow is one row of userViewQuery: the user, then what the administration
// screens show about its sign-in.
type userViewRow struct {
	userRow

	HasPassword         bool       `db:"has_password"`
	HasLink             bool       `db:"has_link"`
	InvitationExpiresAt *time.Time `db:"invitation_expires_at"`
}

func (row userViewRow) view() (app.UserView, error) {
	user, err := row.user()
	if err != nil {
		return app.UserView{}, err
	}

	view := app.UserView{User: user, SignIn: []app.SignInMethod{}}
	if row.HasPassword {
		view.SignIn = append(view.SignIn, app.SignInPassword)
	}

	if row.HasLink {
		view.SignIn = append(view.SignIn, app.SignInOIDC)
	} else {
		// A linked account has nothing left to claim: an invitation row beside a
		// link is not something the administrator can act on.
		view.InvitationExpiresAt = row.InvitationExpiresAt
	}

	return view, nil
}

// scanUser reads one row of userColumns, in order.
func scanUser(row pgx.Row) (identity.User, error) {
	var scanned userRow

	err := row.Scan(&scanned.ID, &scanned.Kind, &scanned.Email, &scanned.DisplayName, &scanned.Role,
		&scanned.Status, &scanned.Policy, &scanned.PolicyManagedBy, &scanned.MustChangePassword,
		&scanned.LastSeenAt, &scanned.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return identity.User{}, app.ErrNotFound
	}

	if err != nil {
		return identity.User{}, fmt.Errorf("postgres: read user: %w", err)
	}

	return scanned.user()
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

	policy := make(access.Policy, 0, len(rules))
	for _, s := range rules {
		rule, err := access.ParseRule(s)
		if err != nil {
			return nil, fmt.Errorf("postgres: decode policy: %w", err)
		}

		policy = append(policy, rule)
	}

	return policy, nil
}
