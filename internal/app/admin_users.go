package app

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

const (
	// TemporaryPasswordTTL is how long a password an administrator issues stays
	// usable. Unclaimed, it lapses and the administrator issues another.
	TemporaryPasswordTTL = 72 * time.Hour
	// InvitationTTL is how long an identity provider invitation stays redeemable,
	// for the same reason and with the same window as a temporary password.
	InvitationTTL = 72 * time.Hour

	// DefaultActivityLimit and MaxActivityLimit bound one page of Activity.
	DefaultActivityLimit = 50
	MaxActivityLimit     = 200
)

var (
	// ErrPolicyManagedByIDP refuses a policy edit the next IdP login would undo.
	ErrPolicyManagedByIDP = errors.New("app: policy is managed by the identity provider")
	// ErrSelfLockout refuses an administrator blocking or demoting themselves.
	ErrSelfLockout = errors.New("app: an administrator cannot block or demote themselves")
	// ErrNotLocal refuses a password for an account that cannot hold one.
	ErrNotLocal = errors.New("app: account cannot hold a password")
	// ErrInvalidRule is what an *InvalidRuleError unwraps to.
	ErrInvalidRule = errors.New("app: invalid policy rule")
	// ErrInvalidInput is what an *InvalidInputError unwraps to.
	ErrInvalidInput = errors.New("app: invalid input")
	// ErrAlreadyLinked refuses an invitation to an account that already signs in
	// through the identity provider.
	ErrAlreadyLinked = errors.New("app: account already has an identity provider link")
	// ErrNotInvitable refuses an invitation nobody could redeem: a service account,
	// an account without an address, or OIDC sign-in not configured.
	ErrNotInvitable = errors.New("app: account cannot be invited")
)

// InvalidRuleError names the first policy rule that does not parse.
type InvalidRuleError struct{ Rule string }

func (e *InvalidRuleError) Error() string {
	return ErrInvalidRule.Error() + ": " + strconv.Quote(e.Rule)
}
func (e *InvalidRuleError) Unwrap() error { return ErrInvalidRule }

// InvalidInputError names the request field that is missing or not acceptable.
type InvalidInputError struct{ Field string }

func (e *InvalidInputError) Error() string { return ErrInvalidInput.Error() + ": " + e.Field }
func (e *InvalidInputError) Unwrap() error { return ErrInvalidInput }

// AdminUsersConfig is the deployment's federated sign-in, as far as administration
// needs to know it.
type AdminUsersConfig struct {
	// OIDCIssuer is the issuer invitations are written for, byte for byte what the
	// identity provider puts in its tokens. Empty means OIDC sign-in is off.
	OIDCIssuer string
	// GroupMappingConfigured reports whether IdP groups own federated policies.
	GroupMappingConfigured bool
}

// AdminUsers is the administrator's view of accounts: people, service accounts,
// their policies, passwords, tokens and history.
//
// Every method requires an active administrator with a full session as actor, and
// every change is recorded in the audit log without a secret in it. Account
// creation commits the account, its credential and its audit record together; any
// other change that landed but whose audit record did not is reported as an error,
// and a secret it created is withheld: an unaudited credential is not handed out.
type AdminUsers struct {
	users     UserRepo
	passwords PasswordRepo
	idents    IdentityRepo
	sessions  SessionRepo
	activity  ActivityRepo
	tokens    *TokenService
	hasher    *PasswordHasher
	audit     AuditSink
	clock     Clock
	catalog   ModelCatalog
	cfg       AdminUsersConfig
}

func NewAdminUsers(users UserRepo, passwords PasswordRepo, idents IdentityRepo, sessions SessionRepo, activity ActivityRepo, tokens *TokenService, hasher *PasswordHasher, audit AuditSink, clock Clock, catalog ModelCatalog, cfg AdminUsersConfig) *AdminUsers {
	return &AdminUsers{
		users: users, passwords: passwords, idents: idents, sessions: sessions, activity: activity,
		tokens: tokens, hasher: hasher, audit: audit, clock: clock, catalog: catalog, cfg: cfg,
	}
}

// requireAdmin admits an active human administrator who is not under a temporary
// password, and nobody else. An unpopulated actor is nobody: a transport that forgot
// to fill it in must not inherit authority. The temporary-password refusal repeats
// the restricted-session gate on purpose: if a transport ever skips that gate, an
// administrator's unchanged temporary password — possibly read out of a bootstrap
// log — still grants nothing here.
func requireAdmin(actor identity.User) error {
	if actor.ID == uuid.Nil || actor.Role != identity.RoleAdmin || !actor.CanSignIn() || actor.MustChangePassword {
		return ErrForbidden
	}
	return nil
}

// ListUsers returns every account, oldest first.
func (s *AdminUsers) ListUsers(ctx context.Context, actor identity.User) ([]UserView, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	return s.users.List(ctx)
}

func (s *AdminUsers) GetUser(ctx context.Context, actor identity.User, id uuid.UUID) (UserView, error) {
	if err := requireAdmin(actor); err != nil {
		return UserView{}, err
	}
	return s.users.View(ctx, id)
}

// NewUser is what an administrator asks CreateUser for.
type NewUser struct {
	Kind        identity.Kind
	Email       string // a human's sign-in address; must be empty for a service account
	DisplayName string
	Role        identity.Role // empty means RoleUser; a service account is always RoleUser
	Policy      []string
	SignIn      SignInMethod // a human's first way in; ignored for a service account
}

// TemporaryPassword is a password shown once, to the administrator who issued it.
type TemporaryPassword struct {
	Password  string
	ExpiresAt time.Time
}

// CreatedUser is the new account and, for a human with a local password, the
// temporary password. Nothing else ever returns that password again.
type CreatedUser struct {
	User              UserView
	TemporaryPassword *TemporaryPassword
}

// CreateUser provisions an account under a fresh random id; the caller cannot pick
// one. Random (v4) ids keep administrator-made accounts disjoint from the v5 ids
// OIDC sign-up derives from a subject, so no sign-up can ever adopt one.
//
//   - A human with SignInPassword gets a temporary password (TemporaryPasswordTTL)
//     and must change it at first sign-in.
//   - A human with SignInOIDC gets an invitation for the address, written for exactly
//     the configured issuer, that the first verified sign-in with it claims.
//   - A service account gets neither: it never signs in, and an administrator issues
//     its tokens.
//
// The account, its credential and the user.create audit record are one write: a
// failure anywhere leaves nothing behind, so the administrator simply retries. An
// address already taken, compared case-insensitively, is ErrConflict.
func (s *AdminUsers) CreateUser(ctx context.Context, actor identity.User, in NewUser) (CreatedUser, error) {
	if err := requireAdmin(actor); err != nil {
		return CreatedUser{}, err
	}
	policy, err := parsePolicy(in.Policy)
	if err != nil {
		return CreatedUser{}, err
	}
	name := strings.TrimSpace(in.DisplayName)
	if name == "" {
		return CreatedUser{}, &InvalidInputError{Field: "displayName"}
	}
	role := cmp.Or(in.Role, identity.RoleUser)
	if !validRole(role) {
		return CreatedUser{}, &InvalidInputError{Field: "role"}
	}
	now := s.clock.Now().UTC()

	var (
		acct NewAccount
		out  CreatedUser
	)
	switch in.Kind {
	case identity.KindService:
		if in.Email != "" {
			return CreatedUser{}, &InvalidInputError{Field: "email"}
		}
		// A service account cannot sign in, so an admin role would grant nothing
		// but a misleading line in the user list.
		if role != identity.RoleUser {
			return CreatedUser{}, &InvalidInputError{Field: "role"}
		}
		acct.User = identity.NewService(uuid.New(), name, policy)
		acct.User.CreatedAt = now
		out.User = UserView{SignIn: []SignInMethod{}}

	case identity.KindHuman:
		email := strings.TrimSpace(in.Email)
		if local, domain, ok := strings.Cut(email, "@"); !ok || local == "" || domain == "" {
			return CreatedUser{}, &InvalidInputError{Field: "email"}
		}
		acct.User = identity.User{
			ID:           uuid.New(),
			Kind:         identity.KindHuman,
			Email:        email,
			DisplayName:  name,
			Role:         role,
			Status:       identity.StatusActive,
			Policy:       policy,
			PolicySource: identity.PolicyLocal,
			CreatedAt:    now,
		}
		switch in.SignIn {
		case SignInPassword:
			// Derived before anything is written: a derivation that fails or is
			// cancelled costs nothing to retry.
			temp, hash, err := drawTemporaryPassword(ctx, s.hasher, now)
			if err != nil {
				return CreatedUser{}, err
			}
			acct.User.MustChangePassword = true
			acct.Password = &StoredPassword{Hash: hash, ExpiresAt: &temp.ExpiresAt}
			out.TemporaryPassword = &temp
			out.User = UserView{SignIn: []SignInMethod{SignInPassword}}
		case SignInOIDC:
			if s.cfg.OIDCIssuer == "" {
				return CreatedUser{}, &InvalidInputError{Field: "signIn"}
			}
			acct.Invitation = &Invitation{Issuer: s.cfg.OIDCIssuer, Email: email, ExpiresAt: now.Add(InvitationTTL)}
			out.User = UserView{SignIn: []SignInMethod{}, InvitationExpiresAt: &acct.Invitation.ExpiresAt}
		default:
			return CreatedUser{}, &InvalidInputError{Field: "signIn"}
		}

	default:
		return CreatedUser{}, &InvalidInputError{Field: "kind"}
	}

	acct.Audit = AuditEvent{
		At:      now,
		ActorID: actor.ID,
		Action:  "user.create",
		Target:  acct.User.ID.String(),
		Detail:  createDetail(acct.User, in.SignIn),
	}
	if err := s.users.CreateAccount(ctx, acct); err != nil {
		return CreatedUser{}, err
	}
	out.User.User = acct.User
	return out, nil
}

func createDetail(u identity.User, signIn SignInMethod) map[string]any {
	d := map[string]any{
		"kind":   string(u.Kind),
		"role":   string(u.Role),
		"policy": ruleStrings(u.Policy),
	}
	if u.Kind == identity.KindHuman {
		d["email"] = u.Email
		d["sign_in"] = string(signIn)
	}
	return d
}

// UserChanges is an administrator's edit. A nil field is left as it is.
type UserChanges struct {
	DisplayName *string
	Role        *identity.Role
	Status      *identity.Status
	Policy      *[]string
}

// UpdateUser applies an edit and returns the account as it now stands. Only the
// fields the edit sets are written, so a concurrent edit of another field survives.
//
//   - A policy change on an account whose policy the identity provider owns is
//     ErrPolicyManagedByIDP while the group mapping is configured. With no mapping
//     configured nothing recomputes that policy any more: it is frozen, so the edit
//     converts it to a local policy and applies. Removing the mapping therefore never
//     leaves an account no administrator can edit.
//   - Every rule is parsed; the first that does not is an *InvalidRuleError.
//   - Blocking deletes the account's sessions, so a block is a revocation and not
//     a pause that an unblock within the session window would undo. Its tokens need
//     nothing: CanUseAPI refuses them from the next request.
//   - An administrator blocking or demoting themselves is ErrSelfLockout.
func (s *AdminUsers) UpdateUser(ctx context.Context, actor identity.User, id uuid.UUID, ch UserChanges) (UserView, error) {
	if err := requireAdmin(actor); err != nil {
		return UserView{}, err
	}
	change := AdminChange{Role: ch.Role, Status: ch.Status, RefuseIdPPolicy: s.cfg.GroupMappingConfigured}
	detail := map[string]any{}
	if ch.DisplayName != nil {
		name := strings.TrimSpace(*ch.DisplayName)
		if name == "" {
			return UserView{}, &InvalidInputError{Field: "displayName"}
		}
		change.DisplayName = &name
		detail["display_name"] = name
	}
	if ch.Role != nil {
		if !validRole(*ch.Role) {
			return UserView{}, &InvalidInputError{Field: "role"}
		}
		detail["role"] = string(*ch.Role)
	}
	if ch.Status != nil {
		if *ch.Status != identity.StatusActive && *ch.Status != identity.StatusBlocked {
			return UserView{}, &InvalidInputError{Field: "status"}
		}
		detail["status"] = string(*ch.Status)
	}
	if ch.Policy != nil {
		policy, err := parsePolicy(*ch.Policy)
		if err != nil {
			return UserView{}, err
		}
		change.Policy = &policy
		detail["policy"] = ruleStrings(policy)
	}
	if id == actor.ID &&
		((ch.Status != nil && *ch.Status == identity.StatusBlocked) ||
			(ch.Role != nil && *ch.Role != identity.RoleAdmin)) {
		return UserView{}, ErrSelfLockout
	}
	if len(detail) == 0 {
		return s.users.View(ctx, id)
	}

	u, err := s.users.ByID(ctx, id)
	if err != nil {
		return UserView{}, err
	}
	if ch.Role != nil && u.Kind == identity.KindService && *ch.Role != identity.RoleUser {
		return UserView{}, &InvalidInputError{Field: "role"}
	}
	if ch.Policy != nil && !u.PolicyEditableByAdmin() {
		if s.cfg.GroupMappingConfigured {
			return UserView{}, ErrPolicyManagedByIDP
		}
		detail["policy_source"] = string(identity.PolicyLocal)
	}

	if err := s.users.UpdateAdminState(ctx, id, change); err != nil {
		return UserView{}, err
	}
	// After the write, not before: from here on no new session can open, so nothing
	// opened between the delete and the block survives it.
	if ch.Status != nil && *ch.Status == identity.StatusBlocked {
		if err := s.sessions.DeleteByUser(ctx, id); err != nil {
			return UserView{}, fmt.Errorf("app: user %s blocked but sessions not ended: %w", id, err)
		}
	}
	if err := s.record(ctx, actor, "user.update", id, s.clock.Now().UTC(), detail); err != nil {
		return UserView{}, err
	}
	return s.users.View(ctx, id)
}

// RenewInvitation gives a person who has not linked an identity yet a fresh
// identity provider invitation for their address, replacing any earlier one, lapsed
// or not — the way back when an invitation expired or was consumed without a link.
// An account already linked is ErrAlreadyLinked; one nobody could redeem an
// invitation for (a service account, no address, OIDC not configured) is
// ErrNotInvitable.
func (s *AdminUsers) RenewInvitation(ctx context.Context, actor identity.User, id uuid.UUID) error {
	if err := requireAdmin(actor); err != nil {
		return err
	}
	if s.cfg.OIDCIssuer == "" {
		return ErrNotInvitable
	}
	u, err := s.users.ByID(ctx, id)
	if err != nil {
		return err
	}
	if u.Kind != identity.KindHuman || u.Email == "" {
		return ErrNotInvitable
	}
	now := s.clock.Now().UTC()
	inv := Invitation{Issuer: s.cfg.OIDCIssuer, Email: u.Email, ExpiresAt: now.Add(InvitationTTL)}
	if err := s.idents.Invite(ctx, id, inv); err != nil {
		return err
	}
	return s.record(ctx, actor, "user.invitation.renew", id, now,
		map[string]any{"email": u.Email, "expires_at": inv.ExpiresAt.Format(time.RFC3339)})
}

// ResetPassword issues a new temporary password (TemporaryPasswordTTL) that must be
// changed at the next sign-in, and ends every session of the account: whoever held
// the old password is out. A service account cannot hold a password (ErrNotLocal).
// A human who signs in only through the identity provider gains a local password.
func (s *AdminUsers) ResetPassword(ctx context.Context, actor identity.User, id uuid.UUID) (TemporaryPassword, error) {
	if err := requireAdmin(actor); err != nil {
		return TemporaryPassword{}, err
	}
	u, err := s.users.ByID(ctx, id)
	if err != nil {
		return TemporaryPassword{}, err
	}
	if u.Kind != identity.KindHuman {
		return TemporaryPassword{}, ErrNotLocal
	}
	now := s.clock.Now().UTC()
	temp, err := resetPassword(ctx, s.users, s.passwords, s.sessions, s.hasher, u.ID, now)
	if err != nil {
		return TemporaryPassword{}, err
	}
	if err := s.record(ctx, actor, "user.password_reset", u.ID, now,
		map[string]any{"expires_at": temp.ExpiresAt.Format(time.RFC3339)}); err != nil {
		return TemporaryPassword{}, err
	}
	return temp, nil
}

// resetPassword gives the human account id a temporary password (TemporaryPasswordTTL)
// that must be changed at the next sign-in, and ends every session of the account. It
// is the one reset: an administrator's (AdminUsers.ResetPassword) and the operator's
// from the shell (Recovery.ResetPassword) both go through it, and each records it.
func resetPassword(ctx context.Context, users UserRepo, passwords PasswordRepo, sessions SessionRepo, hasher *PasswordHasher, id uuid.UUID, now time.Time) (TemporaryPassword, error) {
	temp, hash, err := drawTemporaryPassword(ctx, hasher, now)
	if err != nil {
		return TemporaryPassword{}, err
	}
	// The restriction lands before the password. The other order has a window in
	// which the new password opens an unrestricted session.
	if err := users.SetMustChangePassword(ctx, id, true); err != nil {
		return TemporaryPassword{}, err
	}
	if err := passwords.Set(ctx, id, hash, &temp.ExpiresAt); err != nil {
		return TemporaryPassword{}, err
	}
	if err := sessions.DeleteByUser(ctx, id); err != nil {
		return TemporaryPassword{}, fmt.Errorf("app: password of %s reset but sessions not ended: %w", id, err)
	}
	return temp, nil
}

// drawTemporaryPassword draws a password and derives its hash.
func drawTemporaryPassword(ctx context.Context, hasher *PasswordHasher, now time.Time) (TemporaryPassword, string, error) {
	secret, err := newTemporaryPassword()
	if err != nil {
		return TemporaryPassword{}, "", fmt.Errorf("app: temporary password: %w", err)
	}
	hash, err := hasher.Hash(ctx, secret)
	if err != nil {
		return TemporaryPassword{}, "", fmt.Errorf("app: temporary password: %w", err)
	}
	return TemporaryPassword{Password: secret, ExpiresAt: now.Add(TemporaryPasswordTTL)}, hash, nil
}

// ListTokens returns an account's tokens. An unknown account is ErrNotFound rather
// than an empty list.
func (s *AdminUsers) ListTokens(ctx context.Context, actor identity.User, userID uuid.UUID) ([]credentials.Token, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	if _, err := s.users.ByID(ctx, userID); err != nil {
		return nil, err
	}
	return s.tokens.List(ctx, actor, userID)
}

// IssueToken issues a token on behalf of an account — the only way a service
// account gets one. The secret is returned here and never again.
func (s *AdminUsers) IssueToken(ctx context.Context, actor identity.User, userID uuid.UUID, label string) (credentials.Token, string, error) {
	if err := requireAdmin(actor); err != nil {
		return credentials.Token{}, "", err
	}
	return s.tokens.Issue(ctx, actor, userID, label)
}

// RevokeToken revokes one of userID's tokens. A token that exists but belongs to
// another account is ErrNotFound: the address names userID's token, and that one
// does not exist.
func (s *AdminUsers) RevokeToken(ctx context.Context, actor identity.User, userID, tokenID uuid.UUID) error {
	if err := requireAdmin(actor); err != nil {
		return err
	}
	owned, err := s.tokens.List(ctx, actor, userID)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(owned, func(t credentials.Token) bool { return t.ID == tokenID }) {
		return ErrNotFound
	}
	return s.tokens.Revoke(ctx, actor, tokenID)
}

// Activity is one account's recent history, newest first.
type Activity struct {
	Requests []UsageEvent
	Audit    []AuditEvent
}

// Activity returns up to limit recent requests and up to limit recent audit events.
// A limit outside 1..MaxActivityLimit is DefaultActivityLimit below the range and
// MaxActivityLimit above it.
func (s *AdminUsers) Activity(ctx context.Context, actor identity.User, userID uuid.UUID, limit int) (Activity, error) {
	if err := requireAdmin(actor); err != nil {
		return Activity{}, err
	}
	switch {
	case limit < 1:
		limit = DefaultActivityLimit
	case limit > MaxActivityLimit:
		limit = MaxActivityLimit
	}
	if _, err := s.users.ByID(ctx, userID); err != nil {
		return Activity{}, err
	}
	requests, err := s.activity.RecentUsage(ctx, userID, limit)
	if err != nil {
		return Activity{}, err
	}
	audit, err := s.activity.RecentAudit(ctx, userID, limit)
	if err != nil {
		return Activity{}, err
	}
	return Activity{Requests: requests, Audit: audit}, nil
}

// CatalogProvider is one provider of the live catalogue and the models it serves.
type CatalogProvider struct {
	Name   string
	Models []string
}

// Catalog returns the live catalogue for the policy editor, providers and models
// sorted by name.
func (s *AdminUsers) Catalog(actor identity.User) ([]CatalogProvider, error) {
	if err := requireAdmin(actor); err != nil {
		return nil, err
	}
	served := s.catalog.Models()
	out := make([]CatalogProvider, 0, len(served))
	for name, models := range served {
		sorted := slices.Clone(models)
		slices.Sort(sorted)
		out = append(out, CatalogProvider{Name: name, Models: sorted})
	}
	slices.SortFunc(out, func(a, b CatalogProvider) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

// CoveredModel is one catalogue entry a policy allows.
type CoveredModel struct {
	Provider string
	Model    string
}

// PolicyPreview is what a set of rules would grant today.
type PolicyPreview struct {
	// Invalid holds every rule that does not parse, in the order given.
	Invalid []string
	// Covered holds every (provider, model) of today's catalogue the valid rules
	// cover, sorted. A model is covered only if every provider serving it is allowed
	// — the gate's rule, access.Policy.Admits — so a model two providers serve is
	// listed under both or under neither.
	Covered []CoveredModel
}

// PolicyPreview evaluates rules against today's catalogue. A wildcard also covers
// models published later; the preview can only show today's.
func (s *AdminUsers) PolicyPreview(actor identity.User, rules []string) (PolicyPreview, error) {
	if err := requireAdmin(actor); err != nil {
		return PolicyPreview{}, err
	}
	out := PolicyPreview{Invalid: []string{}, Covered: []CoveredModel{}}
	policy := make(access.Policy, 0, len(rules))
	for _, raw := range rules {
		r, err := access.ParseRule(raw)
		if err != nil {
			out.Invalid = append(out.Invalid, raw)
			continue
		}
		policy = append(policy, r)
	}
	covers := map[string]bool{}
	for provider, models := range s.catalog.Models() {
		for _, model := range models {
			ok, seen := covers[model]
			if !seen {
				ok = policy.Admits(s.catalog, model)
				covers[model] = ok
			}
			if ok {
				out.Covered = append(out.Covered, CoveredModel{Provider: provider, Model: model})
			}
		}
	}
	slices.SortFunc(out.Covered, func(a, b CoveredModel) int {
		return cmp.Or(strings.Compare(a.Provider, b.Provider), strings.Compare(a.Model, b.Model))
	})
	return out, nil
}

// record writes an administrator's action to the audit log. The change it
// describes is already durable, so a failure here is reported as the change not
// being audited; the caller withholds any secret the change produced.
func (s *AdminUsers) record(ctx context.Context, actor identity.User, action string, target uuid.UUID, at time.Time, detail map[string]any) error {
	if err := s.audit.Record(ctx, AuditEvent{
		At:      at,
		ActorID: actor.ID,
		Action:  action,
		Target:  target.String(),
		Detail:  detail,
	}); err != nil {
		return fmt.Errorf("app: %s on %s applied but not audited: %w", action, target, err)
	}
	return nil
}

// parsePolicy parses every rule; the first that does not parse is the error.
func parsePolicy(rules []string) (access.Policy, error) {
	p := make(access.Policy, 0, len(rules))
	for _, raw := range rules {
		r, err := access.ParseRule(raw)
		if err != nil {
			return nil, &InvalidRuleError{Rule: raw}
		}
		p = append(p, r)
	}
	return p, nil
}

func ruleStrings(p access.Policy) []string {
	out := make([]string, 0, len(p))
	for _, r := range p {
		out = append(out, r.String())
	}
	return out
}

func validRole(r identity.Role) bool {
	return r == identity.RoleUser || r == identity.RoleAdmin
}
