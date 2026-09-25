package adminusers

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/google/uuid"
)

const (
	// InvitationTTL is how long an identity provider invitation stays redeemable,
	// for the same reason and with the same window as a temporary password.
	InvitationTTL = 72 * time.Hour

	// DefaultActivityLimit and MaxActivityLimit bound one page of Activity.
	DefaultActivityLimit = 50
	MaxActivityLimit     = 200
)

// The request fields an *InvalidInputError names, as the transport spells them.
const (
	fieldDisplayName = "displayName"
	fieldRole        = "role"
	fieldEmail       = "email"
	fieldSignIn      = "signIn"
)

// Config is the deployment's federated sign-in, as far as administration
// needs to know it.
type Config struct {
	// OIDCIssuer is the issuer invitations are written for, byte for byte what the
	// identity provider puts in its tokens. Empty means OIDC sign-in is off.
	OIDCIssuer string
	// GroupMappingConfigured reports whether IdP groups own federated policies.
	GroupMappingConfigured bool
}

// Service is the administrator's view of accounts: people, service accounts,
// their policies, passwords, tokens and history.
//
// Every method requires an active administrator with a full session as actor, and
// every change is recorded in the audit log without a secret in it. Account
// creation commits the account, its credential and its audit record together; any
// other change that landed but whose audit record did not is reported as an error,
// and a secret it created is withheld: an unaudited credential is not handed out.
type Service struct {
	users     app.UserRepo
	passwords app.PasswordRepo
	idents    app.IdentityRepo
	sessions  app.SessionRepo
	activity  app.ActivityRepo
	tokens    *app.TokenService
	hasher    *app.PasswordHasher
	audit     app.AuditSink
	clock     app.Clock
	catalog   app.ModelCatalog
	cfg       Config
}

func New(
	users app.UserRepo, passwords app.PasswordRepo, idents app.IdentityRepo, sessions app.SessionRepo, activity app.ActivityRepo,
	tokens *app.TokenService, hasher *app.PasswordHasher, audit app.AuditSink, clock app.Clock, catalog app.ModelCatalog, cfg Config,
) *Service {
	return &Service{
		users: users, passwords: passwords, idents: idents, sessions: sessions, activity: activity,
		tokens: tokens, hasher: hasher, audit: audit, clock: clock, catalog: catalog, cfg: cfg,
	}
}

// ListUsers returns every account, oldest first.
func (s *Service) ListUsers(ctx context.Context, actor identity.User) ([]app.UserView, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return nil, err
	}

	views, err := s.users.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("app: list users: %w", err)
	}

	return views, nil
}

func (s *Service) GetUser(ctx context.Context, actor identity.User, id uuid.UUID) (app.UserView, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return app.UserView{}, err
	}

	return s.view(ctx, id)
}

// NewUser is what an administrator asks CreateUser for.
type NewUser struct {
	Kind        identity.Kind
	Email       string // a human's sign-in address; must be empty for a service account
	DisplayName string
	Role        identity.Role // empty means RoleUser; a service account is always RoleUser
	Policy      []string
	SignIn      app.SignInMethod // a human's first way in; ignored for a service account
}

// CreatedUser is the new account and, for a human with a local password, the
// temporary password. Nothing else ever returns that password again.
type CreatedUser struct {
	User              app.UserView
	TemporaryPassword *app.TemporaryPassword
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
func (s *Service) CreateUser(ctx context.Context, actor identity.User, in NewUser) (CreatedUser, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return CreatedUser{}, err
	}

	policy, err := parsePolicy(in.Policy)
	if err != nil {
		return CreatedUser{}, err
	}

	name := strings.TrimSpace(in.DisplayName)
	if name == "" {
		return CreatedUser{}, &app.InvalidInputError{Field: fieldDisplayName}
	}

	role := cmp.Or(in.Role, identity.RoleUser)
	if !validRole(role) {
		return CreatedUser{}, &app.InvalidInputError{Field: fieldRole}
	}

	now := s.clock.Now().UTC()

	var (
		acct app.NewAccount
		out  CreatedUser
	)

	switch in.Kind {
	case identity.KindService:
		acct, out, err = newServiceAccount(in, name, role, policy, now)
	case identity.KindHuman:
		acct, out, err = s.newHumanAccount(ctx, in, name, role, policy, now)
	default:
		err = &app.InvalidInputError{Field: "kind"}
	}

	if err != nil {
		return CreatedUser{}, err
	}

	acct.Audit = app.AuditEvent{
		At:      now,
		ActorID: actor.ID,
		Action:  "user.create",
		Target:  acct.User.ID.String(),
		Detail:  createDetail(acct.User, in.SignIn),
	}
	if err := s.users.CreateAccount(ctx, acct); err != nil {
		return CreatedUser{}, fmt.Errorf("app: create user: %w", err)
	}

	out.User.User = acct.User

	return out, nil
}

// newServiceAccount is CreateUser's account for a service account: no address, no
// sign-in, and never more than RoleUser.
func newServiceAccount(in NewUser, name string, role identity.Role, policy access.Policy, now time.Time) (app.NewAccount, CreatedUser, error) {
	if in.Email != "" {
		return app.NewAccount{}, CreatedUser{}, &app.InvalidInputError{Field: fieldEmail}
	}
	// A service account cannot sign in, so an admin role would grant nothing
	// but a misleading line in the user list.
	if role != identity.RoleUser {
		return app.NewAccount{}, CreatedUser{}, &app.InvalidInputError{Field: fieldRole}
	}

	acct := app.NewAccount{User: identity.NewService(uuid.New(), name, policy)}
	acct.User.CreatedAt = now

	return acct, CreatedUser{User: app.UserView{SignIn: []app.SignInMethod{}}}, nil
}

func createDetail(user identity.User, signIn app.SignInMethod) map[string]any {
	detail := map[string]any{
		"kind":   string(user.Kind),
		"role":   string(user.Role),
		"policy": ruleStrings(user.Policy),
	}
	if user.Kind == identity.KindHuman {
		detail["email"] = user.Email
		detail["sign_in"] = string(signIn)
	}

	return detail
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
func (s *Service) UpdateUser(ctx context.Context, actor identity.User, id uuid.UUID, ch UserChanges) (app.UserView, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return app.UserView{}, err
	}

	change, detail, err := s.adminChange(ch)
	if err != nil {
		return app.UserView{}, err
	}

	if id == actor.ID &&
		((ch.Status != nil && *ch.Status == identity.StatusBlocked) ||
			(ch.Role != nil && *ch.Role != identity.RoleAdmin)) {
		return app.UserView{}, app.ErrSelfLockout
	}

	if len(detail) == 0 {
		return s.view(ctx, id)
	}

	user, err := s.users.ByID(ctx, id)
	if err != nil {
		return app.UserView{}, fmt.Errorf("app: update user: %w", err)
	}

	if ch.Role != nil && user.Kind == identity.KindService && *ch.Role != identity.RoleUser {
		return app.UserView{}, &app.InvalidInputError{Field: fieldRole}
	}

	if ch.Policy != nil && !user.PolicyEditableByAdmin() {
		if s.cfg.GroupMappingConfigured {
			return app.UserView{}, app.ErrPolicyManagedByIDP
		}

		detail["policy_source"] = string(identity.PolicyLocal)
	}

	if err := s.users.UpdateAdminState(ctx, id, change); err != nil {
		return app.UserView{}, fmt.Errorf("app: update user: %w", err)
	}
	// After the write, not before: from here on no new session can open, so nothing
	// opened between the delete and the block survives it.
	if ch.Status != nil && *ch.Status == identity.StatusBlocked {
		if err := s.sessions.DeleteByUser(ctx, id); err != nil {
			return app.UserView{}, fmt.Errorf("app: user %s blocked but sessions not ended: %w", id, err)
		}
	}

	if err := s.record(ctx, actor, "user.update", id, s.clock.Now().UTC(), detail); err != nil {
		return app.UserView{}, err
	}

	return s.view(ctx, id)
}

// RenewInvitation gives a person who has not linked an identity yet a fresh
// identity provider invitation for their address, replacing any earlier one, lapsed
// or not — the way back when an invitation expired or was consumed without a link.
// An account already linked is ErrAlreadyLinked; one nobody could redeem an
// invitation for (a service account, no address, OIDC not configured) is
// ErrNotInvitable.
func (s *Service) RenewInvitation(ctx context.Context, actor identity.User, id uuid.UUID) error {
	if err := app.RequireAdmin(actor); err != nil {
		return err
	}

	if s.cfg.OIDCIssuer == "" {
		return app.ErrNotInvitable
	}

	user, err := s.users.ByID(ctx, id)
	if err != nil {
		return fmt.Errorf("app: renew invitation: %w", err)
	}

	if user.Kind != identity.KindHuman || user.Email == "" {
		return app.ErrNotInvitable
	}

	now := s.clock.Now().UTC()

	inv := app.Invitation{Issuer: s.cfg.OIDCIssuer, Email: user.Email, ExpiresAt: now.Add(InvitationTTL)}
	if err := s.idents.Invite(ctx, id, inv); err != nil {
		return fmt.Errorf("app: renew invitation: %w", err)
	}

	return s.record(ctx, actor, "user.invitation.renew", id, now,
		map[string]any{"email": user.Email, app.AuditExpiresAt: inv.ExpiresAt.Format(time.RFC3339)})
}

// ResetPassword issues a new temporary password (TemporaryPasswordTTL) that must be
// changed at the next sign-in, and ends every session of the account: whoever held
// the old password is out. A service account cannot hold a password (ErrNotLocal).
// A human who signs in only through the identity provider gains a local password.
func (s *Service) ResetPassword(ctx context.Context, actor identity.User, id uuid.UUID) (app.TemporaryPassword, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return app.TemporaryPassword{}, err
	}

	user, err := s.users.ByID(ctx, id)
	if err != nil {
		return app.TemporaryPassword{}, fmt.Errorf("app: reset password: %w", err)
	}

	if user.Kind != identity.KindHuman {
		return app.TemporaryPassword{}, app.ErrNotLocal
	}

	now := s.clock.Now().UTC()

	temp, err := app.ResetPassword(ctx, s.users, s.passwords, s.sessions, s.hasher, user.ID, now)
	if err != nil {
		return app.TemporaryPassword{}, err
	}

	if err := s.record(ctx, actor, "user.password_reset", user.ID, now,
		map[string]any{app.AuditExpiresAt: temp.ExpiresAt.Format(time.RFC3339)}); err != nil {
		return app.TemporaryPassword{}, err
	}

	return temp, nil
}

// ListTokens returns an account's tokens. An unknown account is ErrNotFound rather
// than an empty list.
func (s *Service) ListTokens(ctx context.Context, actor identity.User, userID uuid.UUID) ([]credentials.Token, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return nil, err
	}

	if _, err := s.users.ByID(ctx, userID); err != nil {
		return nil, fmt.Errorf("app: list tokens: %w", err)
	}

	return s.tokens.List(ctx, actor, userID)
}

// IssueToken issues a token on behalf of an account — the only way a service
// account gets one. The secret is returned here and never again.
func (s *Service) IssueToken(
	ctx context.Context, actor identity.User, userID uuid.UUID, label string,
) (credentials.Token, string, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return credentials.Token{}, "", err
	}

	return s.tokens.Issue(ctx, actor, userID, label)
}

// RevokeToken revokes one of userID's tokens. A token that exists but belongs to
// another account is ErrNotFound: the address names userID's token, and that one
// does not exist.
func (s *Service) RevokeToken(ctx context.Context, actor identity.User, userID, tokenID uuid.UUID) error {
	if err := app.RequireAdmin(actor); err != nil {
		return err
	}

	owned, err := s.tokens.List(ctx, actor, userID)
	if err != nil {
		return err
	}

	if !slices.ContainsFunc(owned, func(t credentials.Token) bool { return t.ID == tokenID }) {
		return app.ErrNotFound
	}

	return s.tokens.Revoke(ctx, actor, tokenID)
}

// Activity is one account's recent history, newest first.
type Activity struct {
	Requests []app.UsageEvent
	Audit    []app.AuditEvent
}

// Activity returns up to limit recent requests and up to limit recent audit events.
// A limit outside 1..MaxActivityLimit is DefaultActivityLimit below the range and
// MaxActivityLimit above it.
func (s *Service) Activity(ctx context.Context, actor identity.User, userID uuid.UUID, limit int) (Activity, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return Activity{}, err
	}

	switch {
	case limit < 1:
		limit = DefaultActivityLimit
	case limit > MaxActivityLimit:
		limit = MaxActivityLimit
	}

	if _, err := s.users.ByID(ctx, userID); err != nil {
		return Activity{}, fmt.Errorf("app: activity: %w", err)
	}

	requests, err := s.activity.RecentUsage(ctx, userID, limit)
	if err != nil {
		return Activity{}, fmt.Errorf("app: activity: %w", err)
	}

	audit, err := s.activity.RecentAudit(ctx, userID, limit)
	if err != nil {
		return Activity{}, fmt.Errorf("app: activity: %w", err)
	}

	return Activity{Requests: requests, Audit: audit}, nil
}

// Catalog returns the live catalogue for the policy editor, providers and models
// sorted by name.
func (s *Service) Catalog(actor identity.User) ([]app.CatalogProvider, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return nil, err
	}

	served := s.catalog.Models()

	out := make([]app.CatalogProvider, 0, len(served))
	for name, models := range served {
		sorted := slices.Clone(models)
		slices.Sort(sorted)
		out = append(out, app.CatalogProvider{Name: name, Models: sorted})
	}

	slices.SortFunc(out, func(a, b app.CatalogProvider) int { return strings.Compare(a.Name, b.Name) })

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
func (s *Service) PolicyPreview(actor identity.User, rules []string) (PolicyPreview, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return PolicyPreview{}, err
	}

	out := PolicyPreview{Invalid: []string{}, Covered: []CoveredModel{}}

	policy := make(access.Policy, 0, len(rules))
	for _, raw := range rules {
		rule, err := access.ParseRule(raw)
		if err != nil {
			out.Invalid = append(out.Invalid, raw)

			continue
		}

		policy = append(policy, rule)
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

// newHumanAccount is CreateUser's account for a person, with the credential of the
// first way in they were given: a temporary password or an invitation.
func (s *Service) newHumanAccount(
	ctx context.Context, in NewUser, name string, role identity.Role, policy access.Policy, now time.Time,
) (app.NewAccount, CreatedUser, error) {
	email := strings.TrimSpace(in.Email)
	if local, domain, ok := strings.Cut(email, "@"); !ok || local == "" || domain == "" {
		return app.NewAccount{}, CreatedUser{}, &app.InvalidInputError{Field: fieldEmail}
	}

	acct := app.NewAccount{User: identity.User{
		ID:           uuid.New(),
		Kind:         identity.KindHuman,
		Email:        email,
		DisplayName:  name,
		Role:         role,
		Status:       identity.StatusActive,
		Policy:       policy,
		PolicySource: identity.PolicyLocal,
		CreatedAt:    now,
	}}

	var out CreatedUser

	switch in.SignIn {
	case app.SignInPassword:
		// Derived before anything is written: a derivation that fails or is
		// cancelled costs nothing to retry.
		temp, hash, err := app.DrawTemporaryPassword(ctx, s.hasher, now)
		if err != nil {
			return app.NewAccount{}, CreatedUser{}, err
		}

		acct.User.MustChangePassword = true
		acct.Password = &app.StoredPassword{Hash: hash, ExpiresAt: &temp.ExpiresAt}
		out.TemporaryPassword = &temp
		out.User = app.UserView{SignIn: []app.SignInMethod{app.SignInPassword}}
	case app.SignInOIDC:
		if s.cfg.OIDCIssuer == "" {
			return app.NewAccount{}, CreatedUser{}, &app.InvalidInputError{Field: fieldSignIn}
		}

		acct.Invitation = &app.Invitation{Issuer: s.cfg.OIDCIssuer, Email: email, ExpiresAt: now.Add(InvitationTTL)}
		out.User = app.UserView{SignIn: []app.SignInMethod{}, InvitationExpiresAt: &acct.Invitation.ExpiresAt}
	default:
		return app.NewAccount{}, CreatedUser{}, &app.InvalidInputError{Field: fieldSignIn}
	}

	return acct, out, nil
}

// adminChange validates an edit and turns it into the write and its audit detail.
// The detail is empty when the edit sets nothing.
func (s *Service) adminChange(ch UserChanges) (app.AdminChange, map[string]any, error) {
	change := app.AdminChange{Role: ch.Role, Status: ch.Status, RefuseIDPPolicy: s.cfg.GroupMappingConfigured}
	detail := map[string]any{}

	if ch.DisplayName != nil {
		name := strings.TrimSpace(*ch.DisplayName)
		if name == "" {
			return app.AdminChange{}, nil, &app.InvalidInputError{Field: fieldDisplayName}
		}

		change.DisplayName = &name
		detail["display_name"] = name
	}

	if ch.Role != nil {
		if !validRole(*ch.Role) {
			return app.AdminChange{}, nil, &app.InvalidInputError{Field: fieldRole}
		}

		detail["role"] = string(*ch.Role)
	}

	if ch.Status != nil {
		if *ch.Status != identity.StatusActive && *ch.Status != identity.StatusBlocked {
			return app.AdminChange{}, nil, &app.InvalidInputError{Field: "status"}
		}

		detail["status"] = string(*ch.Status)
	}

	if ch.Policy != nil {
		policy, err := parsePolicy(*ch.Policy)
		if err != nil {
			return app.AdminChange{}, nil, err
		}

		change.Policy = &policy
		detail["policy"] = ruleStrings(policy)
	}

	return change, detail, nil
}

// view is one account as the administrator sees it.
func (s *Service) view(ctx context.Context, id uuid.UUID) (app.UserView, error) {
	view, err := s.users.View(ctx, id)
	if err != nil {
		return app.UserView{}, fmt.Errorf("app: get user: %w", err)
	}

	return view, nil
}

// record writes an administrator's action to the audit log. The change it
// describes is already durable, so a failure here is reported as the change not
// being audited; the caller withholds any secret the change produced.
func (s *Service) record(
	ctx context.Context, actor identity.User, action string, target uuid.UUID, at time.Time, detail map[string]any,
) error {
	if err := s.audit.Record(ctx, app.AuditEvent{
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
	policy := make(access.Policy, 0, len(rules))
	for _, raw := range rules {
		rule, err := access.ParseRule(raw)
		if err != nil {
			return nil, &app.InvalidRuleError{Rule: raw}
		}

		policy = append(policy, rule)
	}

	return policy, nil
}

func ruleStrings(policy access.Policy) []string {
	out := make([]string, 0, len(policy))
	for _, r := range policy {
		out = append(out, r.String())
	}

	return out
}

func validRole(r identity.Role) bool {
	return r == identity.RoleUser || r == identity.RoleAdmin
}
