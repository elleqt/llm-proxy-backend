package app_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

const inviteIssuer = "https://idp.example.com/realms/demo/"

// adminFixture wires AdminUsers to strict mocks: a repository call a test did not
// expect fails it, so a refusal that still reaches a write is caught.
type adminFixture struct {
	users     *mocks.UserRepo
	passwords *mocks.PasswordRepo
	idents    *mocks.IdentityRepo
	sessions  *mocks.SessionRepo
	activity  *mocks.ActivityRepo
	tokens    *mocks.TokenRepo
	audit     *mocks.AuditSink
	catalog   *mocks.ModelCatalog
	svc       *app.AdminUsers
}

func newAdminFixture(t *testing.T, cfg app.AdminUsersConfig) *adminFixture {
	t.Helper()
	fixture := &adminFixture{
		users:     mocks.NewUserRepo(t),
		passwords: mocks.NewPasswordRepo(t),
		idents:    mocks.NewIdentityRepo(t),
		sessions:  mocks.NewSessionRepo(t),
		activity:  mocks.NewActivityRepo(t),
		tokens:    mocks.NewTokenRepo(t),
		audit:     mocks.NewAuditSink(t),
		catalog:   mocks.NewModelCatalog(t),
	}
	clock := mocks.NewClock(t)
	clock.EXPECT().Now().Return(frozen).Maybe()
	tokenSvc := app.NewTokenService(fixture.users, fixture.tokens, fixture.audit, clock, discardLogger{})
	fixture.svc = app.NewAdminUsers(fixture.users, fixture.passwords, fixture.idents, fixture.sessions, fixture.activity,
		tokenSvc, testHasher(), fixture.audit, clock, fixture.catalog, cfg)

	return fixture
}

// recordAudit captures every audit event. Registering it is also an assertion: the
// strict mock fails the test if the action under test records nothing.
func (f *adminFixture) recordAudit() *[]app.AuditEvent {
	var events []app.AuditEvent

	f.audit.EXPECT().Record(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, e app.AuditEvent) error {
		events = append(events, e)

		return nil
	})

	return &events
}

// captureAccount records what CreateUser asks the repository to commit.
func (f *adminFixture) captureAccount() *app.NewAccount {
	var acct app.NewAccount

	f.users.EXPECT().CreateAccount(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, a app.NewAccount) error {
		acct = a

		return nil
	})

	return &acct
}

// viewAfterUpdate answers the read UpdateUser returns its result from.
func (f *adminFixture) viewAfterUpdate(u identity.User) {
	f.users.EXPECT().View(mock.Anything, u.ID).Return(app.UserView{User: u, SignIn: []app.SignInMethod{}}, nil)
}

func newAdmin() identity.User {
	return identity.User{ID: uuid.New(), Kind: identity.KindHuman, Role: identity.RoleAdmin, Status: identity.StatusActive}
}

func newPerson() identity.User {
	return identity.User{
		ID: uuid.New(), Kind: identity.KindHuman, Email: "person@example.com",
		DisplayName: "Person", Role: identity.RoleUser, Status: identity.StatusActive,
		PolicySource: identity.PolicyLocal,
	}
}

// assertNoSecret fails if any audit detail carries one of the secrets.
func assertNoSecret(t *testing.T, events []app.AuditEvent, secrets ...string) {
	t.Helper()

	for _, event := range events {
		raw, err := json.Marshal(event.Detail)
		if err != nil {
			t.Fatalf("marshal detail: %v", err)
		}

		for _, s := range secrets {
			if s != "" && strings.Contains(string(raw)+event.Target, s) {
				t.Fatalf("audit event %s carries a secret: %s", event.Action, raw)
			}
		}
	}
}

// Every method is refused to anyone but an active administrator with a full
// session, before any repository is touched: the strict mocks carry no expectations.
func TestAdminUsersRefuseEveryoneButAnActiveAdmin(t *testing.T) {
	blockedAdmin := newAdmin()
	blockedAdmin.Status = identity.StatusBlocked
	serviceAdmin := newAdmin()
	serviceAdmin.Kind = identity.KindService
	restrictedAdmin := newAdmin()
	restrictedAdmin.MustChangePassword = true
	actors := map[string]identity.User{
		"user":                      newPerson(),
		"blocked admin":             blockedAdmin,
		"service as admin":          serviceAdmin,
		"admin on a temporary pass": restrictedAdmin,
		"nobody":                    {Role: identity.RoleAdmin, Kind: identity.KindHuman, Status: identity.StatusActive},
	}
	name := "x"
	ctx := context.Background()
	target := uuid.New()

	ops := map[string]func(*app.AdminUsers, identity.User) error{
		"ListUsers": func(s *app.AdminUsers, a identity.User) error {
			_, err := s.ListUsers(ctx, a)

			return err
		},
		"GetUser": func(s *app.AdminUsers, a identity.User) error {
			_, err := s.GetUser(ctx, a, target)

			return err
		},
		"CreateUser": func(s *app.AdminUsers, a identity.User) error {
			_, err := s.CreateUser(ctx, a, app.NewUser{Kind: identity.KindService, DisplayName: "bot"})

			return err
		},
		"UpdateUser": func(s *app.AdminUsers, a identity.User) error {
			_, err := s.UpdateUser(ctx, a, target, app.UserChanges{DisplayName: &name})

			return err
		},
		"RenewInvitation": func(s *app.AdminUsers, a identity.User) error { return s.RenewInvitation(ctx, a, target) },
		"ResetPassword": func(s *app.AdminUsers, a identity.User) error {
			_, err := s.ResetPassword(ctx, a, target)

			return err
		},
		"ListTokens": func(s *app.AdminUsers, a identity.User) error {
			_, err := s.ListTokens(ctx, a, target)

			return err
		},
		"IssueToken": func(s *app.AdminUsers, a identity.User) error {
			_, _, err := s.IssueToken(ctx, a, target, "label")

			return err
		},
		"RevokeToken": func(s *app.AdminUsers, a identity.User) error { return s.RevokeToken(ctx, a, target, uuid.New()) },
		"Activity": func(s *app.AdminUsers, a identity.User) error {
			_, err := s.Activity(ctx, a, target, 10)

			return err
		},
		"Catalog": func(s *app.AdminUsers, a identity.User) error {
			_, err := s.Catalog(a)

			return err
		},
		"PolicyPreview": func(s *app.AdminUsers, a identity.User) error {
			_, err := s.PolicyPreview(a, []string{"alpha:*"})

			return err
		},
	}
	for actorName, actor := range actors {
		for opName, op := range ops {
			t.Run(actorName+"/"+opName, func(t *testing.T) {
				f := newAdminFixture(t, app.AdminUsersConfig{OIDCIssuer: inviteIssuer})
				if err := op(f.svc, actor); !errors.Is(err, app.ErrForbidden) {
					t.Fatalf("err = %v, want ErrForbidden", err)
				}
			})
		}
	}
}

func TestCreateHumanWithPasswordShowsTheTemporaryPasswordOnce(t *testing.T) {
	f := newAdminFixture(t, app.AdminUsersConfig{})
	acct := f.captureAccount()
	admin := newAdmin()

	out, err := f.svc.CreateUser(context.Background(), admin, app.NewUser{
		Kind: identity.KindHuman, Email: "Person@Example.com", DisplayName: " Person ",
		Policy: []string{"alpha:*"}, SignIn: app.SignInPassword,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	temp, created := out.TemporaryPassword, acct.User
	if temp == nil || temp.Password == "" || acct.Password == nil {
		t.Fatal("no temporary password for a human with a local password")
	}

	if !identity.VerifyPassword(acct.Password.Hash, temp.Password) {
		t.Fatal("the stored hash does not verify the returned password")
	}

	wantExpiry := frozen.Add(72 * time.Hour)
	if exp := acct.Password.ExpiresAt; exp == nil || !exp.Equal(wantExpiry) || !temp.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("expiry stored %v, returned %v, want %v", exp, temp.ExpiresAt, wantExpiry)
	}

	if !created.MustChangePassword || !out.User.User.MustChangePassword {
		t.Fatal("the account does not have to change its temporary password")
	}

	if acct.Invitation != nil {
		t.Fatal("a password account was also invited")
	}
	// A random id: never derived, never chosen by a caller.
	if created.ID.Version() != 4 {
		t.Fatalf("id %s is version %d, want a random v4 id", created.ID, created.ID.Version())
	}

	if created.DisplayName != "Person" || created.Email != "Person@Example.com" || created.Role != identity.RoleUser {
		t.Fatalf("created = %+v", created)
	}

	if !slices.Equal(out.User.SignIn, []app.SignInMethod{app.SignInPassword}) {
		t.Fatalf("sign-in = %v, want [password]", out.User.SignIn)
	}
	// The audit record is committed with the account, not written beside it.
	if a := acct.Audit; a.Action != "user.create" || a.Target != created.ID.String() || a.ActorID != admin.ID {
		t.Fatalf("audit = %+v, want user.create on the new account by the admin", a)
	}

	assertNoSecret(t, []app.AuditEvent{acct.Audit}, temp.Password, acct.Password.Hash)
}

// A creation that did not commit hands out nothing.
func TestCreateUserWithholdsThePasswordWhenTheWriteFails(t *testing.T) {
	f := newAdminFixture(t, app.AdminUsersConfig{})
	boom := errors.New("transaction rolled back")
	f.users.EXPECT().CreateAccount(mock.Anything, mock.Anything).Return(boom)

	out, err := f.svc.CreateUser(context.Background(), newAdmin(), app.NewUser{
		Kind: identity.KindHuman, Email: "person@example.com", DisplayName: "Person", SignIn: app.SignInPassword,
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the write failure", err)
	}

	if out.TemporaryPassword != nil {
		t.Fatal("a temporary password was handed out for an account that was not stored")
	}
}

// The invitation is written for exactly the configured issuer: PendingByEmail
// matches it byte for byte, so a trailing slash lost here is an invitation nobody
// can redeem. No password is stored, and a pending invitation is not a way in yet.
func TestCreateHumanWithOIDCRecordsAnInvitationForTheExactIssuer(t *testing.T) {
	f := newAdminFixture(t, app.AdminUsersConfig{OIDCIssuer: inviteIssuer})
	acct := f.captureAccount()

	out, err := f.svc.CreateUser(context.Background(), newAdmin(), app.NewUser{
		Kind: identity.KindHuman, Email: "Person@Example.com", DisplayName: "Person", SignIn: app.SignInOIDC,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	want := app.Invitation{Issuer: inviteIssuer, Email: "Person@Example.com", ExpiresAt: frozen.Add(app.InvitationTTL)}
	if acct.Invitation == nil || *acct.Invitation != want {
		t.Fatalf("invitation = %+v, want %+v", acct.Invitation, want)
	}

	if acct.Password != nil || out.TemporaryPassword != nil || acct.User.MustChangePassword {
		t.Fatal("an invited account got a password")
	}

	if len(out.User.SignIn) != 0 || out.User.InvitationExpiresAt == nil || !out.User.InvitationExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("view = %+v, want no working sign-in and the invitation's expiry", out.User)
	}
}

// Without an issuer there is nobody to redeem the invitation: refused before any write.
func TestCreateHumanWithOIDCRefusedWhenOIDCIsOff(t *testing.T) {
	f := newAdminFixture(t, app.AdminUsersConfig{})
	_, err := f.svc.CreateUser(context.Background(), newAdmin(), app.NewUser{
		Kind: identity.KindHuman, Email: "person@example.com", DisplayName: "Person", SignIn: app.SignInOIDC,
	})

	var invalid *app.InvalidInputError
	if !errors.As(err, &invalid) || invalid.Field != "signIn" {
		t.Fatalf("err = %v, want an invalid signIn", err)
	}
}

func TestCreateServiceAccountGetsNoPasswordAndNoIdentity(t *testing.T) {
	f := newAdminFixture(t, app.AdminUsersConfig{OIDCIssuer: inviteIssuer})
	acct := f.captureAccount()

	// SignIn is ignored for a service account.
	out, err := f.svc.CreateUser(context.Background(), newAdmin(), app.NewUser{
		Kind: identity.KindService, DisplayName: "chat-panel", Policy: []string{"alpha:*"}, SignIn: app.SignInOIDC,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if acct.Password != nil || acct.Invitation != nil || out.TemporaryPassword != nil || len(out.User.SignIn) != 0 {
		t.Fatalf("service account got a way in: %+v / %+v", acct, out)
	}

	if c := acct.User; c.Kind != identity.KindService || c.Email != "" || c.ID.Version() != 4 {
		t.Fatalf("created = %+v", c)
	}
}

func TestUpdateUserReportsTheFirstInvalidRule(t *testing.T) {
	f := newAdminFixture(t, app.AdminUsersConfig{})
	rules := []string{"alpha:*", "no-colon", ":no-provider"}
	_, err := f.svc.UpdateUser(context.Background(), newAdmin(), uuid.New(), app.UserChanges{Policy: &rules})

	var invalid *app.InvalidRuleError
	if !errors.As(err, &invalid) {
		t.Fatalf("err = %v, want *InvalidRuleError", err)
	}

	if invalid.Rule != "no-colon" {
		t.Fatalf("rule = %q, want the first bad one, %q", invalid.Rule, "no-colon")
	}
}

func idpUser() identity.User {
	u := newPerson()
	u.PolicySource = identity.PolicyIDP

	return u
}

func TestUpdatePolicyOfAnIdPUserRefusedWhileTheMappingIsConfigured(t *testing.T) {
	fixture := newAdminFixture(t, app.AdminUsersConfig{OIDCIssuer: inviteIssuer, GroupMappingConfigured: true})
	target := idpUser()
	fixture.users.EXPECT().ByID(mock.Anything, target.ID).Return(target, nil)

	rules := []string{"alpha:*"}

	_, err := fixture.svc.UpdateUser(context.Background(), newAdmin(), target.ID, app.UserChanges{Policy: &rules})
	if !errors.Is(err, app.ErrPolicyManagedByIDP) {
		t.Fatalf("err = %v, want ErrPolicyManagedByIDP", err)
	}
}

// With the mapping gone nothing recomputes the policy any more; the edit converts it
// to local and applies, so no account is left that an administrator cannot edit.
func TestUpdatePolicyOfAnIdPUserConvertsItWhenNoMappingIsConfigured(t *testing.T) {
	fixture := newAdminFixture(t, app.AdminUsersConfig{OIDCIssuer: inviteIssuer})
	target := idpUser()
	fixture.users.EXPECT().ByID(mock.Anything, target.ID).Return(target, nil)

	var change app.AdminChange

	fixture.users.EXPECT().UpdateAdminState(mock.Anything, target.ID, mock.Anything).RunAndReturn(func(_ context.Context, _ uuid.UUID, ch app.AdminChange) error {
		change = ch

		return nil
	})
	fixture.viewAfterUpdate(target)
	events := fixture.recordAudit()

	rules := []string{"beta:model-*"}
	if _, err := fixture.svc.UpdateUser(context.Background(), newAdmin(), target.ID, app.UserChanges{Policy: &rules}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	if change.Policy == nil || !change.Policy.Allows("beta", "model-x") || change.Policy.Allows("alpha", "model-x") {
		t.Fatalf("written policy = %v, want exactly beta:model-*", change.Policy)
	}

	if change.RefuseIDPPolicy {
		t.Fatal("the write refuses an idp policy although no mapping owns it")
	}

	if (*events)[0].Detail["policy_source"] != "local" {
		t.Fatalf("audit detail = %v, want the conversion recorded", (*events)[0].Detail)
	}
}

// A block is a revocation: the sessions go, and only after the block is written, so
// a session opened in between cannot survive it.
func TestBlockingAUserDeletesTheirSessions(t *testing.T) {
	fixture := newAdminFixture(t, app.AdminUsersConfig{})
	target := newPerson()
	fixture.users.EXPECT().ByID(mock.Anything, target.ID).Return(target, nil)

	var calls []string

	fixture.users.EXPECT().UpdateAdminState(mock.Anything, target.ID, mock.Anything).RunAndReturn(func(_ context.Context, _ uuid.UUID, ch app.AdminChange) error {
		if ch.Status == nil || *ch.Status != identity.StatusBlocked {
			t.Errorf("written status %v, want blocked", ch.Status)
		}

		calls = append(calls, "write")

		return nil
	})
	fixture.sessions.EXPECT().DeleteByUser(mock.Anything, target.ID).RunAndReturn(func(context.Context, uuid.UUID) error {
		calls = append(calls, "delete sessions")

		return nil
	})
	fixture.viewAfterUpdate(target)
	fixture.recordAudit()

	blocked := identity.StatusBlocked
	if _, err := fixture.svc.UpdateUser(context.Background(), newAdmin(), target.ID, app.UserChanges{Status: &blocked}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	if !slices.Equal(calls, []string{"write", "delete sessions"}) {
		t.Fatalf("calls = %v, want the block written before the sessions are deleted", calls)
	}
}

// A rename writes the name and nothing else — a status or policy copied from an
// earlier read would undo a concurrent block — and leaves the user signed in: the
// strict session mock has no DeleteByUser expectation.
func TestRenameWritesOnlyTheNameAndKeepsSessions(t *testing.T) {
	fixture := newAdminFixture(t, app.AdminUsersConfig{})
	target := newPerson()
	fixture.users.EXPECT().ByID(mock.Anything, target.ID).Return(target, nil)

	var change app.AdminChange

	fixture.users.EXPECT().UpdateAdminState(mock.Anything, target.ID, mock.Anything).RunAndReturn(func(_ context.Context, _ uuid.UUID, ch app.AdminChange) error {
		change = ch

		return nil
	})
	fixture.viewAfterUpdate(target)
	fixture.recordAudit()

	name := " Renamed "
	if _, err := fixture.svc.UpdateUser(context.Background(), newAdmin(), target.ID, app.UserChanges{DisplayName: &name}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	if change.DisplayName == nil || *change.DisplayName != "Renamed" {
		t.Fatalf("written name = %v, want %q", change.DisplayName, "Renamed")
	}

	if change.Role != nil || change.Status != nil || change.Policy != nil {
		t.Fatalf("a rename wrote other fields: %+v", change)
	}
}

func TestAnAdministratorCannotLockThemselvesOut(t *testing.T) {
	blocked, demoted := identity.StatusBlocked, identity.RoleUser
	for name, ch := range map[string]app.UserChanges{
		"block self":  {Status: &blocked},
		"demote self": {Role: &demoted},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAdminFixture(t, app.AdminUsersConfig{})

			admin := newAdmin()
			if _, err := f.svc.UpdateUser(context.Background(), admin, admin.ID, ch); !errors.Is(err, app.ErrSelfLockout) {
				t.Fatalf("err = %v, want ErrSelfLockout", err)
			}
		})
	}
}

func TestRenewInvitationRefusesWhatNobodyCouldRedeem(t *testing.T) {
	noEmail := newPerson()

	noEmail.Email = ""
	for name, tc := range map[string]struct {
		issuer string
		user   *identity.User
	}{
		"OIDC not configured": {"", nil},
		"service account":     {inviteIssuer, &identity.User{ID: uuid.New(), Kind: identity.KindService}},
		"no address":          {inviteIssuer, &noEmail},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newAdminFixture(t, app.AdminUsersConfig{OIDCIssuer: tc.issuer})

			id := uuid.New()
			if tc.user != nil {
				id = tc.user.ID
				fixture.users.EXPECT().ByID(mock.Anything, id).Return(*tc.user, nil)
			}

			if err := fixture.svc.RenewInvitation(context.Background(), newAdmin(), id); !errors.Is(err, app.ErrNotInvitable) {
				t.Fatalf("err = %v, want ErrNotInvitable", err)
			}
		})
	}
}

// The linked-account refusal is the repository's, decided inside the write; the
// service passes it on and records nothing.
func TestRenewInvitationOfALinkedAccountIsAlreadyLinked(t *testing.T) {
	f := newAdminFixture(t, app.AdminUsersConfig{OIDCIssuer: inviteIssuer})
	target := newPerson()
	f.users.EXPECT().ByID(mock.Anything, target.ID).Return(target, nil)
	f.idents.EXPECT().Invite(mock.Anything, target.ID, mock.Anything).Return(app.ErrAlreadyLinked)

	if err := f.svc.RenewInvitation(context.Background(), newAdmin(), target.ID); !errors.Is(err, app.ErrAlreadyLinked) {
		t.Fatalf("err = %v, want ErrAlreadyLinked", err)
	}
}

func TestRenewInvitationInvitesTheAccountsAddressForTheExactIssuer(t *testing.T) {
	fixture := newAdminFixture(t, app.AdminUsersConfig{OIDCIssuer: inviteIssuer})
	target := newPerson()
	fixture.users.EXPECT().ByID(mock.Anything, target.ID).Return(target, nil)
	want := app.Invitation{Issuer: inviteIssuer, Email: target.Email, ExpiresAt: frozen.Add(app.InvitationTTL)}
	fixture.idents.EXPECT().Invite(mock.Anything, target.ID, want).Return(nil)
	events := fixture.recordAudit()

	if err := fixture.svc.RenewInvitation(context.Background(), newAdmin(), target.ID); err != nil {
		t.Fatalf("RenewInvitation: %v", err)
	}

	if e := (*events)[0]; e.Action != "user.invitation.renew" || e.Target != target.ID.String() {
		t.Fatalf("audit = %+v, want user.invitation.renew on the account", e)
	}
}

func TestResetPasswordIssuesATemporaryPasswordAndEndsSessions(t *testing.T) {
	fixture := newAdminFixture(t, app.AdminUsersConfig{})
	target := newPerson()
	fixture.users.EXPECT().ByID(mock.Anything, target.ID).Return(target, nil)

	var (
		calls        []string
		storedHash   string
		storedExpiry *time.Time
	)

	fixture.users.EXPECT().SetMustChangePassword(mock.Anything, target.ID, true).RunAndReturn(func(context.Context, uuid.UUID, bool) error {
		calls = append(calls, "restrict")

		return nil
	})
	fixture.passwords.EXPECT().Set(mock.Anything, target.ID, mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, _ uuid.UUID, hash string, exp *time.Time) error {
			calls = append(calls, "password")
			storedHash, storedExpiry = hash, exp

			return nil
		})
	fixture.sessions.EXPECT().DeleteByUser(mock.Anything, target.ID).Return(nil)
	events := fixture.recordAudit()

	temp, err := fixture.svc.ResetPassword(context.Background(), newAdmin(), target.ID)
	if err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	if !identity.VerifyPassword(storedHash, temp.Password) {
		t.Fatal("the stored hash does not verify the returned password")
	}

	if want := frozen.Add(72 * time.Hour); storedExpiry == nil || !storedExpiry.Equal(want) || !temp.ExpiresAt.Equal(want) {
		t.Fatalf("expiry stored %v, returned %v, want %v", storedExpiry, temp.ExpiresAt, want)
	}
	// Restricted first: the other order lets the new password open an unrestricted
	// session in between.
	if !slices.Equal(calls, []string{"restrict", "password"}) {
		t.Fatalf("calls = %v, want the restriction before the password", calls)
	}

	assertNoSecret(t, *events, temp.Password, storedHash)
}

func TestResetPasswordOfAServiceAccountIsNotLocal(t *testing.T) {
	f := newAdminFixture(t, app.AdminUsersConfig{})
	svc := identity.NewService(uuid.New(), "chat-panel", access.Policy{})
	f.users.EXPECT().ByID(mock.Anything, svc.ID).Return(svc, nil)

	if _, err := f.svc.ResetPassword(context.Background(), newAdmin(), svc.ID); !errors.Is(err, app.ErrNotLocal) {
		t.Fatalf("err = %v, want ErrNotLocal", err)
	}
}

// Issuance on behalf goes through the label rule: nothing is minted under a label it
// refuses. The rule's boundaries are the domain's test.
func TestIssueTokenRefusesALabelTheRuleForbids(t *testing.T) {
	f := newAdminFixture(t, app.AdminUsersConfig{})
	owner := identity.NewService(uuid.New(), "chat-panel", access.Policy{})
	f.users.EXPECT().ByID(mock.Anything, owner.ID).Return(owner, nil)

	_, secret, err := f.svc.IssueToken(context.Background(), newAdmin(), owner.ID, "panel\nforged log line")
	if !errors.Is(err, credentials.ErrInvalidLabel) {
		t.Fatalf("err = %v, want ErrInvalidLabel", err)
	}

	if secret != "" {
		t.Fatal("a secret was returned for a refused label")
	}
}

// The path names the owner: a real token of another account is not found there, and
// is not revoked.
func TestRevokeTokenOfAnotherAccountIsNotFound(t *testing.T) {
	fixture := newAdminFixture(t, app.AdminUsersConfig{})
	owner, other := uuid.New(), uuid.New()

	own, _, err := credentials.Generate(owner, "laptop")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	foreign, _, err := credentials.Generate(other, "desktop")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	fixture.tokens.EXPECT().ListByUser(mock.Anything, owner).Return([]credentials.Token{own}, nil)

	if err := fixture.svc.RevokeToken(context.Background(), newAdmin(), owner, foreign.ID); !errors.Is(err, app.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestActivityBoundsThePageSize(t *testing.T) {
	for asked, want := range map[int]int{0: app.DefaultActivityLimit, 1: 1, 200: 200, 201: app.MaxActivityLimit} {
		fixture := newAdminFixture(t, app.AdminUsersConfig{})
		target := newPerson()
		fixture.users.EXPECT().ByID(mock.Anything, target.ID).Return(target, nil)
		fixture.activity.EXPECT().RecentUsage(mock.Anything, target.ID, want).Return(nil, nil)
		fixture.activity.EXPECT().RecentAudit(mock.Anything, target.ID, want).Return(nil, nil)

		if _, err := fixture.svc.Activity(context.Background(), newAdmin(), target.ID, asked); err != nil {
			t.Fatalf("Activity(limit %d): %v", asked, err)
		}
	}
}

// The preview applies the gate's rule: a model two providers serve is covered only
// when both are allowed, and then under both. Allowing one of them covers only what
// that one serves alone.
func TestPolicyPreviewAgreesWithTheGateOnAModelServedByTwoProviders(t *testing.T) {
	fixture := newAdminFixture(t, app.AdminUsersConfig{})
	fixture.catalog.EXPECT().Models().Return(map[string][]string{
		"alpha": {"shared-model", "solo"},
		"beta":  {"shared-model"},
	})
	fixture.catalog.EXPECT().ProvidersFor("shared-model").Return([]string{"alpha", "beta"})
	fixture.catalog.EXPECT().ProvidersFor("solo").Return([]string{"alpha"})

	admin := newAdmin()

	one, err := fixture.svc.PolicyPreview(admin, []string{"alpha:*", "not a rule"})
	if err != nil {
		t.Fatalf("PolicyPreview: %v", err)
	}

	if want := []app.CoveredModel{{Provider: "alpha", Model: "solo"}}; !slices.Equal(one.Covered, want) {
		t.Fatalf("covered = %v, want %v: shared-model is also served by beta", one.Covered, want)
	}

	if !slices.Equal(one.Invalid, []string{"not a rule"}) {
		t.Fatalf("invalid = %v, want the one rule that does not parse", one.Invalid)
	}

	both, err := fixture.svc.PolicyPreview(admin, []string{"alpha:*", "beta:*"})
	if err != nil {
		t.Fatalf("PolicyPreview: %v", err)
	}

	want := []app.CoveredModel{
		{Provider: "alpha", Model: "shared-model"},
		{Provider: "alpha", Model: "solo"},
		{Provider: "beta", Model: "shared-model"},
	}
	if !slices.Equal(both.Covered, want) || len(both.Invalid) != 0 {
		t.Fatalf("preview = %+v, want covered %v and no errors", both, want)
	}
}
