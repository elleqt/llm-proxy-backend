package adminusers_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/adminusers"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/app/tokens"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const inviteIssuer = "https://idp.example.com/realms/demo/"

// adminFixture wires adminusers.Service to strict mocks: a repository call a test did not
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
	svc       *adminusers.Service
}

func newAdminFixture(t *testing.T, cfg adminusers.Config) *adminFixture {
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
	tokenSvc := tokens.New(fixture.users, fixture.tokens, fixture.audit, clock, discardLogger{})
	fixture.svc = adminusers.New(fixture.users, fixture.passwords, fixture.idents, fixture.sessions, fixture.activity,
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
		require.NoError(t, err, "marshal detail")

		for _, s := range secrets {
			if s != "" {
				require.NotContains(t, string(raw)+event.Target, s, "audit event %s carries a secret", event.Action)
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

	ops := map[string]func(*adminusers.Service, identity.User) error{
		"ListUsers": func(s *adminusers.Service, a identity.User) error {
			_, err := s.ListUsers(ctx, a)

			return err
		},
		"GetUser": func(s *adminusers.Service, a identity.User) error {
			_, err := s.GetUser(ctx, a, target)

			return err
		},
		"CreateUser": func(s *adminusers.Service, a identity.User) error {
			_, err := s.CreateUser(ctx, a, adminusers.NewUser{Kind: identity.KindService, DisplayName: "bot"})

			return err
		},
		"UpdateUser": func(s *adminusers.Service, a identity.User) error {
			_, err := s.UpdateUser(ctx, a, target, adminusers.UserChanges{DisplayName: &name})

			return err
		},
		"RenewInvitation": func(s *adminusers.Service, a identity.User) error { return s.RenewInvitation(ctx, a, target) },
		"ResetPassword": func(s *adminusers.Service, a identity.User) error {
			_, err := s.ResetPassword(ctx, a, target)

			return err
		},
		"ListTokens": func(s *adminusers.Service, a identity.User) error {
			_, err := s.ListTokens(ctx, a, target)

			return err
		},
		"IssueToken": func(s *adminusers.Service, a identity.User) error {
			_, _, err := s.IssueToken(ctx, a, target, "label")

			return err
		},
		"RevokeToken": func(s *adminusers.Service, a identity.User) error { return s.RevokeToken(ctx, a, target, uuid.New()) },
		"Activity": func(s *adminusers.Service, a identity.User) error {
			_, err := s.Activity(ctx, a, target, 10)

			return err
		},
		"Catalog": func(s *adminusers.Service, a identity.User) error {
			_, err := s.Catalog(a)

			return err
		},
		"PolicyPreview": func(s *adminusers.Service, a identity.User) error {
			_, err := s.PolicyPreview(a, []string{"alpha:*"})

			return err
		},
	}
	for actorName, actor := range actors {
		for opName, op := range ops {
			t.Run(actorName+"/"+opName, func(t *testing.T) {
				f := newAdminFixture(t, adminusers.Config{OIDCIssuer: inviteIssuer})
				require.ErrorIs(t, op(f.svc, actor), app.ErrForbidden)
			})
		}
	}
}

func TestCreateHumanWithPasswordShowsTheTemporaryPasswordOnce(t *testing.T) {
	f := newAdminFixture(t, adminusers.Config{})
	acct := f.captureAccount()
	admin := newAdmin()

	out, err := f.svc.CreateUser(context.Background(), admin, adminusers.NewUser{
		Kind: identity.KindHuman, Email: "Person@Example.com", DisplayName: " Person ",
		Policy: []string{"alpha:*"}, SignIn: app.SignInPassword,
	})
	require.NoError(t, err, "CreateUser")

	temp, created := out.TemporaryPassword, acct.User
	require.NotNil(t, temp, "no temporary password for a human with a local password")
	require.NotEmpty(t, temp.Password, "no temporary password for a human with a local password")
	require.NotNil(t, acct.Password, "no password stored for a human with a local password")
	require.True(t, identity.VerifyPassword(acct.Password.Hash, temp.Password),
		"the stored hash does not verify the returned password")

	wantExpiry := frozen.Add(72 * time.Hour)
	exp := acct.Password.ExpiresAt
	require.NotNil(t, exp, "stored expiry")
	require.True(t, exp.Equal(wantExpiry), "expiry stored %v, want %v", exp, wantExpiry)
	require.True(t, temp.ExpiresAt.Equal(wantExpiry), "expiry returned %v, want %v", temp.ExpiresAt, wantExpiry)
	require.True(t, created.MustChangePassword, "the account does not have to change its temporary password")
	require.True(t, out.User.User.MustChangePassword, "the returned view does not have to change its temporary password")
	require.Nil(t, acct.Invitation, "a password account was also invited")
	// A random id: never derived, never chosen by a caller.
	require.Equal(t, uuid.Version(4), created.ID.Version(), "id %s, want a random v4 id", created.ID)
	require.Equal(t, "Person", created.DisplayName, "created display name")
	require.Equal(t, "Person@Example.com", created.Email, "created email")
	require.Equal(t, identity.RoleUser, created.Role, "created role")
	require.Equal(t, []app.SignInMethod{app.SignInPassword}, out.User.SignIn, "sign-in")
	// The audit record is committed with the account, not written beside it.
	require.Equal(t, "user.create", acct.Audit.Action, "audit action")
	require.Equal(t, created.ID.String(), acct.Audit.Target, "audit target, want the new account")
	require.Equal(t, admin.ID, acct.Audit.ActorID, "audit actor, want the admin")

	assertNoSecret(t, []app.AuditEvent{acct.Audit}, temp.Password, acct.Password.Hash)
}

// A creation that did not commit hands out nothing.
func TestCreateUserWithholdsThePasswordWhenTheWriteFails(t *testing.T) {
	f := newAdminFixture(t, adminusers.Config{})
	boom := errors.New("transaction rolled back")
	f.users.EXPECT().CreateAccount(mock.Anything, mock.Anything).Return(boom)

	out, err := f.svc.CreateUser(context.Background(), newAdmin(), adminusers.NewUser{
		Kind: identity.KindHuman, Email: "person@example.com", DisplayName: "Person", SignIn: app.SignInPassword,
	})
	require.ErrorIs(t, err, boom, "want the write failure")
	require.Nil(t, out.TemporaryPassword, "a temporary password was handed out for an account that was not stored")
}

// The invitation is written for exactly the configured issuer: PendingByEmail
// matches it byte for byte, so a trailing slash lost here is an invitation nobody
// can redeem. No password is stored, and a pending invitation is not a way in yet.
func TestCreateHumanWithOIDCRecordsAnInvitationForTheExactIssuer(t *testing.T) {
	f := newAdminFixture(t, adminusers.Config{OIDCIssuer: inviteIssuer})
	acct := f.captureAccount()

	out, err := f.svc.CreateUser(context.Background(), newAdmin(), adminusers.NewUser{
		Kind: identity.KindHuman, Email: "Person@Example.com", DisplayName: "Person", SignIn: app.SignInOIDC,
	})
	require.NoError(t, err, "CreateUser")

	want := app.Invitation{Issuer: inviteIssuer, Email: "Person@Example.com", ExpiresAt: frozen.Add(adminusers.InvitationTTL)}

	require.NotNil(t, acct.Invitation, "no invitation recorded")
	require.Equal(t, want, *acct.Invitation, "invitation")
	require.Nil(t, acct.Password, "an invited account got a password")
	require.Nil(t, out.TemporaryPassword, "an invited account got a temporary password")
	require.False(t, acct.User.MustChangePassword, "an invited account must change a password")
	require.Empty(t, out.User.SignIn, "view: want no working sign-in")
	require.NotNil(t, out.User.InvitationExpiresAt, "view: want the invitation's expiry")
	require.True(t, out.User.InvitationExpiresAt.Equal(want.ExpiresAt),
		"view invitation expiry %v, want %v", out.User.InvitationExpiresAt, want.ExpiresAt)
}

// Without an issuer there is nobody to redeem the invitation: refused before any write.
func TestCreateHumanWithOIDCRefusedWhenOIDCIsOff(t *testing.T) {
	f := newAdminFixture(t, adminusers.Config{})
	_, err := f.svc.CreateUser(context.Background(), newAdmin(), adminusers.NewUser{
		Kind: identity.KindHuman, Email: "person@example.com", DisplayName: "Person", SignIn: app.SignInOIDC,
	})

	var invalid *app.InvalidInputError
	require.ErrorAs(t, err, &invalid)
	require.Equal(t, "signIn", invalid.Field, "invalid field")
}

func TestCreateServiceAccountGetsNoPasswordAndNoIdentity(t *testing.T) {
	f := newAdminFixture(t, adminusers.Config{OIDCIssuer: inviteIssuer})
	acct := f.captureAccount()

	// SignIn is ignored for a service account.
	out, err := f.svc.CreateUser(context.Background(), newAdmin(), adminusers.NewUser{
		Kind: identity.KindService, DisplayName: "chat-panel", Policy: []string{"alpha:*"}, SignIn: app.SignInOIDC,
	})
	require.NoError(t, err, "CreateUser")
	require.Nil(t, acct.Password, "service account got a password")
	require.Nil(t, acct.Invitation, "service account got an invitation")
	require.Nil(t, out.TemporaryPassword, "service account got a temporary password")
	require.Empty(t, out.User.SignIn, "service account got a way in")

	created := acct.User
	require.Equal(t, identity.KindService, created.Kind, "created kind")
	require.Empty(t, created.Email, "created email")
	require.Equal(t, uuid.Version(4), created.ID.Version(), "id %s, want a random v4 id", created.ID)
}

func TestUpdateUserReportsTheFirstInvalidRule(t *testing.T) {
	f := newAdminFixture(t, adminusers.Config{})
	rules := []string{"alpha:*", "no-colon", ":no-provider"}
	_, err := f.svc.UpdateUser(context.Background(), newAdmin(), uuid.New(), adminusers.UserChanges{Policy: &rules})

	var invalid *app.InvalidRuleError
	require.ErrorAs(t, err, &invalid)
	require.Equal(t, "no-colon", invalid.Rule, "want the first bad rule")
}

func idpUser() identity.User {
	u := newPerson()
	u.PolicySource = identity.PolicyIDP

	return u
}

func TestUpdatePolicyOfAnIdPUserRefusedWhileTheMappingIsConfigured(t *testing.T) {
	fixture := newAdminFixture(t, adminusers.Config{OIDCIssuer: inviteIssuer, GroupMappingConfigured: true})
	target := idpUser()
	fixture.users.EXPECT().ByID(mock.Anything, target.ID).Return(target, nil)

	rules := []string{"alpha:*"}

	_, err := fixture.svc.UpdateUser(context.Background(), newAdmin(), target.ID, adminusers.UserChanges{Policy: &rules})
	require.ErrorIs(t, err, app.ErrPolicyManagedByIDP)
}

// With the mapping gone nothing recomputes the policy any more; the edit converts it
// to local and applies, so no account is left that an administrator cannot edit.
func TestUpdatePolicyOfAnIdPUserConvertsItWhenNoMappingIsConfigured(t *testing.T) {
	fixture := newAdminFixture(t, adminusers.Config{OIDCIssuer: inviteIssuer})
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
	_, err := fixture.svc.UpdateUser(context.Background(), newAdmin(), target.ID, adminusers.UserChanges{Policy: &rules})
	require.NoError(t, err, "UpdateUser")
	require.NotNil(t, change.Policy, "no policy written")
	require.True(t, change.Policy.Allows("beta", "model-x"), "written policy %v, want exactly beta:model-*", change.Policy)
	require.False(t, change.Policy.Allows("alpha", "model-x"), "written policy %v, want exactly beta:model-*", change.Policy)
	require.False(t, change.RefuseIDPPolicy, "the write refuses an idp policy although no mapping owns it")
	require.NotEmpty(t, *events, "nothing was audited")
	require.Equal(t, "local", (*events)[0].Detail["policy_source"], "audit detail, want the conversion recorded")
}

// A block is a revocation: the sessions go, and only after the block is written, so
// a session opened in between cannot survive it.
func TestBlockingAUserDeletesTheirSessions(t *testing.T) {
	fixture := newAdminFixture(t, adminusers.Config{})
	target := newPerson()
	fixture.users.EXPECT().ByID(mock.Anything, target.ID).Return(target, nil)

	var calls []string

	fixture.users.EXPECT().UpdateAdminState(mock.Anything, target.ID, mock.Anything).RunAndReturn(func(_ context.Context, _ uuid.UUID, ch app.AdminChange) error {
		require.NotNil(t, ch.Status, "no status written")
		require.Equal(t, identity.StatusBlocked, *ch.Status, "written status")

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
	_, err := fixture.svc.UpdateUser(context.Background(), newAdmin(), target.ID, adminusers.UserChanges{Status: &blocked})
	require.NoError(t, err, "UpdateUser")
	require.Equal(t, []string{"write", "delete sessions"}, calls, "want the block written before the sessions are deleted")
}

// A rename writes the name and nothing else — a status or policy copied from an
// earlier read would undo a concurrent block — and leaves the user signed in: the
// strict session mock has no DeleteByUser expectation.
func TestRenameWritesOnlyTheNameAndKeepsSessions(t *testing.T) {
	fixture := newAdminFixture(t, adminusers.Config{})
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
	_, err := fixture.svc.UpdateUser(context.Background(), newAdmin(), target.ID, adminusers.UserChanges{DisplayName: &name})
	require.NoError(t, err, "UpdateUser")
	require.NotNil(t, change.DisplayName, "no name written")
	require.Equal(t, "Renamed", *change.DisplayName, "written name")
	require.Nil(t, change.Role, "a rename wrote the role")
	require.Nil(t, change.Status, "a rename wrote the status")
	require.Nil(t, change.Policy, "a rename wrote the policy")
}

func TestAnAdministratorCannotLockThemselvesOut(t *testing.T) {
	blocked, demoted := identity.StatusBlocked, identity.RoleUser
	for name, ch := range map[string]adminusers.UserChanges{
		"block self":  {Status: &blocked},
		"demote self": {Role: &demoted},
	} {
		t.Run(name, func(t *testing.T) {
			f := newAdminFixture(t, adminusers.Config{})

			admin := newAdmin()
			_, err := f.svc.UpdateUser(context.Background(), admin, admin.ID, ch)
			require.ErrorIs(t, err, app.ErrSelfLockout)
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
			fixture := newAdminFixture(t, adminusers.Config{OIDCIssuer: tc.issuer})

			id := uuid.New()
			if tc.user != nil {
				id = tc.user.ID
				fixture.users.EXPECT().ByID(mock.Anything, id).Return(*tc.user, nil)
			}

			require.ErrorIs(t, fixture.svc.RenewInvitation(context.Background(), newAdmin(), id), app.ErrNotInvitable)
		})
	}
}

// The linked-account refusal is the repository's, decided inside the write; the
// service passes it on and records nothing.
func TestRenewInvitationOfALinkedAccountIsAlreadyLinked(t *testing.T) {
	f := newAdminFixture(t, adminusers.Config{OIDCIssuer: inviteIssuer})
	target := newPerson()
	f.users.EXPECT().ByID(mock.Anything, target.ID).Return(target, nil)
	f.idents.EXPECT().Invite(mock.Anything, target.ID, mock.Anything).Return(app.ErrAlreadyLinked)

	require.ErrorIs(t, f.svc.RenewInvitation(context.Background(), newAdmin(), target.ID), app.ErrAlreadyLinked)
}

func TestRenewInvitationInvitesTheAccountsAddressForTheExactIssuer(t *testing.T) {
	fixture := newAdminFixture(t, adminusers.Config{OIDCIssuer: inviteIssuer})
	target := newPerson()
	fixture.users.EXPECT().ByID(mock.Anything, target.ID).Return(target, nil)
	want := app.Invitation{Issuer: inviteIssuer, Email: target.Email, ExpiresAt: frozen.Add(adminusers.InvitationTTL)}
	fixture.idents.EXPECT().Invite(mock.Anything, target.ID, want).Return(nil)
	events := fixture.recordAudit()

	require.NoError(t, fixture.svc.RenewInvitation(context.Background(), newAdmin(), target.ID), "RenewInvitation")
	require.NotEmpty(t, *events, "nothing was audited")
	require.Equal(t, "user.invitation.renew", (*events)[0].Action, "audit action")
	require.Equal(t, target.ID.String(), (*events)[0].Target, "audit target, want the account")
}

func TestResetPasswordIssuesATemporaryPasswordAndEndsSessions(t *testing.T) {
	fixture := newAdminFixture(t, adminusers.Config{})
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
	require.NoError(t, err, "ResetPassword")
	require.True(t, identity.VerifyPassword(storedHash, temp.Password), "the stored hash does not verify the returned password")

	want := frozen.Add(72 * time.Hour)

	require.NotNil(t, storedExpiry, "stored expiry")
	require.True(t, storedExpiry.Equal(want), "expiry stored %v, want %v", storedExpiry, want)
	require.True(t, temp.ExpiresAt.Equal(want), "expiry returned %v, want %v", temp.ExpiresAt, want)
	// Restricted first: the other order lets the new password open an unrestricted
	// session in between.
	require.Equal(t, []string{"restrict", "password"}, calls, "want the restriction before the password")

	assertNoSecret(t, *events, temp.Password, storedHash)
}

func TestResetPasswordOfAServiceAccountIsNotLocal(t *testing.T) {
	f := newAdminFixture(t, adminusers.Config{})
	svc := identity.NewService(uuid.New(), "chat-panel", access.Policy{})
	f.users.EXPECT().ByID(mock.Anything, svc.ID).Return(svc, nil)

	_, err := f.svc.ResetPassword(context.Background(), newAdmin(), svc.ID)
	require.ErrorIs(t, err, app.ErrNotLocal)
}

// Issuance on behalf goes through the label rule: nothing is minted under a label it
// refuses. The rule's boundaries are the domain's test.
func TestIssueTokenRefusesALabelTheRuleForbids(t *testing.T) {
	f := newAdminFixture(t, adminusers.Config{})
	owner := identity.NewService(uuid.New(), "chat-panel", access.Policy{})
	f.users.EXPECT().ByID(mock.Anything, owner.ID).Return(owner, nil)

	_, secret, err := f.svc.IssueToken(context.Background(), newAdmin(), owner.ID, "panel\nforged log line")
	require.ErrorIs(t, err, credentials.ErrInvalidLabel)
	require.Empty(t, secret, "a secret was returned for a refused label")
}

// The path names the owner: a real token of another account is not found there, and
// is not revoked.
func TestRevokeTokenOfAnotherAccountIsNotFound(t *testing.T) {
	fixture := newAdminFixture(t, adminusers.Config{})
	owner, other := uuid.New(), uuid.New()

	own, _, err := credentials.Generate(owner, "laptop")
	require.NoError(t, err, "Generate")

	foreign, _, err := credentials.Generate(other, "desktop")
	require.NoError(t, err, "Generate")

	fixture.tokens.EXPECT().ListByUser(mock.Anything, owner).Return([]credentials.Token{own}, nil)

	err = fixture.svc.RevokeToken(context.Background(), newAdmin(), owner, foreign.ID)
	require.ErrorIs(t, err, app.ErrNotFound)
}

func TestActivityBoundsThePageSize(t *testing.T) {
	for asked, want := range map[int]int{0: adminusers.DefaultActivityLimit, 1: 1, 200: 200, 201: adminusers.MaxActivityLimit} {
		fixture := newAdminFixture(t, adminusers.Config{})
		target := newPerson()
		fixture.users.EXPECT().ByID(mock.Anything, target.ID).Return(target, nil)
		fixture.activity.EXPECT().RecentUsage(mock.Anything, target.ID, want).Return(nil, nil)
		fixture.activity.EXPECT().RecentAudit(mock.Anything, target.ID, want).Return(nil, nil)

		_, err := fixture.svc.Activity(context.Background(), newAdmin(), target.ID, asked)
		require.NoError(t, err, "Activity(limit %d)", asked)
	}
}

// The preview applies the gate's rule: a model two providers serve is covered only
// when both are allowed, and then under both. Allowing one of them covers only what
// that one serves alone.
func TestPolicyPreviewAgreesWithTheGateOnAModelServedByTwoProviders(t *testing.T) {
	fixture := newAdminFixture(t, adminusers.Config{})
	fixture.catalog.EXPECT().Models().Return(map[string][]string{
		"alpha": {"shared-model", "solo"},
		"beta":  {"shared-model"},
	})
	fixture.catalog.EXPECT().ProvidersFor("shared-model").Return([]string{"alpha", "beta"})
	fixture.catalog.EXPECT().ProvidersFor("solo").Return([]string{"alpha"})

	admin := newAdmin()

	one, err := fixture.svc.PolicyPreview(admin, []string{"alpha:*", "not a rule"})
	require.NoError(t, err, "PolicyPreview")
	require.Equal(t, []adminusers.CoveredModel{{Provider: "alpha", Model: "solo"}}, one.Covered,
		"covered: shared-model is also served by beta")
	require.Equal(t, []string{"not a rule"}, one.Invalid, "invalid: want the one rule that does not parse")

	both, err := fixture.svc.PolicyPreview(admin, []string{"alpha:*", "beta:*"})
	require.NoError(t, err, "PolicyPreview")

	want := []adminusers.CoveredModel{
		{Provider: "alpha", Model: "shared-model"},
		{Provider: "alpha", Model: "solo"},
		{Provider: "beta", Model: "shared-model"},
	}
	require.Equal(t, want, both.Covered, "covered")
	require.Empty(t, both.Invalid, "want no errors")
}
