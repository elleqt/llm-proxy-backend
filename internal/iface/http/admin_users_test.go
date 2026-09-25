package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func mustPolicy(t *testing.T, rules ...string) access.Policy {
	t.Helper()

	policy := make(access.Policy, 0, len(rules))
	for _, s := range rules {
		r, err := access.ParseRule(s)
		require.NoError(t, err, "ParseRule %q", s)

		policy = append(policy, r)
	}

	return policy
}

// wantField asserts an Error names field.
func wantField(t *testing.T, e api.Error, field string) {
	t.Helper()

	require.NotNil(t, e.Field, "the error names no field; want %q", field)
	require.Equal(t, field, *e.Field, "field")
}

func TestListUsersDescribesEveryAccount(t *testing.T) {
	env := newEnv(t)
	human := person("person@example.com")
	human.Policy = mustPolicy(t, "claude:*")
	human.CreatedAt = env.clock.Now().Add(-48 * time.Hour)
	seen := env.clock.Now().Add(-time.Minute)
	human.LastSeenAt = &seen
	bot := identity.NewService(uuid.New(), "CI bot", nil)
	invited := person("invited@example.com")
	lapsed := env.clock.Now().Add(-time.Hour)
	env.users.EXPECT().List(mock.Anything).Return([]app.UserView{
		{User: human, SignIn: []app.SignInMethod{app.SignInPassword, app.SignInOIDC}},
		{User: bot, SignIn: []app.SignInMethod{}},
		{User: invited, SignIn: []app.SignInMethod{}, InvitationExpiresAt: &lapsed},
	}, nil)

	var got []api.AdminUser
	decodeBody(t, env.do(http.MethodGet, "/api/admin/users", "", withCookie(env.signedIn(admin()))), http.StatusOK, &got)

	require.Len(t, got, 3, "accounts")

	personRow, serviceRow, invitedRow := got[0], got[1], got[2]
	require.Equal(t, human.ID, personRow.Id, "person id")
	require.NotNil(t, personRow.Email, "person email")
	require.Equal(t, human.Email, *personRow.Email, "person email")
	require.Equal(t, api.Human, personRow.Kind, "person kind")
	require.Equal(t, api.Active, personRow.Status, "person status")
	require.Equal(t, []string{"claude:*"}, personRow.Policy, "person policy")
	require.Equal(t, []api.AdminUserSignIn{api.AdminUserSignInPassword, api.AdminUserSignInOidc}, personRow.SignIn, "person sign-in")
	require.NotNil(t, personRow.LastSeenAt, "person last seen")
	require.True(t, personRow.LastSeenAt.Equal(seen), "person last seen = %v, want %v", personRow.LastSeenAt, seen)
	require.True(t, personRow.CreatedAt.Equal(human.CreatedAt), "person created = %v, want %v", personRow.CreatedAt, human.CreatedAt)
	require.Nil(t, personRow.InvitationExpiresAt, "person invitation")

	require.Equal(t, api.Service, serviceRow.Kind, "service account kind")
	require.Nil(t, serviceRow.Email, "service account email")
	require.NotNil(t, serviceRow.SignIn, "service account sign-in must be empty, not null")
	require.Empty(t, serviceRow.SignIn, "service account sign-in")
	require.NotNil(t, serviceRow.Policy, "service account policy must be empty, not null")

	require.NotNil(t, invitedRow.InvitationExpiresAt, "the invited person has no invitation")
	require.True(t, invitedRow.InvitationExpiresAt.Equal(lapsed), "invitation expires = %v, want the lapsed %v",
		invitedRow.InvitationExpiresAt, lapsed)
	require.Empty(t, invitedRow.SignIn, "the invited person has a way in")
}

func TestAnAdminServiceFailureIsInternalAndUndescribed(t *testing.T) {
	e := newEnv(t)
	e.users.EXPECT().List(mock.Anything).Return(nil, errors.New("pq: relation users does not exist"))
	rec := e.do(http.MethodGet, "/api/admin/users", "", withCookie(e.signedIn(admin())))
	apiError(t, rec, http.StatusInternalServerError, codeInternal)

	require.NotContains(t, rec.Body.String(), "relation", "the response describes the failure")
}

// The temporary password is in the response that creates the account and nowhere
// else: reading the account back, alone or in the list, never shows it.
func TestCreatingAPersonShowsTheTemporaryPasswordOnlyThere(t *testing.T) {
	env := newEnv(t)
	cookie := withCookie(env.signedIn(admin()))

	var acct app.NewAccount

	env.users.EXPECT().CreateAccount(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, n app.NewAccount) error {
		acct = n

		return nil
	})

	var out api.CreatedUser
	decodeBody(t, env.do(http.MethodPost, "/api/admin/users",
		`{"kind":"human","email":"new@example.com","displayName":"New Person","policy":["claude:*"],"signIn":"password"}`, cookie),
		http.StatusCreated, &out)

	temp := out.TemporaryPassword
	require.NotNil(t, temp, "no temporary password")
	require.NotNil(t, acct.Password, "no password was stored")
	require.Equal(t, "plain:"+temp.Password, acct.Password.Hash, "the temporary password is not the one whose hash was stored")
	require.True(t, temp.ExpiresAt.Equal(env.clock.Now().Add(app.TemporaryPasswordTTL)),
		"expires at %s, want %s", temp.ExpiresAt, env.clock.Now().Add(app.TemporaryPasswordTTL))

	created := out.User
	require.Equal(t, acct.User.ID, created.Id, "created user id")
	require.NotNil(t, created.Email, "created user email")
	require.Equal(t, "new@example.com", *created.Email, "created user email")
	require.True(t, created.MustChangePassword, "created user must change password")
	require.Equal(t, []api.AdminUserSignIn{api.AdminUserSignInPassword}, created.SignIn, "created user sign-in")
	require.Equal(t, []string{"claude:*"}, created.Policy, "created user policy")

	view := app.UserView{User: acct.User, SignIn: []app.SignInMethod{app.SignInPassword}}
	env.users.EXPECT().View(mock.Anything, acct.User.ID).Return(view, nil)
	env.users.EXPECT().List(mock.Anything).Return([]app.UserView{view}, nil)

	for _, path := range []string{"/api/admin/users/" + acct.User.ID.String(), "/api/admin/users"} {
		rec := env.do(http.MethodGet, path, "", cookie)
		require.Equal(t, http.StatusOK, rec.Code, "GET %s status; body %s", path, rec.Body)
		require.NotContains(t, rec.Body.String(), temp.Password, "GET %s shows the password", path)
		require.NotContains(t, rec.Body.String(), acct.Password.Hash, "GET %s shows the password hash", path)
	}
}

func TestCreatingAServiceAccountIssuesNoPassword(t *testing.T) {
	e := newEnv(t)
	e.users.EXPECT().CreateAccount(mock.Anything, mock.Anything).Return(nil)
	rec := e.do(http.MethodPost, "/api/admin/users", `{"kind":"service","displayName":"CI","policy":[]}`,
		withCookie(e.signedIn(admin())))

	var raw map[string]json.RawMessage
	decodeBody(t, rec, http.StatusCreated, &raw)

	require.NotContains(t, raw, "temporaryPassword", "a service account got a temporary password: %s", rec.Body)
}

func TestCreateUserRefusals(t *testing.T) {
	cases := []struct {
		name, body  string
		setup       func(e *testEnv)
		status      int
		code, field string
	}{
		{
			"address taken", `{"kind":"human","email":"x@example.com","displayName":"X","policy":[],"signIn":"password"}`,
			func(e *testEnv) { e.users.EXPECT().CreateAccount(mock.Anything, mock.Anything).Return(app.ErrConflict) },
			http.StatusConflict, codeEmailTaken, "",
		},
		{
			"unknown kind", `{"kind":"robot","displayName":"X","policy":[]}`, nil,
			http.StatusUnprocessableEntity, codeInvalidInput, "kind",
		},
		{
			"oidc without an identity provider", `{"kind":"human","email":"x@example.com","displayName":"X","policy":[],"signIn":"oidc"}`, nil,
			http.StatusUnprocessableEntity, codeInvalidInput, "signIn",
		},
		{
			"bad rule", `{"kind":"service","displayName":"X","policy":["claude:*","claude"]}`, nil,
			http.StatusUnprocessableEntity, codeInvalidRule, "claude",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			if tc.setup != nil {
				tc.setup(e)
			}

			got := apiError(t, e.do(http.MethodPost, "/api/admin/users", tc.body, withCookie(e.signedIn(admin()))), tc.status, tc.code)
			if tc.field != "" {
				wantField(t, got, tc.field)
			}
		})
	}
}

func TestGetUser(t *testing.T) {
	env := newEnv(t)
	cookie := withCookie(env.signedIn(admin()))
	user := person("p@example.com")
	user.Status = identity.StatusBlocked
	env.users.EXPECT().View(mock.Anything, user.ID).Return(app.UserView{User: user, SignIn: []app.SignInMethod{}}, nil)

	var got api.AdminUser
	decodeBody(t, env.do(http.MethodGet, "/api/admin/users/"+user.ID.String(), "", cookie), http.StatusOK, &got)

	require.Equal(t, user.ID, got.Id, "user id")
	require.Equal(t, api.Blocked, got.Status, "user status")

	unknown := uuid.New()
	env.users.EXPECT().View(mock.Anything, unknown).Return(app.UserView{}, app.ErrNotFound)
	apiError(t, env.do(http.MethodGet, "/api/admin/users/"+unknown.String(), "", cookie), http.StatusNotFound, codeNotFound)
	apiError(t, env.do(http.MethodGet, "/api/admin/users/not-a-uuid", "", cookie), http.StatusNotFound, codeNotFound)
}

func TestUpdateUserAppliesTheEdit(t *testing.T) {
	env := newEnv(t)
	user := person("p@example.com")
	env.users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)

	var change app.AdminChange

	env.users.EXPECT().UpdateAdminState(mock.Anything, user.ID, mock.Anything).RunAndReturn(func(_ context.Context, _ uuid.UUID, ch app.AdminChange) error {
		change = ch

		return nil
	})
	after := user
	after.DisplayName = "Renamed"
	after.Policy = mustPolicy(t, "chatgpt:*")
	env.users.EXPECT().View(mock.Anything, user.ID).Return(app.UserView{User: after, SignIn: []app.SignInMethod{}}, nil)

	var got api.AdminUser
	decodeBody(t, env.do(http.MethodPatch, "/api/admin/users/"+user.ID.String(), `{"displayName":"Renamed","policy":["chatgpt:*"]}`,
		withCookie(env.signedIn(admin()))), http.StatusOK, &got)

	require.NotNil(t, change.DisplayName, "change display name")
	require.Equal(t, "Renamed", *change.DisplayName, "change display name")
	require.NotNil(t, change.Policy, "change policy")
	require.Len(t, *change.Policy, 1, "change policy")
	require.Equal(t, "chatgpt:*", (*change.Policy)[0].String(), "change policy")
	require.Nil(t, change.Role, "the change touches the role")
	require.Nil(t, change.Status, "the change touches the status")

	require.Equal(t, "Renamed", got.DisplayName, "the account as it now stands")
	require.Equal(t, []string{"chatgpt:*"}, got.Policy, "the account as it now stands")
}

func TestUpdateUserRefusals(t *testing.T) {
	idp := person("fed@example.com")
	idp.PolicySource = identity.PolicyIDP

	cases := []struct {
		name        string
		opts        []envOption
		target      func(e *testEnv, self identity.User) uuid.UUID
		body        string
		status      int
		code, field string
	}{
		{
			"blocking oneself", nil,
			func(_ *testEnv, self identity.User) uuid.UUID { return self.ID },
			`{"status":"blocked"}`, http.StatusConflict, codeSelfLockout, "",
		},
		{
			"policy owned by the identity provider",
			[]envOption{withAdminConfig(app.AdminUsersConfig{GroupMappingConfigured: true})},
			func(e *testEnv, _ identity.User) uuid.UUID {
				e.users.EXPECT().ByID(mock.Anything, idp.ID).Return(idp, nil)

				return idp.ID
			},
			`{"policy":["claude:*"]}`, http.StatusConflict, codePolicyManagedByIDP, "",
		},
		{
			"bad rule", nil,
			func(_ *testEnv, _ identity.User) uuid.UUID { return uuid.New() },
			`{"policy":["claude:*",":nothing"]}`, http.StatusUnprocessableEntity, codeInvalidRule, ":nothing",
		},
		{
			"unknown status", nil,
			func(_ *testEnv, _ identity.User) uuid.UUID { return uuid.New() },
			`{"status":"gone"}`, http.StatusUnprocessableEntity, codeInvalidInput, "status",
		},
		{
			"unknown account", nil,
			func(e *testEnv, _ identity.User) uuid.UUID {
				id := uuid.New()
				e.users.EXPECT().ByID(mock.Anything, id).Return(identity.User{}, app.ErrNotFound)

				return id
			},
			`{"displayName":"X"}`, http.StatusNotFound, codeNotFound, "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, tc.opts...)
			self := admin()
			cookie := withCookie(e.signedIn(self))
			id := tc.target(e, self)

			got := apiError(t, e.do(http.MethodPatch, "/api/admin/users/"+id.String(), tc.body, cookie), tc.status, tc.code)
			if tc.field != "" {
				wantField(t, got, tc.field)
			}
		})
	}
}

func TestResetPasswordShowsTheNewPasswordOnlyThere(t *testing.T) {
	env := newEnv(t)
	cookie := withCookie(env.signedIn(admin()))
	user := person("p@example.com")
	env.users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)
	env.users.EXPECT().SetMustChangePassword(mock.Anything, user.ID, true).Return(nil)

	var hash string

	env.pwds.EXPECT().Set(mock.Anything, user.ID, mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, _ uuid.UUID, h string, _ *time.Time) error {
		hash = h

		return nil
	})
	env.sessions.EXPECT().DeleteByUser(mock.Anything, user.ID).Return(nil)

	var temp api.TemporaryPassword
	decodeBody(t, env.do(http.MethodPost, "/api/admin/users/"+user.ID.String()+"/password-reset", "", cookie), http.StatusOK, &temp)

	require.NotEmpty(t, temp.Password, "no temporary password")
	require.Equal(t, "plain:"+temp.Password, hash, "the temporary password is not the one stored")
	require.True(t, temp.ExpiresAt.Equal(env.clock.Now().Add(app.TemporaryPasswordTTL)),
		"expires at %s, want %s", temp.ExpiresAt, env.clock.Now().Add(app.TemporaryPasswordTTL))

	user.MustChangePassword = true
	env.users.EXPECT().View(mock.Anything, user.ID).Return(app.UserView{User: user, SignIn: []app.SignInMethod{app.SignInPassword}}, nil)

	rec := env.do(http.MethodGet, "/api/admin/users/"+user.ID.String(), "", cookie)
	require.Equal(t, http.StatusOK, rec.Code, "GET status; body %s", rec.Body)
	require.NotContains(t, rec.Body.String(), temp.Password, "GET shows the password")
}

func TestResetPasswordOfAServiceAccountIsNotLocal(t *testing.T) {
	e := newEnv(t)
	bot := identity.NewService(uuid.New(), "CI", nil)
	e.users.EXPECT().ByID(mock.Anything, bot.ID).Return(bot, nil)
	apiError(t, e.do(http.MethodPost, "/api/admin/users/"+bot.ID.String()+"/password-reset", "", withCookie(e.signedIn(admin()))),
		http.StatusConflict, codeNotLocal)
}

func TestRenewInvitation(t *testing.T) {
	const issuer = "https://idp.example.com/realms/x/"

	user := person("p@example.com")
	path := "/api/admin/users/" + user.ID.String() + "/invitation"

	t.Run("invited", func(t *testing.T) {
		env := newEnv(t, withAdminConfig(app.AdminUsersConfig{OIDCIssuer: issuer}))
		env.users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)
		env.idents.EXPECT().Invite(mock.Anything, user.ID, app.Invitation{
			Issuer: issuer, Email: user.Email, ExpiresAt: env.clock.Now().Add(app.InvitationTTL),
		}).Return(nil)

		rec := env.do(http.MethodPost, path, "", withCookie(env.signedIn(admin())))
		require.Equal(t, http.StatusNoContent, rec.Code, "status; body %s", rec.Body)
		require.Zero(t, rec.Body.Len(), "body %s", rec.Body)
	})
	// Two renewals for one address race on the invitation's unique index; the one
	// that loses finds the account freshly invited, which is what it asked for.
	t.Run("a concurrent renewal won", func(t *testing.T) {
		e := newEnv(t, withAdminConfig(app.AdminUsersConfig{OIDCIssuer: issuer}))
		e.users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)
		e.idents.EXPECT().Invite(mock.Anything, user.ID, mock.Anything).Return(app.ErrConflict)

		rec := e.do(http.MethodPost, path, "", withCookie(e.signedIn(admin())))
		require.Equal(t, http.StatusNoContent, rec.Code, "status; body %s", rec.Body)
		require.Zero(t, rec.Body.Len(), "body %s", rec.Body)
	})
	t.Run("already linked", func(t *testing.T) {
		e := newEnv(t, withAdminConfig(app.AdminUsersConfig{OIDCIssuer: issuer}))
		e.users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)
		e.idents.EXPECT().Invite(mock.Anything, user.ID, mock.Anything).Return(app.ErrAlreadyLinked)
		apiError(t, e.do(http.MethodPost, path, "", withCookie(e.signedIn(admin()))), http.StatusConflict, codeAlreadyLinked)
	})
	t.Run("no identity provider", func(t *testing.T) {
		e := newEnv(t)
		apiError(t, e.do(http.MethodPost, path, "", withCookie(e.signedIn(admin()))), http.StatusConflict, codeNotInvitable)
	})
}

// A token issued on an account's behalf shows its secret once; the account's token
// list afterwards shows the prefix and never the secret or its hash.
func TestIssuingATokenForAnAccountShowsItsSecretOnlyThere(t *testing.T) {
	env := newEnv(t)
	cookie := withCookie(env.signedIn(admin()))
	bot := identity.NewService(uuid.New(), "CI", nil)
	env.users.EXPECT().ByID(mock.Anything, bot.ID).Return(bot, nil)

	var stored credentials.Token

	env.tokens.EXPECT().Create(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, tok credentials.Token) error {
		stored = tok

		return nil
	})

	var out api.IssuedToken
	decodeBody(t, env.do(http.MethodPost, "/api/admin/users/"+bot.ID.String()+"/tokens", `{"label":"ci"}`, cookie), http.StatusCreated, &out)

	require.NotEmpty(t, out.Secret, "no secret was issued")
	require.Equal(t, stored.Hash, credentials.HashSecret(out.Secret), "the issued secret is not the stored token's")
	require.Equal(t, bot.ID, stored.UserID, "the token was stored for another account")
	require.Equal(t, stored.ID, out.Token.Id, "issued token id")

	env.tokens.EXPECT().ListByUser(mock.Anything, bot.ID).Return([]credentials.Token{stored}, nil)
	rec := env.do(http.MethodGet, "/api/admin/users/"+bot.ID.String()+"/tokens", "", cookie)

	var list []api.Token
	decodeBody(t, rec, http.StatusOK, &list)

	require.Len(t, list, 1, "token list %s", rec.Body)
	require.Equal(t, stored.Prefix, list[0].Prefix, "token list prefix")
	require.NotContains(t, rec.Body.String(), out.Secret, "the token list shows the secret")
	require.NotContains(t, rec.Body.String(), stored.Hash, "the token list shows the hash")
}

func TestIssuingATokenWithABadLabelIsInvalidInputOnTheLabel(t *testing.T) {
	e := newEnv(t)
	bot := identity.NewService(uuid.New(), "CI", nil)
	e.users.EXPECT().ByID(mock.Anything, bot.ID).Return(bot, nil)
	rec := e.do(http.MethodPost, "/api/admin/users/"+bot.ID.String()+"/tokens", `{"label":""}`, withCookie(e.signedIn(admin())))
	wantField(t, apiError(t, rec, http.StatusUnprocessableEntity, codeInvalidInput), "label")
}

func TestListingTheTokensOfAnUnknownAccountIsNotFound(t *testing.T) {
	e := newEnv(t)
	id := uuid.New()
	e.users.EXPECT().ByID(mock.Anything, id).Return(identity.User{}, app.ErrNotFound)
	apiError(t, e.do(http.MethodGet, "/api/admin/users/"+id.String()+"/tokens", "", withCookie(e.signedIn(admin()))),
		http.StatusNotFound, codeNotFound)
}

func TestRevokingAnAccountsToken(t *testing.T) {
	owner := person("p@example.com")

	tok, _, err := credentials.Generate(owner.ID, "laptop")
	require.NoError(t, err, "Generate")

	path := "/api/admin/users/" + owner.ID.String() + "/tokens/" + tok.ID.String()

	t.Run("revoked", func(t *testing.T) {
		env := newEnv(t)
		env.tokens.EXPECT().ListByUser(mock.Anything, owner.ID).Return([]credentials.Token{tok}, nil)
		env.tokens.EXPECT().ByID(mock.Anything, tok.ID).Return(tok, nil)

		var saved credentials.Token

		env.tokens.EXPECT().Save(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, tk credentials.Token) error {
			saved = tk

			return nil
		})

		rec := env.do(http.MethodDelete, path, "", withCookie(env.signedIn(admin())))
		require.Equal(t, http.StatusNoContent, rec.Code, "status")
		require.False(t, saved.Active(), "the token was not revoked")
	})
	// The address names the token as one of that account's; another account's token
	// is not there, and nothing is revoked.
	t.Run("another account's token", func(t *testing.T) {
		e := newEnv(t)
		e.tokens.EXPECT().ListByUser(mock.Anything, owner.ID).Return(nil, nil)
		apiError(t, e.do(http.MethodDelete, path, "", withCookie(e.signedIn(admin()))), http.StatusNotFound, codeNotFound)
	})
}

// The ledger stores no status for a served request (upstream records one only on
// failure): the activity view reports it as the 200 it was, and keeps a failure's.
func TestActivityReportsServedRequestsAsSuccessful(t *testing.T) {
	env := newEnv(t)
	self := admin()
	user := person("p@example.com")
	tokenID := uuid.New()
	at := env.clock.Now().Add(-time.Minute)
	env.users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)
	env.activity.EXPECT().RecentUsage(mock.Anything, user.ID, app.DefaultActivityLimit).Return([]app.UsageEvent{
		{
			At: at, TokenID: tokenID, Provider: "claude", Model: "m", Stream: true, TokensTotal: 42, LatencyMS: 1500,
			Cost: app.UsageCost{InputUSD: 0.5, OutputUSD: 1, CacheSavingsUSD: -2, Priced: true},
		},
		// Priced at zero: a number, not null.
		{
			At: at, Provider: "claude", Model: "m", StatusCode: http.StatusBadGateway, Failed: true,
			Cost: app.UsageCost{Priced: true},
		},
		{At: at, Provider: "claude", Model: "m", Failed: true, Cost: app.UsageCost{UnpricedTokens: 5}},
	}, nil)
	env.activity.EXPECT().RecentAudit(mock.Anything, user.ID, app.DefaultActivityLimit).Return([]app.AuditEvent{
		{At: at, ActorID: self.ID, Action: "token.issue", Target: "token/" + tokenID.String(), Detail: map[string]any{"label": "ci"}},
		{At: at, Action: "auth.sign_in"},
	}, nil)

	var got api.Activity
	decodeBody(t, env.do(http.MethodGet, "/api/admin/users/"+user.ID.String()+"/activity", "", withCookie(env.signedIn(self))), http.StatusOK, &got)

	require.Len(t, got.Requests, 3, "activity requests")
	require.Len(t, got.Audit, 2, "activity audit")

	served, failed, unknown := got.Requests[0], got.Requests[1], got.Requests[2]
	require.Equal(t, http.StatusOK, served.StatusCode, "served request status")
	require.NotNil(t, served.TokenId, "served request token")
	require.Equal(t, tokenID, *served.TokenId, "served request token")
	require.True(t, served.Stream, "served request stream")
	require.Equal(t, 42, served.TokensTotal, "served request tokens")
	require.Equal(t, 1500, served.LatencyMs, "served request latency")

	require.Equal(t, http.StatusBadGateway, failed.StatusCode, "failed request status")
	require.Nil(t, failed.TokenId, "failed request token")

	require.Zero(t, unknown.StatusCode, "a failure without a status")

	require.NotNil(t, served.CostUSD, "served cost")
	require.Equal(t, 1.5, *served.CostUSD, "served cost")
	require.NotNil(t, failed.CostUSD, "priced-at-zero cost")
	require.Zero(t, *failed.CostUSD, "priced-at-zero cost")
	require.Nil(t, unknown.CostUSD, "unpriced request's cost")

	issue, signIn := got.Audit[0], got.Audit[1]
	require.NotNil(t, issue.ActorId, "audit actor")
	require.Equal(t, self.ID, *issue.ActorId, "audit actor")
	require.NotNil(t, issue.Target, "audit target")
	require.NotNil(t, issue.Detail, "audit detail")
	require.Equal(t, "ci", (*issue.Detail)["label"], "audit detail label")

	require.Nil(t, signIn.ActorId, "audit event without actor")
	require.Nil(t, signIn.Target, "audit event without target")
	require.Nil(t, signIn.Detail, "audit event without detail")
}

func TestActivityLimit(t *testing.T) {
	user := person("p@example.com")
	path := "/api/admin/users/" + user.ID.String() + "/activity?limit="

	t.Run("the largest page", func(t *testing.T) {
		e := newEnv(t)
		e.users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)
		e.activity.EXPECT().RecentUsage(mock.Anything, user.ID, app.MaxActivityLimit).Return(nil, nil)
		e.activity.EXPECT().RecentAudit(mock.Anything, user.ID, app.MaxActivityLimit).Return(nil, nil)

		rec := e.do(http.MethodGet, path+"200", "", withCookie(e.signedIn(admin())))
		require.JSONEq(t, `{"audit":[],"requests":[]}`, rec.Body.String(), "want empty arrays")
	})

	for _, bad := range []string{"0", "201", "ten"} {
		t.Run(bad, func(t *testing.T) {
			e := newEnv(t)
			rec := e.do(http.MethodGet, path+bad, "", withCookie(e.signedIn(admin())))
			wantField(t, apiError(t, rec, http.StatusUnprocessableEntity, codeInvalidInput), "limit")
		})
	}
}

func TestCatalogListsProvidersAndModelsSorted(t *testing.T) {
	e := newEnv(t)
	e.catalog.EXPECT().Models().Return(map[string][]string{"claude": {"b", "a"}, "chatgpt": {"x"}})

	var got api.Catalog
	decodeBody(t, e.do(http.MethodGet, "/api/admin/catalog", "", withCookie(e.signedIn(admin()))), http.StatusOK, &got)

	require.Len(t, got.Providers, 2, "catalog providers")
	require.Equal(t, "chatgpt", got.Providers[0].Name, "first provider")
	require.Equal(t, "claude", got.Providers[1].Name, "second provider")
	require.Equal(t, []string{"a", "b"}, got.Providers[1].Models, "claude's models")
}

// The preview reports each rule that does not parse and covers a model only when
// every provider serving it is allowed, as the gate does.
func TestPolicyPreview(t *testing.T) {
	env := newEnv(t)
	env.catalog.EXPECT().Models().Return(map[string][]string{"claude": {"shared"}, "chatgpt": {"shared", "own"}})
	env.catalog.EXPECT().ProvidersFor("shared").Return([]string{"chatgpt", "claude"})
	env.catalog.EXPECT().ProvidersFor("own").Return([]string{"chatgpt"})

	var got api.PolicyPreview
	decodeBody(t, env.do(http.MethodPost, "/api/admin/policy/preview", `{"rules":["chatgpt:*","nonsense"]}`,
		withCookie(env.signedIn(admin()))), http.StatusOK, &got)

	require.Len(t, got.Errors, 1, "errors")
	require.Equal(t, "nonsense", got.Errors[0].Rule, "error rule")
	require.Equal(t, codeInvalidRule, got.Errors[0].Code, "error code")

	require.Len(t, got.Covered, 1, "covered; want only chatgpt's own model")
	require.Equal(t, "chatgpt", got.Covered[0].Provider, "covered provider")
	require.Equal(t, "own", got.Covered[0].Model, "covered model")
}
