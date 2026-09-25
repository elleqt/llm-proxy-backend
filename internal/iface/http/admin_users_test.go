package http

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

func mustPolicy(t *testing.T, rules ...string) access.Policy {
	t.Helper()

	policy := make(access.Policy, 0, len(rules))
	for _, s := range rules {
		r, err := access.ParseRule(s)
		if err != nil {
			t.Fatal(err)
		}

		policy = append(policy, r)
	}

	return policy
}

// wantField asserts an Error names field.
func wantField(t *testing.T, e api.Error, field string) {
	t.Helper()

	if e.Field == nil || *e.Field != field {
		t.Fatalf("field = %v, want %q", e.Field, field)
	}
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

	if len(got) != 3 {
		t.Fatalf("got %d accounts, want 3", len(got))
	}

	personRow, serviceRow, invitedRow := got[0], got[1], got[2]
	if personRow.Id != human.ID || personRow.Email == nil || *personRow.Email != human.Email || personRow.Kind != "human" || personRow.Status != "active" ||
		len(personRow.Policy) != 1 || personRow.Policy[0] != "claude:*" || len(personRow.SignIn) != 2 || personRow.SignIn[0] != "password" || personRow.SignIn[1] != "oidc" ||
		personRow.LastSeenAt == nil || !personRow.LastSeenAt.Equal(seen) || !personRow.CreatedAt.Equal(human.CreatedAt) || personRow.InvitationExpiresAt != nil {
		t.Fatalf("person = %+v", personRow)
	}

	if serviceRow.Kind != "service" || serviceRow.Email != nil || serviceRow.SignIn == nil || len(serviceRow.SignIn) != 0 || serviceRow.Policy == nil {
		t.Fatalf("service account = %+v, want no email and empty (not null) sign-in and policy", serviceRow)
	}

	if invitedRow.InvitationExpiresAt == nil || !invitedRow.InvitationExpiresAt.Equal(lapsed) || len(invitedRow.SignIn) != 0 {
		t.Fatalf("invited person = %+v, want the lapsed invitation and no way in", invitedRow)
	}
}

func TestAnAdminServiceFailureIsInternalAndUndescribed(t *testing.T) {
	e := newEnv(t)
	e.users.EXPECT().List(mock.Anything).Return(nil, errors.New("pq: relation users does not exist"))
	rec := e.do(http.MethodGet, "/api/admin/users", "", withCookie(e.signedIn(admin())))
	apiError(t, rec, http.StatusInternalServerError, codeInternal)

	if strings.Contains(rec.Body.String(), "relation") {
		t.Fatalf("the response describes the failure: %s", rec.Body)
	}
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
	if temp == nil || acct.Password == nil || acct.Password.Hash != "plain:"+temp.Password {
		t.Fatalf("temporary password %+v is not the one whose hash was stored", temp)
	}

	if !temp.ExpiresAt.Equal(env.clock.Now().Add(app.TemporaryPasswordTTL)) {
		t.Fatalf("expires at %s, want %s", temp.ExpiresAt, env.clock.Now().Add(app.TemporaryPasswordTTL))
	}

	u := out.User
	if u.Id != acct.User.ID || u.Email == nil || *u.Email != "new@example.com" || !u.MustChangePassword ||
		len(u.SignIn) != 1 || u.SignIn[0] != "password" || len(u.Policy) != 1 || u.Policy[0] != "claude:*" {
		t.Fatalf("created user = %+v", u)
	}

	view := app.UserView{User: acct.User, SignIn: []app.SignInMethod{app.SignInPassword}}
	env.users.EXPECT().View(mock.Anything, acct.User.ID).Return(view, nil)
	env.users.EXPECT().List(mock.Anything).Return([]app.UserView{view}, nil)

	for _, path := range []string{"/api/admin/users/" + acct.User.ID.String(), "/api/admin/users"} {
		rec := env.do(http.MethodGet, path, "", cookie)
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), temp.Password) || strings.Contains(rec.Body.String(), acct.Password.Hash) {
			t.Fatalf("GET %s = %d %s: want 200 without the password or its hash", path, rec.Code, rec.Body)
		}
	}
}

func TestCreatingAServiceAccountIssuesNoPassword(t *testing.T) {
	e := newEnv(t)
	e.users.EXPECT().CreateAccount(mock.Anything, mock.Anything).Return(nil)
	rec := e.do(http.MethodPost, "/api/admin/users", `{"kind":"service","displayName":"CI","policy":[]}`,
		withCookie(e.signedIn(admin())))

	var raw map[string]json.RawMessage
	decodeBody(t, rec, http.StatusCreated, &raw)

	if _, ok := raw["temporaryPassword"]; ok {
		t.Fatalf("a service account got a temporary password: %s", rec.Body)
	}
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

	if got.Id != user.ID || got.Status != "blocked" {
		t.Fatalf("user = %+v", got)
	}

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

	if change.DisplayName == nil || *change.DisplayName != "Renamed" || change.Policy == nil || len(*change.Policy) != 1 || (*change.Policy)[0].String() != "chatgpt:*" ||
		change.Role != nil || change.Status != nil {
		t.Fatalf("change = %+v, want the name and policy only", change)
	}

	if got.DisplayName != "Renamed" || len(got.Policy) != 1 || got.Policy[0] != "chatgpt:*" {
		t.Fatalf("user = %+v, want the account as it now stands", got)
	}
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

	if temp.Password == "" || hash != "plain:"+temp.Password || !temp.ExpiresAt.Equal(env.clock.Now().Add(app.TemporaryPasswordTTL)) {
		t.Fatalf("temporary password %+v is not the one stored", temp)
	}

	user.MustChangePassword = true
	env.users.EXPECT().View(mock.Anything, user.ID).Return(app.UserView{User: user, SignIn: []app.SignInMethod{app.SignInPassword}}, nil)

	rec := env.do(http.MethodGet, "/api/admin/users/"+user.ID.String(), "", cookie)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), temp.Password) {
		t.Fatalf("GET = %d %s: want 200 without the password", rec.Code, rec.Body)
	}
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
		if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
			t.Fatalf("status = %d, body %s; want 204", rec.Code, rec.Body)
		}
	})
	// Two renewals for one address race on the invitation's unique index; the one
	// that loses finds the account freshly invited, which is what it asked for.
	t.Run("a concurrent renewal won", func(t *testing.T) {
		e := newEnv(t, withAdminConfig(app.AdminUsersConfig{OIDCIssuer: issuer}))
		e.users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)
		e.idents.EXPECT().Invite(mock.Anything, user.ID, mock.Anything).Return(app.ErrConflict)

		rec := e.do(http.MethodPost, path, "", withCookie(e.signedIn(admin())))
		if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
			t.Fatalf("status = %d, body %s; want 204", rec.Code, rec.Body)
		}
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

	if out.Secret == "" || credentials.HashSecret(out.Secret) != stored.Hash || stored.UserID != bot.ID || out.Token.Id != stored.ID {
		t.Fatalf("issued %+v, stored for %s: want the account's token and its secret", out.Token, stored.UserID)
	}

	env.tokens.EXPECT().ListByUser(mock.Anything, bot.ID).Return([]credentials.Token{stored}, nil)
	rec := env.do(http.MethodGet, "/api/admin/users/"+bot.ID.String()+"/tokens", "", cookie)

	var list []api.Token
	decodeBody(t, rec, http.StatusOK, &list)

	if len(list) != 1 || list[0].Prefix != stored.Prefix ||
		strings.Contains(rec.Body.String(), out.Secret) || strings.Contains(rec.Body.String(), stored.Hash) {
		t.Fatalf("token list %s: want the prefix and never the secret or hash", rec.Body)
	}
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
	if err != nil {
		t.Fatal(err)
	}

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
		if rec.Code != http.StatusNoContent || saved.Active() {
			t.Fatalf("status = %d, revoked = %t; want 204 and the token revoked", rec.Code, !saved.Active())
		}
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

	if len(got.Requests) != 3 || len(got.Audit) != 2 {
		t.Fatalf("activity = %+v", got)
	}

	served, failed, unknown := got.Requests[0], got.Requests[1], got.Requests[2]
	if served.StatusCode != http.StatusOK || served.TokenId == nil || *served.TokenId != tokenID ||
		!served.Stream || served.TokensTotal != 42 || served.LatencyMs != 1500 {
		t.Fatalf("served request = %+v, want status 200 and its token", served)
	}

	if failed.StatusCode != http.StatusBadGateway || failed.TokenId != nil {
		t.Fatalf("failed request = %+v, want its 502 and no token", failed)
	}

	if unknown.StatusCode != 0 {
		t.Fatalf("a failure without a status reads as %d, want 0", unknown.StatusCode)
	}

	if served.CostUSD == nil || *served.CostUSD != 1.5 {
		t.Fatalf("served cost = %v, want 1.5", served.CostUSD)
	}

	if failed.CostUSD == nil || *failed.CostUSD != 0 {
		t.Fatalf("priced-at-zero cost = %v, want 0", failed.CostUSD)
	}

	if unknown.CostUSD != nil {
		t.Fatalf("unpriced request's cost = %v, want none", *unknown.CostUSD)
	}

	issue, signIn := got.Audit[0], got.Audit[1]
	if issue.ActorId == nil || *issue.ActorId != self.ID || issue.Target == nil || issue.Detail == nil || (*issue.Detail)["label"] != "ci" {
		t.Fatalf("audit event = %+v", issue)
	}

	if signIn.ActorId != nil || signIn.Target != nil || signIn.Detail != nil {
		t.Fatalf("audit event without actor, target or detail = %+v", signIn)
	}
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
		if strings.TrimSpace(rec.Body.String()) != `{"audit":[],"requests":[]}` {
			t.Fatalf("body = %s, want empty arrays", rec.Body)
		}
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

	if len(got.Providers) != 2 || got.Providers[0].Name != "chatgpt" || got.Providers[1].Name != "claude" ||
		strings.Join(got.Providers[1].Models, ",") != "a,b" {
		t.Fatalf("catalog = %+v", got)
	}
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

	if len(got.Errors) != 1 || got.Errors[0].Rule != "nonsense" || got.Errors[0].Code != codeInvalidRule {
		t.Fatalf("errors = %+v", got.Errors)
	}

	if len(got.Covered) != 1 || got.Covered[0].Provider != "chatgpt" || got.Covered[0].Model != "own" {
		t.Fatalf("covered = %+v, want only chatgpt's own model", got.Covered)
	}
}
