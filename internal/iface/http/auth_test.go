package http

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	appauth "github.com/elleqt/llm-proxy-backend/internal/app/auth"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAuthConfigReportsTheSignInMethods(t *testing.T) {
	var off api.AuthConfig
	decodeBody(t, newEnv(t).do(http.MethodGet, "/api/auth/config", ""), http.StatusOK, &off)

	require.True(t, off.LocalLogin, "without OIDC: local login")
	require.False(t, off.Oidc.Enabled, "without OIDC: oidc enabled")
	require.Nil(t, off.Oidc.DisplayName, "without OIDC: button label")

	var on api.AuthConfig
	decodeBody(t, newEnv(t, withOIDC).do(http.MethodGet, "/api/auth/config", ""), http.StatusOK, &on)

	require.True(t, on.LocalLogin, "with OIDC: local login")
	require.True(t, on.Oidc.Enabled, "with OIDC: oidc enabled")
	require.NotNil(t, on.Oidc.DisplayName, "with OIDC: button label")
	require.Equal(t, "Example SSO", *on.Oidc.DisplayName, "with OIDC: button label")
}

// With local sign-in off, the login screen is not offered the form and the login
// route does not exist: it answers as any unknown route does, before any password
// work or throttle charge (the strict mocks expect neither).
func TestLocalLoginOffRemovesThePasswordSignIn(t *testing.T) {
	env := newEnv(t, withOIDC, func(e *testEnv) { e.deps.LocalLogin = false })

	var cfg api.AuthConfig
	decodeBody(t, env.do(http.MethodGet, "/api/auth/config", ""), http.StatusOK, &cfg)

	require.False(t, cfg.LocalLogin, "local login is offered")
	require.True(t, cfg.Oidc.Enabled, "oidc is not offered")

	apiError(t, env.do(http.MethodPost, "/api/auth/login", `{"email":"person@example.com","password":"right password"}`),
		http.StatusNotFound, codeNotFound)
}

// admitAttempt lets one sign-in attempt for email through the throttle.
func (e *testEnv) admitAttempt(email string) {
	e.attempts.EXPECT().Failures(mock.Anything, email).Return(0, nil, nil)
	e.attempts.EXPECT().Charge(mock.Anything, email, testMaxFailures, mock.Anything, mock.Anything).Return(1, nil, nil)
}

// A successful sign-in sets the session cookie with every protective flag, and
// answers with the user as GET /api/me would — restricted included.
func TestLoginSetsTheSessionCookieAndDescribesTheUser(t *testing.T) {
	env := newEnv(t)
	user := person("person@example.com")
	user.MustChangePassword = true
	env.admitAttempt(user.Email)
	env.users.EXPECT().ByEmail(mock.Anything, user.Email).Return(user, nil)
	env.pwds.EXPECT().Get(mock.Anything, user.ID).Return("plain:right password", nil, nil)
	env.attempts.EXPECT().Clear(mock.Anything, user.Email).Return(nil)

	var stored app.Session

	env.sessions.EXPECT().Create(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, s app.Session) error {
		stored = s

		return nil
	})

	rec := env.do(http.MethodPost, "/api/auth/login", `{"email":"person@example.com","password":"right password"}`)

	var me api.Me
	decodeBody(t, rec, http.StatusOK, &me)

	require.Equal(t, user.ID, me.Id, "me id")
	require.True(t, me.Restricted, "me restricted")
	require.NotNil(t, me.Email, "me email")
	require.Equal(t, user.Email, *me.Email, "me email")

	cookie := cookieNamed(t, rec, sessionCookieName)
	require.Equal(t, stored.IDHash, appauth.HashSessionID(cookie.Value), "the cookie does not carry the id of the session that was stored")

	require.True(t, cookie.HttpOnly, "cookie HttpOnly")
	require.True(t, cookie.Secure, "cookie Secure")
	require.Equal(t, http.SameSiteLaxMode, cookie.SameSite, "cookie SameSite")
	require.Equal(t, "/", cookie.Path, "cookie Path")
	require.Equal(t, int(appauth.SessionTTL/time.Second), cookie.MaxAge, "MaxAge is not the session TTL")
	require.NotContains(t, rec.Body.String(), cookie.Value, "the session id is in the response body")
}

// Secure comes off only when the deployment says so (local development over http).
func TestTheCookieIsNotSecureOnlyWhenConfiguredSo(t *testing.T) {
	e := newEnv(t, withInsecureCookies)

	rec := e.do(http.MethodPost, "/api/auth/logout", "")
	c := cookieNamed(t, rec, sessionCookieName)
	require.False(t, c.Secure, "Secure is set although the deployment turned it off")
}

func TestLoginRefusalsAreJSONWithTheContractsCodes(t *testing.T) {
	t.Run("wrong password", func(t *testing.T) {
		e := newEnv(t)
		e.admitAttempt("nobody@example.com")
		e.users.EXPECT().ByEmail(mock.Anything, "nobody@example.com").Return(person(""), app.ErrNotFound)
		rec := e.do(http.MethodPost, "/api/auth/login", `{"email":"nobody@example.com","password":"guess"}`)
		apiError(t, rec, http.StatusUnauthorized, codeInvalidCredentials)

		require.Empty(t, rec.Result().Cookies(), "a refused sign-in set a cookie")
	})

	t.Run("locked address", func(t *testing.T) {
		e := newEnv(t)
		until := e.clock.Now().Add(90*time.Second + 200*time.Millisecond)
		e.attempts.EXPECT().Failures(mock.Anything, "person@example.com").Return(testMaxFailures, &until, nil)
		rec := e.do(http.MethodPost, "/api/auth/login", `{"email":"person@example.com","password":"guess"}`)
		apiError(t, rec, http.StatusTooManyRequests, codeLockedOut)

		require.Equal(t, "91", rec.Header().Get("Retry-After"), "Retry-After is not the lock's remaining time, rounded up")
	})

	t.Run("store down", func(t *testing.T) {
		e := newEnv(t)
		e.attempts.EXPECT().Failures(mock.Anything, mock.Anything).Return(0, nil, errors.New("connection refused"))
		rec := e.do(http.MethodPost, "/api/auth/login", `{"email":"person@example.com","password":"guess"}`)
		apiError(t, rec, http.StatusInternalServerError, codeInternal)
	})

	t.Run("not JSON", func(t *testing.T) {
		apiError(t, newEnv(t).do(http.MethodPost, "/api/auth/login", `email=a`), http.StatusUnprocessableEntity, codeInvalidInput)
	})
}

// Sign-out ends the session in the store, writes the sign-out audit row, and clears
// the cookie.
func TestLogoutEndsTheSessionAndClearsTheCookie(t *testing.T) {
	var events []app.AuditEvent

	e := newEnv(t, auditInto(&events))
	user := person("person@example.com")
	cookie := e.signedIn(user)
	e.sessions.EXPECT().Delete(mock.Anything, appauth.HashSessionID(cookie.Value)).Return(nil)

	rec := e.do(http.MethodPost, "/api/auth/logout", "", withCookie(cookie))
	require.Equal(t, http.StatusNoContent, rec.Code, "status")

	c := cookieNamed(t, rec, sessionCookieName)
	require.Negative(t, c.MaxAge, "cookie %+v was not cleared", c)
	require.Empty(t, c.Value, "cookie %+v was not cleared", c)

	require.Len(t, events, 1, "audit")
	require.Equal(t, "auth.signout", events[0].Action, "audit action")
	require.Equal(t, user.ID, events[0].ActorID, "audit actor")
}

// A cookie whose session is already gone must still be cleared, or the browser keeps
// presenting it.
func TestLogoutClearsTheCookieOfASessionAlreadyGone(t *testing.T) {
	e := newEnv(t)
	e.sessions.EXPECT().ByHash(mock.Anything, mock.Anything).Return(app.Session{}, app.ErrNotFound)

	rec := e.do(http.MethodPost, "/api/auth/logout", "", withCookie(&http.Cookie{Name: sessionCookieName, Value: "stale"}))
	require.Equal(t, http.StatusNoContent, rec.Code, "status")

	c := cookieNamed(t, rec, sessionCookieName)
	require.Negative(t, c.MaxAge, "cookie %+v was not cleared", c)
}

func TestLogoutReportsASessionThatCouldNotBeEnded(t *testing.T) {
	e := newEnv(t)
	cookie := e.signedIn(person("person@example.com"))
	e.sessions.EXPECT().Delete(mock.Anything, mock.Anything).Return(errors.New("connection refused"))
	rec := e.do(http.MethodPost, "/api/auth/logout", "", withCookie(cookie))
	apiError(t, rec, http.StatusInternalServerError, codeInternal)

	c := cookieNamed(t, rec, sessionCookieName)
	require.Negative(t, c.MaxAge, "cookie %+v was not cleared", c)
}

func TestPasswordChange(t *testing.T) {
	restricted := func(e *testEnv) (*http.Cookie, app.Session) {
		u := person("person@example.com")
		u.MustChangePassword = true
		e.pwds.EXPECT().Get(mock.Anything, u.ID).Return("plain:temporary", nil, nil).Maybe()

		return e.signedIn(u), app.Session{UserID: u.ID}
	}

	t.Run("a restricted session sets a new password without the old one", func(t *testing.T) {
		env := newEnv(t)
		cookie, sess := restricted(env)
		env.pwds.EXPECT().Set(mock.Anything, sess.UserID, "plain:a long new password", (*time.Time)(nil)).Return(nil)
		env.users.EXPECT().SetMustChangePassword(mock.Anything, sess.UserID, false).Return(nil)
		// Every other session of the account ends; the one that changed it stays.
		env.sessions.EXPECT().DeleteByUserExcept(mock.Anything, sess.UserID, appauth.HashSessionID(cookie.Value)).Return(nil)

		rec := env.do(http.MethodPost, "/api/auth/password", `{"newPassword":"a long new password"}`, withCookie(cookie))
		require.Equal(t, http.StatusNoContent, rec.Code, "status; body %s", rec.Body)
	})

	t.Run("too short", func(t *testing.T) {
		e := newEnv(t)
		cookie, _ := restricted(e)

		rec := e.do(http.MethodPost, "/api/auth/password", `{"newPassword":"short"}`, withCookie(cookie))
		wantField(t, apiError(t, rec, http.StatusBadRequest, codeWeakPassword), "newPassword")
	})

	t.Run("empty", func(t *testing.T) {
		e := newEnv(t)
		cookie, _ := restricted(e)

		rec := e.do(http.MethodPost, "/api/auth/password", `{"newPassword":""}`, withCookie(cookie))
		wantField(t, apiError(t, rec, http.StatusBadRequest, codeEmptyPassword), "newPassword")
	})

	// A federated user has no local password to prove: the same answer as a wrong one.
	t.Run("no local password", func(t *testing.T) {
		e := newEnv(t)
		u := person("federated@example.com")
		e.pwds.EXPECT().Get(mock.Anything, u.ID).Return("", nil, app.ErrNotFound)
		rec := e.do(http.MethodPost, "/api/auth/password",
			`{"currentPassword":"anything","newPassword":"a long new password"}`, withCookie(e.signedIn(u)))
		apiError(t, rec, http.StatusUnauthorized, codeInvalidCredentials)
	})

	// Blocked between the session check and the change: the session no longer
	// stands, so the answer is the signed-out one, not a credential verdict.
	t.Run("blocked mid-request", func(t *testing.T) {
		env := newEnv(t)
		user := person("person@example.com")
		blocked := user
		blocked.Status = identity.StatusBlocked

		const id = "the-session"
		env.sessions.EXPECT().ByHash(mock.Anything, appauth.HashSessionID(id)).
			Return(app.Session{IDHash: appauth.HashSessionID(id), UserID: user.ID, ExpiresAt: env.clock.Now().Add(time.Hour)}, nil)
		env.users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil).Once()
		env.users.EXPECT().ByID(mock.Anything, user.ID).Return(blocked, nil).Once()
		rec := env.do(http.MethodPost, "/api/auth/password",
			`{"currentPassword":"anything","newPassword":"a long new password"}`,
			withCookie(&http.Cookie{Name: sessionCookieName, Value: id}))
		apiError(t, rec, http.StatusUnauthorized, codeUnauthenticated)
	})

	// invalid_credentials rejects what was typed; the session is untouched (no
	// Delete expectation) and no cookie is cleared.
	t.Run("wrong current password on a full session", func(t *testing.T) {
		e := newEnv(t)
		u := person("person@example.com")
		e.pwds.EXPECT().Get(mock.Anything, u.ID).Return("plain:the real one", nil, nil)
		rec := e.do(http.MethodPost, "/api/auth/password",
			`{"currentPassword":"a guess","newPassword":"a long new password"}`, withCookie(e.signedIn(u)))
		apiError(t, rec, http.StatusUnauthorized, codeInvalidCredentials)

		require.Empty(t, rec.Result().Cookies(), "a wrong current password touched the session cookie")
	})
}

// startOIDC redirects to the IdP and hands back the sealed challenge; the helper
// returns both.
func startOIDC(t *testing.T, env *testEnv) (*http.Cookie, url.Values) {
	t.Helper()
	env.idp.EXPECT().AuthURL(mock.Anything).RunAndReturn(func(ch app.Challenge) string {
		return "https://idp.example.com/auth?state=" + url.QueryEscape(ch.State)
	})

	rec := env.do(http.MethodGet, "/api/auth/oidc/start", "")
	require.Equal(t, http.StatusFound, rec.Code, "start: status")

	loc, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err, "start redirected to %q", rec.Header().Get("Location"))
	require.Equal(t, "idp.example.com", loc.Host, "start did not redirect to the IdP")

	cookie := cookieNamed(t, rec, oidcCookieName)
	require.True(t, cookie.HttpOnly, "challenge cookie HttpOnly")
	require.True(t, cookie.Secure, "challenge cookie Secure")
	require.Equal(t, http.SameSiteLaxMode, cookie.SameSite, "challenge cookie SameSite")
	require.Equal(t, oidcCookiePath, cookie.Path, "challenge cookie Path")
	require.Equal(t, int(oidcChallengeTTL/time.Second), cookie.MaxAge, "challenge cookie MaxAge")

	return cookie, loc.Query()
}

func TestOIDCStartIsNotFoundWhenOIDCIsOff(t *testing.T) {
	apiError(t, newEnv(t).do(http.MethodGet, "/api/auth/oidc/start", ""), http.StatusNotFound, codeOIDCDisabled)
}

// The challenge travels in the cookie, sealed: the verifier the IdP exchange needs is
// not readable in it, and the callback that presents it signs the person in.
func TestOIDCCallbackCompletesTheLoginTheCookieStarted(t *testing.T) {
	env := newEnv(t, withOIDC)
	cookie, query := startOIDC(t, env)

	user := person("person@example.com")

	var exchanged app.Challenge

	env.idp.EXPECT().Exchange(mock.Anything, "the-code", mock.Anything).RunAndReturn(
		func(_ context.Context, _ string, ch app.Challenge) (app.Claims, error) {
			exchanged = ch

			return app.Claims{Issuer: "https://idp.example.com", Subject: "sub-1"}, nil
		})
	env.idents.EXPECT().BySubject(mock.Anything, "https://idp.example.com", "sub-1").Return(user.ID, nil)
	env.users.EXPECT().ByID(mock.Anything, user.ID).Return(user, nil)
	env.sessions.EXPECT().Create(mock.Anything, mock.Anything).Return(nil)

	require.NotContains(t, cookie.Value, query.Get("state"), "the challenge cookie carries the state in the clear")

	rec := env.do(http.MethodGet, "/api/auth/oidc/callback?code=the-code&state="+url.QueryEscape(query.Get("state")), "",
		withCookie(cookie))
	require.Equal(t, http.StatusFound, rec.Code, "callback status")
	require.Equal(t, "/", rec.Header().Get("Location"), "callback redirect")

	require.Equal(t, query.Get("state"), exchanged.State, "the exchange did not get the sealed state back")
	require.NotEmpty(t, exchanged.Verifier, "the exchange got no verifier")
	require.NotContains(t, cookie.Value, exchanged.Verifier, "the challenge cookie carries the verifier in the clear")

	cookieNamed(t, rec, sessionCookieName)

	c := cookieNamed(t, rec, oidcCookieName)
	require.Negative(t, c.MaxAge, "the spent challenge cookie was not cleared")
}

// Every failure is a redirect to the login page, never a JSON body: the callback is a
// browser navigation.
func TestOIDCCallbackFailuresRedirectToTheLoginPage(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, e *testEnv) (query string, cookie *http.Cookie)
		want  string
	}{
		{"no challenge cookie", func(t *testing.T, e *testEnv) (string, *http.Cookie) {
			t.Helper()

			_, q := startOIDC(t, e)

			return "code=c&state=" + url.QueryEscape(q.Get("state")), nil
		}, oidcFailed},
		{"tampered cookie", func(t *testing.T, e *testEnv) (string, *http.Cookie) {
			t.Helper()

			c, q := startOIDC(t, e)
			b := []byte(c.Value)
			b[len(b)/2] ^= 1

			return "code=c&state=" + url.QueryEscape(q.Get("state")), &http.Cookie{Name: oidcCookieName, Value: string(b)}
		}, oidcFailed},
		{"expired challenge", func(t *testing.T, e *testEnv) (string, *http.Cookie) {
			t.Helper()

			c, q := startOIDC(t, e)
			e.clock.advance(oidcChallengeTTL)

			return "code=c&state=" + url.QueryEscape(q.Get("state")), c
		}, oidcFailed},
		{"state mismatch", func(t *testing.T, e *testEnv) (string, *http.Cookie) {
			t.Helper()

			c, _ := startOIDC(t, e)

			return "code=c&state=someone-elses", c
		}, oidcFailed},
		{"unknown subject, sign-up closed", func(t *testing.T, e *testEnv) (string, *http.Cookie) {
			t.Helper()

			c, q := startOIDC(t, e)
			e.idp.EXPECT().Exchange(mock.Anything, "c", mock.Anything).Return(app.Claims{Subject: "stranger"}, nil)
			e.idents.EXPECT().BySubject(mock.Anything, mock.Anything, "stranger").Return(uuid.Nil, app.ErrNotFound)

			return "code=c&state=" + url.QueryEscape(q.Get("state")), c
		}, oidcForbidden},
		{"IdP unreachable", func(t *testing.T, e *testEnv) (string, *http.Cookie) {
			t.Helper()

			c, q := startOIDC(t, e)
			e.idp.EXPECT().Exchange(mock.Anything, "c", mock.Anything).Return(app.Claims{}, errors.New("dial tcp: timeout"))

			return "code=c&state=" + url.QueryEscape(q.Get("state")), c
		}, oidcFailed},
		{"IdP denied access", func(t *testing.T, e *testEnv) (string, *http.Cookie) {
			t.Helper()

			c, q := startOIDC(t, e)

			return "error=access_denied&state=" + url.QueryEscape(q.Get("state")), c
		}, oidcForbidden},
		{"IdP denial for another login", func(t *testing.T, e *testEnv) (string, *http.Cookie) {
			t.Helper()

			c, _ := startOIDC(t, e)

			return "error=access_denied&state=someone-elses", c
		}, oidcFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newEnv(t, withOIDC)
			query, cookie := tc.setup(t, env)

			var mods []func(*http.Request)
			if cookie != nil {
				mods = append(mods, withCookie(cookie))
			}

			rec := env.do(http.MethodGet, "/api/auth/oidc/callback?"+query, "", mods...)
			require.Equal(t, http.StatusFound, rec.Code, "status")
			require.Equal(t, tc.want, rec.Header().Get("Location"), "redirect")
			require.NotEqual(t, "application/json", rec.Header().Get("Content-Type"), "a navigational route answered with JSON")

			for _, sc := range rec.Result().Cookies() {
				require.NotEqual(t, sessionCookieName, sc.Name, "a refused login set a session cookie")
			}
		})
	}
}
