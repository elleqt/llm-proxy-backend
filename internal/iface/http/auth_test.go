package http

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
)

func TestAuthConfigReportsTheSignInMethods(t *testing.T) {
	var off api.AuthConfig
	decodeBody(t, newEnv(t).do(http.MethodGet, "/api/auth/config", ""), http.StatusOK, &off)
	if !off.LocalLogin || off.Oidc.Enabled || off.Oidc.DisplayName != nil {
		t.Fatalf("without OIDC: %+v, want local login only", off)
	}

	var on api.AuthConfig
	decodeBody(t, newEnv(t, withOIDC).do(http.MethodGet, "/api/auth/config", ""), http.StatusOK, &on)
	if !on.LocalLogin || !on.Oidc.Enabled || on.Oidc.DisplayName == nil || *on.Oidc.DisplayName != "Example SSO" {
		t.Fatalf("with OIDC: %+v, want both methods and the button label", on)
	}
}

// With local sign-in off, the login screen is not offered the form and the login
// route does not exist: it answers as any unknown route does, before any password
// work or throttle charge (the strict mocks expect neither).
func TestLocalLoginOffRemovesThePasswordSignIn(t *testing.T) {
	e := newEnv(t, withOIDC, func(e *testEnv) { e.deps.LocalLogin = false })
	var cfg api.AuthConfig
	decodeBody(t, e.do(http.MethodGet, "/api/auth/config", ""), http.StatusOK, &cfg)
	if cfg.LocalLogin || !cfg.Oidc.Enabled {
		t.Fatalf("config = %+v, want OIDC only", cfg)
	}
	apiError(t, e.do(http.MethodPost, "/api/auth/login", `{"email":"person@example.com","password":"right password"}`),
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
	e := newEnv(t)
	u := person("person@example.com")
	u.MustChangePassword = true
	e.admitAttempt(u.Email)
	e.users.EXPECT().ByEmail(mock.Anything, u.Email).Return(u, nil)
	e.pwds.EXPECT().Get(mock.Anything, u.ID).Return("plain:right password", nil, nil)
	e.attempts.EXPECT().Clear(mock.Anything, u.Email).Return(nil)
	var stored app.Session
	e.sessions.EXPECT().Create(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, s app.Session) error {
		stored = s
		return nil
	})

	rec := e.do(http.MethodPost, "/api/auth/login", `{"email":"person@example.com","password":"right password"}`)
	var me api.Me
	decodeBody(t, rec, http.StatusOK, &me)
	if me.Id != u.ID || !me.Restricted || me.Email == nil || *me.Email != u.Email {
		t.Fatalf("me = %+v, want %s, restricted", me, u.ID)
	}

	c := cookieNamed(t, rec, sessionCookieName)
	if app.HashSessionID(c.Value) != stored.IDHash {
		t.Fatal("the cookie does not carry the id of the session that was stored")
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Fatalf("cookie HttpOnly=%t Secure=%t SameSite=%v Path=%q; want HttpOnly, Secure, Lax, /",
			c.HttpOnly, c.Secure, c.SameSite, c.Path)
	}
	if c.MaxAge != int(app.SessionTTL/time.Second) {
		t.Fatalf("MaxAge = %d, want the session TTL %d", c.MaxAge, int(app.SessionTTL/time.Second))
	}
	if strings.Contains(rec.Body.String(), c.Value) {
		t.Fatal("the session id is in the response body")
	}
}

// Secure comes off only when the deployment says so (local development over http).
func TestTheCookieIsNotSecureOnlyWhenConfiguredSo(t *testing.T) {
	e := newEnv(t, withInsecureCookies)
	rec := e.do(http.MethodPost, "/api/auth/logout", "")
	if c := cookieNamed(t, rec, sessionCookieName); c.Secure {
		t.Fatal("Secure is set although the deployment turned it off")
	}
}

func TestLoginRefusalsAreJSONWithTheContractsCodes(t *testing.T) {
	t.Run("wrong password", func(t *testing.T) {
		e := newEnv(t)
		e.admitAttempt("nobody@example.com")
		e.users.EXPECT().ByEmail(mock.Anything, "nobody@example.com").Return(person(""), app.ErrNotFound)
		rec := e.do(http.MethodPost, "/api/auth/login", `{"email":"nobody@example.com","password":"guess"}`)
		apiError(t, rec, http.StatusUnauthorized, codeInvalidCredentials)
		if len(rec.Result().Cookies()) != 0 {
			t.Fatal("a refused sign-in set a cookie")
		}
	})

	t.Run("locked address", func(t *testing.T) {
		e := newEnv(t)
		until := e.clock.Now().Add(90*time.Second + 200*time.Millisecond)
		e.attempts.EXPECT().Failures(mock.Anything, "person@example.com").Return(testMaxFailures, &until, nil)
		rec := e.do(http.MethodPost, "/api/auth/login", `{"email":"person@example.com","password":"guess"}`)
		apiError(t, rec, http.StatusTooManyRequests, codeLockedOut)
		if got := rec.Header().Get("Retry-After"); got != "91" {
			t.Fatalf("Retry-After = %q, want 91 (the lock's remaining time, rounded up)", got)
		}
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
	u := person("person@example.com")
	cookie := e.signedIn(u)
	e.sessions.EXPECT().Delete(mock.Anything, app.HashSessionID(cookie.Value)).Return(nil)

	rec := e.do(http.MethodPost, "/api/auth/logout", "", withCookie(cookie))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if c := cookieNamed(t, rec, sessionCookieName); c.MaxAge >= 0 || c.Value != "" {
		t.Fatalf("cookie %+v was not cleared", c)
	}
	if len(events) != 1 || events[0].Action != "auth.signout" || events[0].ActorID != u.ID {
		t.Fatalf("audit = %+v, want one auth.signout by %s", events, u.ID)
	}
}

// A cookie whose session is already gone must still be cleared, or the browser keeps
// presenting it.
func TestLogoutClearsTheCookieOfASessionAlreadyGone(t *testing.T) {
	e := newEnv(t)
	e.sessions.EXPECT().ByHash(mock.Anything, mock.Anything).Return(app.Session{}, app.ErrNotFound)
	rec := e.do(http.MethodPost, "/api/auth/logout", "", withCookie(&http.Cookie{Name: sessionCookieName, Value: "stale"}))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if c := cookieNamed(t, rec, sessionCookieName); c.MaxAge >= 0 {
		t.Fatalf("cookie %+v was not cleared", c)
	}
}

func TestLogoutReportsASessionThatCouldNotBeEnded(t *testing.T) {
	e := newEnv(t)
	cookie := e.signedIn(person("person@example.com"))
	e.sessions.EXPECT().Delete(mock.Anything, mock.Anything).Return(errors.New("connection refused"))
	rec := e.do(http.MethodPost, "/api/auth/logout", "", withCookie(cookie))
	apiError(t, rec, http.StatusInternalServerError, codeInternal)
	if c := cookieNamed(t, rec, sessionCookieName); c.MaxAge >= 0 {
		t.Fatalf("cookie %+v was not cleared", c)
	}
}

func TestPasswordChange(t *testing.T) {
	restricted := func(e *testEnv) (*http.Cookie, app.Session) {
		u := person("person@example.com")
		u.MustChangePassword = true
		e.pwds.EXPECT().Get(mock.Anything, u.ID).Return("plain:temporary", nil, nil).Maybe()
		return e.signedIn(u), app.Session{UserID: u.ID}
	}

	t.Run("a restricted session sets a new password without the old one", func(t *testing.T) {
		e := newEnv(t)
		cookie, sess := restricted(e)
		e.pwds.EXPECT().Set(mock.Anything, sess.UserID, "plain:a long new password", (*time.Time)(nil)).Return(nil)
		e.users.EXPECT().SetMustChangePassword(mock.Anything, sess.UserID, false).Return(nil)
		// Every other session of the account ends; the one that changed it stays.
		e.sessions.EXPECT().DeleteByUserExcept(mock.Anything, sess.UserID, app.HashSessionID(cookie.Value)).Return(nil)
		rec := e.do(http.MethodPost, "/api/auth/password", `{"newPassword":"a long new password"}`, withCookie(cookie))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want 204; body %s", rec.Code, rec.Body)
		}
	})

	t.Run("too short", func(t *testing.T) {
		e := newEnv(t)
		cookie, _ := restricted(e)
		rec := e.do(http.MethodPost, "/api/auth/password", `{"newPassword":"short"}`, withCookie(cookie))
		if f := apiError(t, rec, http.StatusBadRequest, codeWeakPassword).Field; f == nil || *f != "newPassword" {
			t.Fatalf("field = %v, want newPassword", f)
		}
	})

	t.Run("empty", func(t *testing.T) {
		e := newEnv(t)
		cookie, _ := restricted(e)
		rec := e.do(http.MethodPost, "/api/auth/password", `{"newPassword":""}`, withCookie(cookie))
		if f := apiError(t, rec, http.StatusBadRequest, codeEmptyPassword).Field; f == nil || *f != "newPassword" {
			t.Fatalf("field = %v, want newPassword", f)
		}
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
		e := newEnv(t)
		u := person("person@example.com")
		blocked := u
		blocked.Status = identity.StatusBlocked
		const id = "the-session"
		e.sessions.EXPECT().ByHash(mock.Anything, app.HashSessionID(id)).
			Return(app.Session{IDHash: app.HashSessionID(id), UserID: u.ID, ExpiresAt: e.clock.Now().Add(time.Hour)}, nil)
		e.users.EXPECT().ByID(mock.Anything, u.ID).Return(u, nil).Once()
		e.users.EXPECT().ByID(mock.Anything, u.ID).Return(blocked, nil).Once()
		rec := e.do(http.MethodPost, "/api/auth/password",
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
		if len(rec.Result().Cookies()) != 0 {
			t.Fatal("a wrong current password touched the session cookie")
		}
	})
}

// startOIDC redirects to the IdP and hands back the sealed challenge; the helper
// returns both.
func startOIDC(t *testing.T, e *testEnv) (*http.Cookie, url.Values) {
	t.Helper()
	e.idp.EXPECT().AuthURL(mock.Anything).RunAndReturn(func(ch app.Challenge) string {
		return "https://idp.example.com/auth?state=" + url.QueryEscape(ch.State)
	})
	rec := e.do(http.MethodGet, "/api/auth/oidc/start", "")
	if rec.Code != http.StatusFound {
		t.Fatalf("start: status = %d, want 302", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Host != "idp.example.com" {
		t.Fatalf("start redirected to %q, want the IdP", rec.Header().Get("Location"))
	}
	c := cookieNamed(t, rec, oidcCookieName)
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != oidcCookiePath ||
		c.MaxAge != int(oidcChallengeTTL/time.Second) {
		t.Fatalf("challenge cookie %+v: want HttpOnly, Secure, Lax, path %s, ten minutes", c, oidcCookiePath)
	}
	return c, loc.Query()
}

func TestOIDCStartIsNotFoundWhenOIDCIsOff(t *testing.T) {
	apiError(t, newEnv(t).do(http.MethodGet, "/api/auth/oidc/start", ""), http.StatusNotFound, codeOIDCDisabled)
}

// The challenge travels in the cookie, sealed: the verifier the IdP exchange needs is
// not readable in it, and the callback that presents it signs the person in.
func TestOIDCCallbackCompletesTheLoginTheCookieStarted(t *testing.T) {
	e := newEnv(t, withOIDC)
	cookie, q := startOIDC(t, e)

	u := person("person@example.com")
	var exchanged app.Challenge
	e.idp.EXPECT().Exchange(mock.Anything, "the-code", mock.Anything).RunAndReturn(
		func(_ context.Context, _ string, ch app.Challenge) (app.Claims, error) {
			exchanged = ch
			return app.Claims{Issuer: "https://idp.example.com", Subject: "sub-1"}, nil
		})
	e.idents.EXPECT().BySubject(mock.Anything, "https://idp.example.com", "sub-1").Return(u.ID, nil)
	e.users.EXPECT().ByID(mock.Anything, u.ID).Return(u, nil)
	e.sessions.EXPECT().Create(mock.Anything, mock.Anything).Return(nil)

	if strings.Contains(cookie.Value, q.Get("state")) {
		t.Fatal("the challenge cookie carries the state in the clear")
	}
	rec := e.do(http.MethodGet, "/api/auth/oidc/callback?code=the-code&state="+url.QueryEscape(q.Get("state")), "",
		withCookie(cookie))
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("callback: status %d to %q, want 302 to /", rec.Code, rec.Header().Get("Location"))
	}
	if exchanged.State != q.Get("state") || exchanged.Verifier == "" || strings.Contains(cookie.Value, exchanged.Verifier) {
		t.Fatalf("the exchange did not get the sealed challenge back intact")
	}
	cookieNamed(t, rec, sessionCookieName)
	if c := cookieNamed(t, rec, oidcCookieName); c.MaxAge >= 0 {
		t.Fatal("the spent challenge cookie was not cleared")
	}
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
			_, q := startOIDC(t, e)
			return "code=c&state=" + url.QueryEscape(q.Get("state")), nil
		}, oidcFailed},
		{"tampered cookie", func(t *testing.T, e *testEnv) (string, *http.Cookie) {
			c, q := startOIDC(t, e)
			b := []byte(c.Value)
			b[len(b)/2] ^= 1
			return "code=c&state=" + url.QueryEscape(q.Get("state")), &http.Cookie{Name: oidcCookieName, Value: string(b)}
		}, oidcFailed},
		{"expired challenge", func(t *testing.T, e *testEnv) (string, *http.Cookie) {
			c, q := startOIDC(t, e)
			e.clock.advance(oidcChallengeTTL)
			return "code=c&state=" + url.QueryEscape(q.Get("state")), c
		}, oidcFailed},
		{"state mismatch", func(t *testing.T, e *testEnv) (string, *http.Cookie) {
			c, _ := startOIDC(t, e)
			return "code=c&state=someone-elses", c
		}, oidcFailed},
		{"unknown subject, sign-up closed", func(t *testing.T, e *testEnv) (string, *http.Cookie) {
			c, q := startOIDC(t, e)
			e.idp.EXPECT().Exchange(mock.Anything, "c", mock.Anything).Return(app.Claims{Subject: "stranger"}, nil)
			e.idents.EXPECT().BySubject(mock.Anything, mock.Anything, "stranger").Return(uuid.Nil, app.ErrNotFound)
			return "code=c&state=" + url.QueryEscape(q.Get("state")), c
		}, oidcForbidden},
		{"IdP unreachable", func(t *testing.T, e *testEnv) (string, *http.Cookie) {
			c, q := startOIDC(t, e)
			e.idp.EXPECT().Exchange(mock.Anything, "c", mock.Anything).Return(app.Claims{}, errors.New("dial tcp: timeout"))
			return "code=c&state=" + url.QueryEscape(q.Get("state")), c
		}, oidcFailed},
		{"IdP denied access", func(t *testing.T, e *testEnv) (string, *http.Cookie) {
			c, q := startOIDC(t, e)
			return "error=access_denied&state=" + url.QueryEscape(q.Get("state")), c
		}, oidcForbidden},
		{"IdP denial for another login", func(t *testing.T, e *testEnv) (string, *http.Cookie) {
			c, _ := startOIDC(t, e)
			return "error=access_denied&state=someone-elses", c
		}, oidcFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, withOIDC)
			query, cookie := c.setup(t, e)
			var mods []func(*http.Request)
			if cookie != nil {
				mods = append(mods, withCookie(cookie))
			}
			rec := e.do(http.MethodGet, "/api/auth/oidc/callback?"+query, "", mods...)
			if rec.Code != http.StatusFound || rec.Header().Get("Location") != c.want {
				t.Fatalf("status %d to %q, want 302 to %s", rec.Code, rec.Header().Get("Location"), c.want)
			}
			if rec.Header().Get("Content-Type") == "application/json" {
				t.Fatal("a navigational route answered with JSON")
			}
			for _, sc := range rec.Result().Cookies() {
				if sc.Name == sessionCookieName {
					t.Fatal("a refused login set a session cookie")
				}
			}
		})
	}
}
