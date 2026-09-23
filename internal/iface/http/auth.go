package http

import (
	"errors"
	"net/http"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
)

// oidcCookieName holds the sealed OIDC challenge between start and callback. Its path
// is the two OIDC routes, so the browser sends it nowhere else.
const (
	oidcCookieName = "llmproxy_oidc"
	oidcCookiePath = "/api/auth/oidc"
)

// Where the OIDC callback sends the browser. The callback is a top-level navigation
// from the identity provider, so it answers with redirects, never a JSON body.
const (
	oidcSignedIn  = "/"
	oidcForbidden = "/login?error=oidc_forbidden"
	oidcFailed    = "/login?error=oidc_failed"
	// loginRateLimited is where a rate-limited OIDC navigation is sent.
	loginRateLimited = "/login?error=rate_limited"
)

func (rt *router) getAuthConfig(w http.ResponseWriter, _ *http.Request) {
	var out api.AuthConfig
	out.LocalLogin = rt.LocalLogin
	out.Oidc.Enabled = rt.OIDC != nil
	if rt.OIDC != nil && rt.OIDCDisplayName != "" {
		name := rt.OIDCDisplayName
		out.Oidc.DisplayName = &name
	}
	writeJSON(w, http.StatusOK, out)
}

// login is local sign-in. Its only 401 is invalid_credentials, for every refusal
// alike; a locked address is 429 locked_out with the lock's remaining time. It is
// routed only while local sign-in is on (Deps.LocalLogin).
func (rt *router) login(w http.ResponseWriter, r *http.Request) {
	var body api.LoginRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	sess, user, err := rt.Auth.SignIn(r.Context(), body.Email, body.Password, sessionMeta(r))
	var locked *app.LockedOutError
	switch {
	case errors.As(err, &locked):
		writeRetryAfter(w, locked.Until.Sub(rt.Clock.Now()), codeLockedOut, "too many failed attempts for this address")
		return
	case errors.Is(err, app.ErrInvalidCredentials):
		writeError(w, http.StatusUnauthorized, codeInvalidCredentials, "invalid credentials")
		return
	case err != nil:
		rt.internal(w, r, err)
		return
	}
	rt.cookies.setSession(w, sess)
	writeJSON(w, http.StatusOK, meOf(user))
}

// logout ends the caller's session, if there is one, and always clears the cookie.
func (rt *router) logout(w http.ResponseWriter, r *http.Request) {
	rt.cookies.clearSession(w)
	if c, ok := callerFrom(r.Context()); ok {
		if err := rt.Auth.SignOut(r.Context(), c.session); err != nil {
			rt.internal(w, r, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// changePassword serves a restricted session as well as a full one: it is the way
// out of the restriction. invalid_credentials here rejects what was typed and leaves
// the session alone.
func (rt *router) changePassword(w http.ResponseWriter, r *http.Request) {
	c, _ := callerFrom(r.Context())
	var body api.PasswordChangeRequest
	if !decodeJSON(w, r, &body) {
		return
	}
	var current string
	if body.CurrentPassword != nil {
		current = *body.CurrentPassword
	}
	err := rt.Auth.ChangePassword(r.Context(), c.session, current, body.NewPassword)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, identity.ErrEmptyPassword):
		writeFieldError(w, http.StatusBadRequest, codeEmptyPassword, "newPassword", "the new password is empty")
	case errors.Is(err, app.ErrWeakPassword):
		writeFieldError(w, http.StatusBadRequest, codeWeakPassword, "newPassword", "the new password is too short")
	case errors.Is(err, app.ErrInvalidCredentials), errors.Is(err, app.ErrNotFound):
		// ErrNotFound: a federated user has no local password to prove.
		writeError(w, http.StatusUnauthorized, codeInvalidCredentials, "invalid credentials")
	case errors.Is(err, app.ErrForbidden):
		// Blocked between loading the session and here.
		writeError(w, http.StatusUnauthorized, codeUnauthenticated, "no valid session")
	default:
		rt.internal(w, r, err)
	}
}

// startOIDC sends the browser to the identity provider, holding the login's
// challenge in a sealed cookie until the callback.
func (rt *router) startOIDC(w http.ResponseWriter, r *http.Request) {
	if rt.OIDC == nil {
		writeError(w, http.StatusNotFound, codeOIDCDisabled, "federated sign-in is not configured")
		return
	}
	authURL, ch, err := rt.OIDC.Begin()
	if err != nil {
		rt.internal(w, r, err)
		return
	}
	sealed, err := rt.sealer.seal(ch)
	if err != nil {
		rt.internal(w, r, err)
		return
	}
	rt.setOIDCCookie(w, sealed, int(oidcChallengeTTL.Seconds()))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// oidcCallback completes the login the challenge cookie belongs to. The cookie is
// spent whatever the outcome: a challenge serves one callback.
func (rt *router) oidcCallback(w http.ResponseWriter, r *http.Request) {
	rt.setOIDCCookie(w, "", -1)
	if rt.OIDC == nil {
		http.Redirect(w, r, oidcFailed, http.StatusFound)
		return
	}
	cookie, err := r.Cookie(oidcCookieName)
	if err != nil {
		http.Redirect(w, r, oidcFailed, http.StatusFound)
		return
	}
	ch, err := rt.sealer.open(cookie.Value)
	q := r.URL.Query()
	if err != nil || q.Get("code") == "" {
		http.Redirect(w, r, oidcFailed, http.StatusFound)
		return
	}
	sess, err := rt.OIDC.Complete(r.Context(), q.Get("code"), q.Get("state"), ch, sessionMeta(r))
	switch {
	case errors.Is(err, app.ErrForbidden):
		http.Redirect(w, r, oidcForbidden, http.StatusFound)
		return
	case err != nil:
		if !errors.Is(err, app.ErrInvalidCredentials) {
			// Not a verdict on the person: the IdP or the database failed, and
			// an operator needs to know.
			rt.Log.Warnf("web: oidc callback: %v", err)
		}
		http.Redirect(w, r, oidcFailed, http.StatusFound)
		return
	}
	rt.cookies.setSession(w, sess)
	http.Redirect(w, r, oidcSignedIn, http.StatusFound)
}

// setOIDCCookie writes (maxAge > 0) or retires (maxAge < 0) the challenge cookie.
// SameSite=Lax, not Strict: the callback is a cross-site top-level navigation from the
// identity provider, and Lax cookies are sent on those.
func (rt *router) setOIDCCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcCookieName,
		Value:    value,
		Path:     oidcCookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   rt.CookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}
