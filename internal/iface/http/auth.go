package http

import (
	"errors"
	"log/slog"
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

func (rt *router) getAuthConfig(rw http.ResponseWriter, _ *http.Request) {
	var out api.AuthConfig

	out.LocalLogin = rt.LocalLogin

	out.Oidc.Enabled = rt.OIDC != nil
	if rt.OIDC != nil && rt.OIDCDisplayName != "" {
		name := rt.OIDCDisplayName
		out.Oidc.DisplayName = &name
	}

	writeJSON(rw, http.StatusOK, out)
}

// login is local sign-in. Its only 401 is invalid_credentials, for every refusal
// alike; a locked address is 429 locked_out with the lock's remaining time. It is
// routed only while local sign-in is on (Deps.LocalLogin).
func (rt *router) login(rw http.ResponseWriter, req *http.Request) {
	var body api.LoginRequest
	if !decodeJSON(rw, req, &body) {
		return
	}

	sess, user, err := rt.Auth.SignIn(req.Context(), body.Email, body.Password, sessionMeta(req))

	var locked *app.LockedOutError
	switch {
	case errors.As(err, &locked):
		writeRetryAfter(rw, locked.Until.Sub(rt.Clock.Now()), codeLockedOut, "too many failed attempts for this address")

		return
	case errors.Is(err, app.ErrInvalidCredentials):
		writeError(rw, http.StatusUnauthorized, codeInvalidCredentials, "invalid credentials")

		return
	case err != nil:
		rt.internal(rw, req, err)

		return
	}

	rt.cookies.setSession(rw, sess)
	writeJSON(rw, http.StatusOK, meOf(user))
}

// logout ends the caller's session, if there is one, and always clears the cookie.
func (rt *router) logout(rw http.ResponseWriter, req *http.Request) {
	rt.cookies.clearSession(rw)

	if c, ok := callerFrom(req.Context()); ok {
		if err := rt.Auth.SignOut(req.Context(), c.session); err != nil {
			rt.internal(rw, req, err)

			return
		}
	}

	rw.WriteHeader(http.StatusNoContent)
}

// changePassword serves a restricted session as well as a full one: it is the way
// out of the restriction. invalid_credentials here rejects what was typed and leaves
// the session alone.
func (rt *router) changePassword(rw http.ResponseWriter, req *http.Request) {
	actor, _ := callerFrom(req.Context())

	var body api.PasswordChangeRequest
	if !decodeJSON(rw, req, &body) {
		return
	}

	var current string
	if body.CurrentPassword != nil {
		current = *body.CurrentPassword
	}

	err := rt.Auth.ChangePassword(req.Context(), actor.session, current, body.NewPassword)
	switch {
	case err == nil:
		rw.WriteHeader(http.StatusNoContent)
	case errors.Is(err, identity.ErrEmptyPassword):
		writeFieldError(rw, http.StatusBadRequest, codeEmptyPassword, "newPassword", "the new password is empty")
	case errors.Is(err, app.ErrWeakPassword):
		writeFieldError(rw, http.StatusBadRequest, codeWeakPassword, "newPassword", "the new password is too short")
	case errors.Is(err, app.ErrInvalidCredentials), errors.Is(err, app.ErrNotFound):
		// ErrNotFound: a federated user has no local password to prove.
		writeError(rw, http.StatusUnauthorized, codeInvalidCredentials, "invalid credentials")
	case errors.Is(err, app.ErrForbidden):
		// Blocked between loading the session and here.
		writeError(rw, http.StatusUnauthorized, codeUnauthenticated, "no valid session")
	default:
		rt.internal(rw, req, err)
	}
}

// startOIDC sends the browser to the identity provider, holding the login's
// challenge in a sealed cookie until the callback.
func (rt *router) startOIDC(rw http.ResponseWriter, req *http.Request) {
	if rt.OIDC == nil {
		writeError(rw, http.StatusNotFound, codeOIDCDisabled, "federated sign-in is not configured")

		return
	}

	authURL, ch, err := rt.OIDC.Begin()
	if err != nil {
		rt.internal(rw, req, err)

		return
	}

	sealed, err := rt.sealer.seal(ch)
	if err != nil {
		rt.internal(rw, req, err)

		return
	}

	rt.setOIDCCookie(rw, sealed, int(oidcChallengeTTL.Seconds()))
	http.Redirect(rw, req, authURL, http.StatusFound)
}

// oidcCallback completes the login the challenge cookie belongs to. The cookie is
// spent whatever the outcome: a challenge serves one callback.
func (rt *router) oidcCallback(rw http.ResponseWriter, req *http.Request) {
	rt.setOIDCCookie(rw, "", -1)

	if rt.OIDC == nil {
		http.Redirect(rw, req, oidcFailed, http.StatusFound)

		return
	}

	cookie, err := req.Cookie(oidcCookieName)
	if err != nil {
		http.Redirect(rw, req, oidcFailed, http.StatusFound)

		return
	}

	ch, err := rt.sealer.open(cookie.Value)

	query := req.URL.Query()
	if err == nil && query.Get("error") == "access_denied" && ch.Answers(query.Get("state")) {
		// The identity provider refused the sign-in: the person or the
		// provider's policy denied access. Named, unlike other IdP errors,
		// so the login page can say "no access" instead of "failed". Like a
		// code, the refusal is this login's answer only when it carries the
		// state this login sent (RFC 6749 §10.12).
		http.Redirect(rw, req, oidcForbidden, http.StatusFound)

		return
	}

	if err != nil || query.Get("code") == "" {
		http.Redirect(rw, req, oidcFailed, http.StatusFound)

		return
	}

	sess, err := rt.OIDC.Complete(req.Context(), query.Get("code"), query.Get("state"), ch, sessionMeta(req))
	switch {
	case errors.Is(err, app.ErrForbidden):
		http.Redirect(rw, req, oidcForbidden, http.StatusFound)

		return
	case err != nil:
		if !errors.Is(err, app.ErrInvalidCredentials) {
			// Not a verdict on the person: the IdP or the database failed, and
			// an operator needs to know.
			rt.Log.Warn("oidc callback failed", slog.Any("err", err))
		}

		http.Redirect(rw, req, oidcFailed, http.StatusFound)

		return
	}

	rt.cookies.setSession(rw, sess)
	http.Redirect(rw, req, oidcSignedIn, http.StatusFound)
}

// setOIDCCookie writes (maxAge > 0) or retires (maxAge < 0) the challenge cookie.
// SameSite=Lax, not Strict: the callback is a cross-site top-level navigation from the
// identity provider, and Lax cookies are sent on those.
func (rt *router) setOIDCCookie(w http.ResponseWriter, value string, maxAge int) {
	//nolint:gosec // HttpOnly and Lax are set; Secure is the deployment's CookieSecure, off only for plain-http development.
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
