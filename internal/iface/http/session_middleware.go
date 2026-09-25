package http

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

// sessionCookieName is the cookie the browser carries, as the contract's security
// scheme names it. It holds the plaintext session id — the only place that value ever
// appears after sign-in returns it.
const sessionCookieName = "llmproxy_session"

// caller is who an authenticated request acts for: the session its cookie named and
// the owner loaded with it. The user travels alongside the session, not inside it —
// app.Session stays the store's shape, and a handler needing the person does not load
// them a second time.
type caller struct {
	session app.Session
	user    identity.User
}

// callerCtxKey is unexported and of a type no other package can name or construct.
// That is the point: a handler reaches a caller only if loadSession validated one and
// put it there. Nothing downstream can forge the value, and no accidental collision
// with another package's context key can produce one either.
type callerCtxKey struct{}

func withCaller(ctx context.Context, c caller) context.Context {
	return context.WithValue(ctx, callerCtxKey{}, c)
}

// callerFrom returns the validated caller on ctx, if there is one.
func callerFrom(ctx context.Context) (caller, bool) {
	c, ok := ctx.Value(callerCtxKey{}).(caller)

	return c, ok
}

// cookies writes the session cookie with the deployment's Secure setting and clock.
type cookies struct {
	secure bool
	clock  app.Clock
}

// setSession writes the session id to the browser.
//
// HttpOnly keeps it out of reach of any script on the page, so an XSS bug cannot read
// it out. Secure keeps it off plaintext transport (only a development setup turns it
// off). SameSite=Lax is what makes the cabinet's state-changing endpoints safe from a
// cross-site form post while still letting a person follow a link into the
// application and arrive signed in. Max-Age is what is left of the session's window.
func (c cookies) setSession(w http.ResponseWriter, sess app.Session) {
	//nolint:gosec // HttpOnly and Lax are set; Secure is the deployment's CookieSecure, off only for plain-http development.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sess.ID,
		Path:     "/",
		MaxAge:   max(1, int(sess.ExpiresAt.Sub(c.clock.Now())/time.Second)),
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSession retires the cookie on sign-out. The attributes have to match the ones
// it was set with or the browser keeps the original.
func (c cookies) clearSession(w http.ResponseWriter) {
	//nolint:gosec // Mirrors setSession's attributes; Secure is the deployment's CookieSecure, off only for plain-http development.
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   c.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// loadSession resolves the session cookie and attaches the caller it names.
//
// It never rejects a request for want of a session: a missing, unknown or expired
// cookie simply produces a request with no caller, and requireSession is what turns
// that into a 401. Keeping the two apart is what lets an endpoint be reachable both
// signed in and not. Which sessions are valid, and whether one is restricted, is
// app.AuthService.ResolveSession's to decide.
func loadSession(auth *app.AuthService, log app.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		cookie, err := req.Cookie(sessionCookieName)
		if err != nil || cookie.Value == "" {
			next.ServeHTTP(rw, req)

			return
		}

		sess, user, err := auth.ResolveSession(req.Context(), cookie.Value)
		switch {
		case errors.Is(err, app.ErrNotFound):
			next.ServeHTTP(rw, req)
		case err != nil:
			// A failure of the lookup, not a verdict on the request: it must
			// not be mistaken for one.
			internalError(rw, req, log, err)
		default:
			next.ServeHTTP(rw, req.WithContext(withCaller(req.Context(), caller{session: sess, user: user})))
		}
	})
}

// requireSession admits any live session, restricted or not. It guards only the
// routes a person holding a temporary password still has to reach (restrictedAllowed).
func requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if _, ok := callerFrom(req.Context()); !ok {
			writeError(rw, http.StatusUnauthorized, codeUnauthenticated, "no valid session")

			return
		}

		next.ServeHTTP(rw, req)
	})
}

// requireFullSession admits only an unrestricted session. It is the default guard.
//
// This is what keeps must_change_password from degrading into a banner. A session
// opened with a temporary password is refused here with 403 — not redirected, not
// warned about — so every endpoint behind this guard is genuinely out of reach until
// the password is changed. 403 and not 401 because the caller is authenticated; there
// is nothing to sign in again for.
func requireFullSession(next http.Handler) http.Handler {
	return requireSession(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if c, _ := callerFrom(req.Context()); c.session.Restricted {
			writeError(rw, http.StatusForbidden, codePasswordChangeRequired, "the temporary password must be changed first")

			return
		}

		next.ServeHTTP(rw, req)
	}))
}

// requireAdmin admits only an administrator; it sits behind requireFullSession. To
// anyone else the administration API does not exist: they get the answer an unknown
// route gets, 404 not_found, as the frontend shows them not-found for /admin. The
// application services check the role again; this guard is what keeps a
// non-administrator from learning which admin routes and ids exist.
func requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if c, _ := callerFrom(req.Context()); c.user.Role != identity.RoleAdmin {
			writeError(rw, http.StatusNotFound, codeNotFound, "no such endpoint")

			return
		}

		next.ServeHTTP(rw, req)
	})
}

// internalError logs err and answers the contract's 500. The error text goes to the
// log only: it may name internals, and the client has no use for them.
func internalError(w http.ResponseWriter, r *http.Request, log app.Logger, err error) {
	log.Warn("internal error serving request",
		slog.String("method", r.Method), slog.String("path", r.URL.Path), slog.Any("err", err))
	writeError(w, http.StatusInternalServerError, codeInternal, "internal error")
}
