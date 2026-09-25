package http

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/adminusers"
	"github.com/elleqt/llm-proxy-backend/internal/app/auth"
	"github.com/elleqt/llm-proxy-backend/internal/app/settings"
	"github.com/elleqt/llm-proxy-backend/internal/app/tokens"
)

// Deps is what the web API is built from.
type Deps struct {
	Auth   *auth.Service
	Tokens *tokens.Service
	// OIDC is nil when federated sign-in is not configured; /api/auth/config then
	// says so and /api/auth/oidc/start answers oidc_disabled.
	OIDC *auth.OIDC
	// OIDCDisplayName is the sign-in button's label; empty leaves it to the client.
	OIDCDisplayName string
	// LocalLogin offers sign-in with an email and a password. Off, the login form is
	// not offered and POST /api/auth/login answers as an unknown route does.
	LocalLogin bool
	// Usage serves the cabinet's consumption chart.
	Usage *app.UsageService
	// Models serves the cabinet's list of the models the caller may use.
	Models *app.ModelsService

	// The administration API's services.
	AdminUsers *adminusers.Service
	Settings   *settings.Service
	Prices     *app.Prices
	Providers  *app.Providers

	Clock app.Clock
	Log   app.Logger

	// PublicAPIURL is the proxied API's public base URL, without a trailing slash.
	PublicAPIURL string
	// CookieSecure marks the cookies Secure. Only local development over plain
	// http turns it off.
	CookieSecure bool
	// SessionKey seals the OIDC challenge cookie (see challengeSealer). Required,
	// at least 32 bytes, when OIDC is set.
	SessionKey []byte
	// SignInRate limits each client on the sign-in and password routes. The zero
	// value means DefaultSignInRate.
	SignInRate RateLimit
}

// The route patterns more than one access table below names.
const (
	routeLogin        = "POST /api/auth/login"
	routePassword     = "POST /api/auth/password" //nolint:gosec // a route pattern, not a credential
	routeOIDCStart    = "GET /api/auth/oidc/start"
	routeOIDCCallback = "GET /api/auth/oidc/callback"
)

// NewRouter's refusals of an incomplete Deps.
var (
	errMissingDependency = errors.New("web: router is missing a dependency")
	errNoPublicAPIURL    = errors.New("web: router needs the public API URL")
	errBadSignInRate     = errors.New("web: sign-in rate limit needs a positive burst, interval and client bound")
)

// anonymous lists the routes that need no session. Every other route needs one.
var anonymous = map[string]bool{
	"GET /api/auth/config": true,
	routeLogin:             true,
	routeOIDCStart:         true,
	routeOIDCCallback:      true,
	// Signing out needs no session: a cookie whose session is already gone must
	// still be cleared (logout signs out the session when there is one).
	"POST /api/auth/logout": true,
}

// restrictedAllowed is every authenticated route a restricted session — one opened
// with a temporary password that has not been changed — may reach, as the contract's
// Conventions list them (logout, the third, is anonymous). Every other authenticated
// route, including any added later, requires a full session: the restriction is the
// default, and this list is the only way out of it.
var restrictedAllowed = map[string]bool{
	"GET /api/me": true,
	routePassword: true,
}

// signInLimited lists the routes the per-client rate limit applies to — the ones that
// spend password work or start a sign-in — with how each refuses. The OIDC routes are
// browser navigations, so they redirect to the login page instead of answering JSON.
var signInLimited = map[string]func(http.ResponseWriter, *http.Request, time.Duration){
	routeLogin:        refuseJSON,
	routePassword:     refuseJSON,
	routeOIDCStart:    refuseNavigation,
	routeOIDCCallback: refuseNavigation,
}

// adminPrefix starts every administration route. Each one needs a full session of an
// administrator (requireAdmin), whatever the tables above say.
const adminPrefix = "/api/admin/"

func adminOnly(pattern string) bool {
	_, path, _ := strings.Cut(pattern, " ")

	return strings.HasPrefix(path, adminPrefix)
}

// router holds the handlers' dependencies.
type router struct {
	Deps

	cookies cookies
	sealer  *challengeSealer // nil without OIDC
}

// NewRouter builds the web API: /api/auth/*, the cabinet (/api/me/*), /api/connect
// and the administration API (/api/admin/*). It is served on its own listener
// (config.Web.Addr), never on the proxied API's.
//
// Every response it writes on failure — from a handler or from any middleware — is
// the contract's JSON Error. The chain, outermost first: panic recovery, the body
// cap, the JSON content-type requirement for mutating requests, session loading,
// then per route the rate limit, the session guard and, on /api/admin/*, the
// administrator guard.
func NewRouter(deps Deps) (http.Handler, error) {
	if deps.Auth == nil || deps.Tokens == nil || deps.Usage == nil || deps.Models == nil || deps.Clock == nil || deps.Log == nil ||
		deps.AdminUsers == nil || deps.Settings == nil || deps.Prices == nil || deps.Providers == nil {
		return nil, errMissingDependency
	}

	if deps.PublicAPIURL == "" {
		return nil, errNoPublicAPIURL
	}

	if deps.SignInRate == (RateLimit{}) {
		deps.SignInRate = DefaultSignInRate
	}

	if deps.SignInRate.Burst < 1 || deps.SignInRate.Every <= 0 || deps.SignInRate.MaxClients < 1 {
		return nil, errBadSignInRate
	}

	rt := &router{Deps: deps, cookies: cookies{secure: deps.CookieSecure, clock: deps.Clock}}
	if deps.OIDC != nil {
		s, err := newChallengeSealer(deps.SessionKey, deps.Clock)
		if err != nil {
			return nil, err
		}

		rt.sealer = s
	}

	limit := newLimiter(deps.SignInRate, deps.Clock)
	mux := http.NewServeMux()

	for pattern, h := range rt.routes() {
		var handler http.Handler = h
		if adminOnly(pattern) {
			handler = requireAdmin(handler)
		}

		switch {
		case anonymous[pattern]:
		case restrictedAllowed[pattern]:
			handler = requireSession(handler)
		default:
			handler = requireFullSession(handler)
		}

		if refuse, ok := signInLimited[pattern]; ok {
			handler = rateLimited(limit, refuse, handler)
		}

		mux.Handle(pattern, handler)
	}
	// Everything unrouted — an unknown path, or a known one with another method —
	// lands here rather than in ServeMux's plain-text 404 and 405.
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, codeNotFound, "no such endpoint")
	})

	return recoverPanics(deps.Log, limitBody(requireJSON(loadSession(deps.Auth, deps.Log, mux)))), nil
}

// routes is every endpoint by its ServeMux pattern. Access is not decided here:
// NewRouter applies anonymous, restrictedAllowed, signInLimited and adminOnly to
// these keys.
func (rt *router) routes() map[string]http.HandlerFunc {
	routes := map[string]http.HandlerFunc{
		"GET /api/auth/config":            rt.getAuthConfig,
		routeLogin:                        rt.login,
		"POST /api/auth/logout":           rt.logout,
		routePassword:                     rt.changePassword,
		routeOIDCStart:                    rt.startOIDC,
		routeOIDCCallback:                 rt.oidcCallback,
		"GET /api/me":                     rt.getMe,
		"GET /api/me/tokens":              rt.listMyTokens,
		"POST /api/me/tokens":             rt.issueMyToken,
		"DELETE /api/me/tokens/{tokenId}": rt.revokeMyToken,
		"GET /api/me/usage":               rt.getMyUsage,
		"GET /api/me/models":              rt.listMyModels,
		"GET /api/connect":                rt.getConnectInfo,
	}
	if !rt.LocalLogin {
		delete(routes, routeLogin)
	}

	rt.registerAdminUsers(routes)
	rt.registerAdminSettings(routes)
	rt.registerAdminProviders(routes)

	return routes
}

// adminFailure answers an administration service's error by appRefusals.
func (rt *router) adminFailure(w http.ResponseWriter, r *http.Request, err error) {
	writeAppError(w, r, rt.Log, err)
}

// internal logs err and answers 500.
func (rt *router) internal(w http.ResponseWriter, r *http.Request, err error) {
	internalError(w, r, rt.Log, err)
}

// NewServer is the web listener's server: every timeout set, so a slow or idle
// client cannot hold a connection open indefinitely, and headers bounded.
func NewServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}
