package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// pathOf turns a ServeMux pattern into a request line that matches it.
func pathOf(pattern string) (string, string) {
	method, path, _ := strings.Cut(pattern, " ")
	path = strings.ReplaceAll(path, "{userId}", uuid.NewString())
	path = strings.ReplaceAll(path, "{accountId}", "claude-someone.json")

	return method, strings.ReplaceAll(path, "{tokenId}", uuid.NewString())
}

// allRoutes is every pattern the router serves.
func allRoutes() []string {
	routes := (&router{}).routes()

	out := make([]string, 0, len(routes))
	for p := range routes {
		out = append(out, p)
	}

	return out
}

// The contract's Conventions, written out here rather than read from the router: a
// restricted session reaches GET /api/me, POST /api/auth/password and
// POST /api/auth/logout, and nothing else. Every other route that needs a session
// answers it 403 password_change_required — including any route added later, which is
// why this walks the router's table instead of listing today's routes.
func TestARestrictedSessionReachesOnlyTheContractsAllowList(t *testing.T) {
	contract := map[string]bool{
		"GET /api/me":             true,
		"POST /api/auth/password": true,
		"POST /api/auth/logout":   true,
	}
	for _, pattern := range allRoutes() {
		if anonymous[pattern] && !contract[pattern] {
			continue
		}

		t.Run(pattern, func(t *testing.T) {
			env := newEnv(t)
			user := person("restricted@example.com")
			user.MustChangePassword = true
			method, path := pathOf(pattern)
			// A malformed body: a route the guard admits refuses it as input (or
			// ignores it), a route it refuses never reads it.
			env.sessions.EXPECT().Delete(mock.Anything, mock.Anything).Return(nil).Maybe()

			rec := env.do(method, path, "{", withCookie(env.signedIn(user)))
			if contract[pattern] {
				require.NotEqual(t, http.StatusForbidden, rec.Code, "the contract lets a restricted session reach this; body %s", rec.Body)
				require.NotEqual(t, http.StatusUnauthorized, rec.Code, "the contract lets a restricted session reach this; body %s", rec.Body)

				return
			}

			apiError(t, rec, http.StatusForbidden, codePasswordChangeRequired)
		})
	}
}

// Every route that is not explicitly anonymous needs a session, and says so with the
// one code a client treats as "signed out".
func TestEveryAuthenticatedRouteRefusesARequestWithoutASession(t *testing.T) {
	for _, pattern := range allRoutes() {
		if anonymous[pattern] {
			continue
		}

		t.Run(pattern, func(t *testing.T) {
			method, path := pathOf(pattern)
			apiError(t, newEnv(t).do(method, path, "{}"), http.StatusUnauthorized, codeUnauthenticated)
		})
	}
}

// The administration API does not exist for anyone but an administrator: a person
// with a full session gets what an unrouted path gets, whatever they send. The body
// and query are ones every admin handler would refuse as input, so a route that let
// the request through to its handler answers something else.
func TestEveryAdminRouteIsNotFoundToANonAdministrator(t *testing.T) {
	for _, pattern := range allRoutes() {
		if !adminOnly(pattern) {
			continue
		}

		t.Run(pattern, func(t *testing.T) {
			e := newEnv(t)
			method, path := pathOf(pattern)
			rec := e.do(method, path+"?limit=0", "{", withCookie(e.signedIn(person("p@example.com"))))
			apiError(t, rec, http.StatusNotFound, codeNotFound)
		})
	}
}

// Admin routes cannot be served without their services.
func TestNewRouterRefusesAMissingAdminService(t *testing.T) {
	env := newEnv(t)
	for name, drop := range map[string]func(*Deps){
		"users":     func(d *Deps) { d.AdminUsers = nil },
		"settings":  func(d *Deps) { d.Settings = nil },
		"prices":    func(d *Deps) { d.Prices = nil },
		"providers": func(d *Deps) { d.Providers = nil },
	} {
		d := env.deps
		drop(&d)

		_, err := NewRouter(d)
		assert.Error(t, err, "NewRouter without the %s service", name)
	}
}

// Every refusal the middleware writes is the contract's JSON Error: a client that
// renders from `code` must never meet a text/plain body.
func TestEveryMiddlewareRefusalIsAJSONError(t *testing.T) {
	big := strings.Repeat("x", maxBodyBytes+1)

	cases := []struct {
		name   string
		send   func(e *testEnv) *httptest.ResponseRecorder
		status int
		code   string
	}{
		{"content type", func(e *testEnv) *httptest.ResponseRecorder {
			return e.do(http.MethodPost, "/api/auth/login", `{}`, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") })
		}, http.StatusUnsupportedMediaType, codeUnsupportedMediaType},
		{"no content type on a body-less post", func(e *testEnv) *httptest.ResponseRecorder {
			return e.do(http.MethodPost, "/api/auth/logout", "", func(r *http.Request) { r.Header.Del("Content-Type") })
		}, http.StatusUnsupportedMediaType, codeUnsupportedMediaType},
		{"declared body too large", func(e *testEnv) *httptest.ResponseRecorder {
			return e.do(http.MethodPost, "/api/auth/login", big)
		}, http.StatusRequestEntityTooLarge, codePayloadTooLarge},
		{"undeclared body too large", func(e *testEnv) *httptest.ResponseRecorder {
			return e.do(http.MethodPost, "/api/auth/login", `{"email":"`+big+`"}`, func(r *http.Request) { r.ContentLength = -1 })
		}, http.StatusRequestEntityTooLarge, codePayloadTooLarge},
		{"no session", func(e *testEnv) *httptest.ResponseRecorder {
			return e.do(http.MethodGet, "/api/me", "")
		}, http.StatusUnauthorized, codeUnauthenticated},
		{"restricted session", func(e *testEnv) *httptest.ResponseRecorder {
			u := person("restricted@example.com")
			u.MustChangePassword = true

			return e.do(http.MethodGet, "/api/connect", "", withCookie(e.signedIn(u)))
		}, http.StatusForbidden, codePasswordChangeRequired},
		{"unknown path", func(e *testEnv) *httptest.ResponseRecorder {
			return e.do(http.MethodGet, "/api/nothing-here", "")
		}, http.StatusNotFound, codeNotFound},
		{"known path, other method", func(e *testEnv) *httptest.ResponseRecorder {
			return e.do(http.MethodPut, "/api/me", "{}")
		}, http.StatusNotFound, codeNotFound},
		{"rate limit", func(e *testEnv) *httptest.ResponseRecorder {
			e.do(http.MethodPost, "/api/auth/login", "{")

			return e.do(http.MethodPost, "/api/auth/login", "{")
		}, http.StatusTooManyRequests, codeRateLimited},
		{"session store down", func(e *testEnv) *httptest.ResponseRecorder {
			e.sessions.EXPECT().ByHash(mock.Anything, mock.Anything).Return(app.Session{}, errors.New("connection refused"))

			return e.do(http.MethodGet, "/api/me", "", withCookie(&http.Cookie{Name: sessionCookieName, Value: "x"}))
		}, http.StatusInternalServerError, codeInternal},
		{"panic", func(e *testEnv) *httptest.ResponseRecorder {
			e.usage.EXPECT().SeriesForUser(mock.Anything, mock.Anything, mock.Anything, mock.Anything).
				RunAndReturn(func(_ context.Context, _ uuid.UUID, _, _ time.Time) (app.UsageSeries, error) { panic("boom") })

			return e.do(http.MethodGet, "/api/me/usage", "", withCookie(e.signedIn(person("p@example.com"))))
		}, http.StatusInternalServerError, codeInternal},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, withRate(RateLimit{Burst: 1, Every: time.Minute, MaxClients: 10}))
			apiError(t, c.send(e), c.status, c.code)
		})
	}
}

// An internal failure is logged for the operator and never described to the client.
func TestAnInternalErrorKeepsItsTextOutOfTheResponse(t *testing.T) {
	env := newEnv(t)

	const detail = "pq: relation sessions does not exist at 192.0.2.5"
	env.sessions.EXPECT().ByHash(mock.Anything, mock.Anything).Return(app.Session{}, errors.New(detail))
	rec := env.do(http.MethodGet, "/api/me", "", withCookie(&http.Cookie{Name: sessionCookieName, Value: "x"}))
	apiError(t, rec, http.StatusInternalServerError, codeInternal)

	require.NotContains(t, rec.Body.String(), "relation", "the response describes the failure")
	require.Contains(t, env.log.text(), detail, "the failure was not logged")
}

// A JSON content type with parameters is still JSON.
func TestAJSONContentTypeWithACharsetIsAccepted(t *testing.T) {
	e := newEnv(t)

	rec := e.do(http.MethodPost, "/api/auth/logout", "", func(r *http.Request) {
		r.Header.Set("Content-Type", "application/json; charset=utf-8")
	})
	require.Equal(t, http.StatusNoContent, rec.Code, "status; body %s", rec.Body)
}

// DELETE carries no body, so it needs no content type: the frontend sets the header
// on POST, PUT and PATCH only.
func TestADeleteWithoutAContentTypeIsServed(t *testing.T) {
	env := newEnv(t)
	user := person("person@example.com")

	mine, _, err := credentials.Generate(user.ID, "mine")
	require.NoError(t, err, "Generate")

	env.tokens.EXPECT().ByID(mock.Anything, mine.ID).Return(mine, nil)
	env.tokens.EXPECT().Save(mock.Anything, mock.Anything).Return(nil)

	rec := env.do(http.MethodDelete, "/api/me/tokens/"+mine.ID.String(), "", withCookie(env.signedIn(user)))
	require.Equal(t, http.StatusNoContent, rec.Code, "status; body %s", rec.Body)
}

// rateRefused reports whether rec is a rate-limit refusal of either kind.
func rateRefused(rec *httptest.ResponseRecorder) bool {
	return rec.Code == http.StatusTooManyRequests || rec.Header().Get("Location") == loginRateLimited
}

// The limit covers exactly the routes that spend password work or start a sign-in,
// and it is per client: the key is X-Real-IP, set by the frontend's proxy. The API
// routes refuse with 429 JSON; the OIDC routes are browser navigations and send the
// browser back to the login page instead.
func TestSignInRoutesAreRateLimitedPerClient(t *testing.T) {
	limited := map[string]bool{ // pattern -> navigational
		"POST /api/auth/login":        false,
		"POST /api/auth/password":     false,
		"GET /api/auth/oidc/start":    true,
		"GET /api/auth/oidc/callback": true,
	}
	for pattern, navigational := range limited {
		t.Run(pattern, func(t *testing.T) {
			checkSignInRouteLimit(t, pattern, navigational)
		})
	}

	t.Run("other routes", func(t *testing.T) {
		e := newEnv(t, withRate(RateLimit{Burst: 1, Every: time.Hour, MaxClients: 10}))
		for i := range 3 {
			rec := e.do(http.MethodGet, "/api/auth/config", "")
			require.Equal(t, http.StatusOK, rec.Code, "attempt %d: status", i+1)
		}
	})
}

// checkSignInRouteLimit asserts pattern admits one attempt per client per bucket
// refill and refuses the next the way its kind of route must: navigational routes
// redirect to the login page, the others answer 429 JSON with Retry-After.
func checkSignInRouteLimit(t *testing.T, pattern string, navigational bool) {
	t.Helper()

	env := newEnv(t, withRate(RateLimit{Burst: 1, Every: 10 * time.Second, MaxClients: 10}))

	method, path := pathOf(pattern)
	require.False(t, rateRefused(env.do(method, path, "{", fromIP("198.51.100.1"))), "the first attempt was refused")

	rec := env.do(method, path, "{", fromIP("198.51.100.1"))
	if navigational {
		require.Equal(t, http.StatusFound, rec.Code, "status")
		require.Equal(t, loginRateLimited, rec.Header().Get("Location"), "redirect")
		require.NotEqual(t, "application/json", rec.Header().Get("Content-Type"), "a navigational route answered with JSON")
	} else {
		apiError(t, rec, http.StatusTooManyRequests, codeRateLimited)
		require.Equal(t, "10", rec.Header().Get("Retry-After"), "Retry-After")
	}
	// Another client behind the same proxy connection is not limited.
	require.False(t, rateRefused(env.do(method, path, "{", fromIP("198.51.100.2"))), "a different client was refused")
	// Once the bucket refills the first client is admitted again.
	env.clock.advance(10 * time.Second)

	require.False(t, rateRefused(env.do(method, path, "{", fromIP("198.51.100.1"))), "the client was still refused after the bucket refilled")
}

// An IPv6 client can use any address of its /64, so the /64 is what is limited: two
// addresses in one /64 share a bucket, and a neighbouring /64 has its own.
func TestIPv6ClientsAreLimitedByTheirSlash64(t *testing.T) {
	env := newEnv(t, withRate(RateLimit{Burst: 1, Every: time.Hour, MaxClients: 10}))
	require.False(t, rateRefused(env.do(http.MethodPost, "/api/auth/login", "{", fromIP("2001:db8:0:1::1"))), "the first attempt was refused")

	rec := env.do(http.MethodPost, "/api/auth/login", "{", fromIP("2001:db8:0:1:ffff:ffff:ffff:ffff"))
	apiError(t, rec, http.StatusTooManyRequests, codeRateLimited)

	require.False(t, rateRefused(env.do(http.MethodPost, "/api/auth/login", "{", fromIP("2001:db8:0:2::1"))), "a client in another /64 was refused")
}

// Without X-Real-IP (or with garbage in it) the connection's peer is the client.
func TestClientIPFallsBackToThePeerAddress(t *testing.T) {
	for header, want := range map[string]string{
		"":                 "192.0.2.10",
		"not an address":   "192.0.2.10",
		"203.0.113.7":      "203.0.113.7",
		" 2001:db8::1 ":    "2001:db8::1",
		"::ffff:192.0.2.9": "192.0.2.9",
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", http.NoBody)

		req.RemoteAddr = testClientAddr
		if header != "" {
			req.Header.Set("X-Real-IP", header)
		}

		assert.Equal(t, want, clientIP(req), "X-Real-IP %q: clientIP", header)
	}
}

// Retry-After is whole seconds rounded up: a client that waits exactly that long is
// admitted, never refused once more for a fraction of a second.
func TestRetryAfterRoundsUp(t *testing.T) {
	for wait, want := range map[time.Duration]int{
		1500 * time.Millisecond: 2,
		3 * time.Second:         3,
		0:                       1,
		-time.Second:            1,
	} {
		rec := httptest.NewRecorder()
		writeRetryAfter(rec, wait, codeRateLimited, "slow down")

		assert.Equal(t, strconv.Itoa(want), rec.Header().Get("Retry-After"), "wait %v: Retry-After", wait)
	}
}

func TestNewRouterRefusesOIDCWithoutAUsableKey(t *testing.T) {
	e := newEnv(t, withOIDC)
	d := e.deps

	d.SessionKey = []byte("too short")
	_, err := NewRouter(d)
	require.Error(t, err, "NewRouter accepted OIDC with a short session key")
}

func TestServerHasEveryTimeoutSet(t *testing.T) {
	s := NewServer("127.0.0.1:0", http.NotFoundHandler())
	require.Positive(t, s.ReadHeaderTimeout, "ReadHeaderTimeout: a zero timeout lets a client hold a connection forever")
	require.Positive(t, s.ReadTimeout, "ReadTimeout: a zero timeout lets a client hold a connection forever")
	require.Positive(t, s.WriteTimeout, "WriteTimeout: a zero timeout lets a client hold a connection forever")
	require.Positive(t, s.IdleTimeout, "IdleTimeout: a zero timeout lets a client hold a connection forever")
	require.Positive(t, s.MaxHeaderBytes, "MaxHeaderBytes must be set")
}
