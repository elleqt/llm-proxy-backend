package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

func TestRestrictedSessionIsRejectedByFullSessionGuard(t *testing.T) {
	handler := requireFullSession(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/me/tokens", nil)
	req = req.WithContext(withCaller(req.Context(), caller{session: app.Session{Restricted: true}}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestFullSessionPasses(t *testing.T) {
	handler := requireFullSession(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/api/me/tokens", nil)
	req = req.WithContext(withCaller(req.Context(), caller{session: app.Session{Restricted: false}}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// The other half of the restriction: the endpoint that changes the password has to
// stay reachable, or a restricted session is a locked door with no key.
func TestRequireSessionAdmitsARestrictedSession(t *testing.T) {
	handler := requireSession(okHandler())
	req := httptest.NewRequest(http.MethodPost, "/api/me/password", nil)
	req = req.WithContext(withCaller(req.Context(), caller{session: app.Session{Restricted: true}}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// 401 and not 403: there is no session at all, so signing in is the remedy.
func TestBothGuardsRefuseARequestWithNoSession(t *testing.T) {
	for name, guard := range map[string]func(http.Handler) http.Handler{
		"requireSession":     requireSession,
		"requireFullSession": requireFullSession,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			guard(okHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/me", nil))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
		})
	}
}

// otherKey stands in for any context key another package might use. The session key
// is unexported and of an unexported type, so no value planted from outside this
// package can be read back as a validated session.
type otherKey struct{}

func TestASessionCanOnlyComeFromThisPackage(t *testing.T) {
	ctx := context.WithValue(context.Background(), otherKey{}, caller{})
	if _, ok := callerFrom(ctx); ok {
		t.Fatal("a session planted under a foreign key was accepted as validated")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/me/tokens", nil).WithContext(ctx)
	requireFullSession(okHandler()).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// A live user who owns the session, for the cases where the user is not what is
// under test.
func activeUser(id uuid.UUID) identity.User {
	return identity.User{
		ID:           id,
		Kind:         identity.KindHuman,
		Email:        "person@example.com",
		Role:         identity.RoleUser,
		Status:       identity.StatusActive,
		PolicySource: identity.PolicyLocal,
	}
}

// An expired session does not authenticate. The store applies the window, so the
// middleware sees the same answer it would see for an id that never existed — and
// never gets as far as loading a user.
func TestAnExpiredSessionDoesNotAuthenticate(t *testing.T) {
	const id = "a-session-id"
	sessions := mocks.NewSessionRepo(t)
	users := mocks.NewUserRepo(t)
	sessions.EXPECT().ByHash(mock.Anything, app.HashSessionID(id)).
		Return(app.Session{}, app.ErrNotFound)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/me/tokens", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: id})

	loadSession(resolverOver(users, sessions), &testLog{t: t}, requireSession(okHandler())).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// The cookie carries the plaintext id; the lookup key is its hash. A middleware that
// passed the cookie value through would make the stored column as good as the cookie.
func TestLoadSessionResolvesTheCookieByItsHash(t *testing.T) {
	const id = "a-session-id"
	owner := uuid.New()
	stored := app.Session{IDHash: app.HashSessionID(id), UserID: owner}

	sessions := mocks.NewSessionRepo(t)
	sessions.EXPECT().ByHash(mock.Anything, app.HashSessionID(id)).Return(stored, nil)
	users := mocks.NewUserRepo(t)
	users.EXPECT().ByID(mock.Anything, owner).Return(activeUser(owner), nil)

	var got caller
	var ok bool
	handler := loadSession(resolverOver(users, sessions), &testLog{t: t}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok = callerFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: id})
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if !ok {
		t.Fatal("the handler saw no session")
	}
	if got.session.UserID != owner || got.user.ID != owner {
		t.Fatalf("caller = %+v, want the owner %v", got, owner)
	}
	if got.session.ID != "" {
		t.Fatalf("the loaded session carries the plaintext id %q", got.session.ID)
	}
}

// The restriction is read off the user at every request, not off the session row.
// That is what makes a temporary password issued after sign-in bind the session the
// person is holding now instead of the next one they open.
func TestARestrictionIssuedAfterSignInBindsTheLiveSession(t *testing.T) {
	const id = "a-session-id"
	owner := uuid.New()
	// The row is exactly what SignIn wrote before the administrator acted: it
	// carries no restriction, and there is nowhere for one to have been recorded.
	stored := app.Session{IDHash: app.HashSessionID(id), UserID: owner}

	user := activeUser(owner)
	user.MustChangePassword = true

	sessions := mocks.NewSessionRepo(t)
	sessions.EXPECT().ByHash(mock.Anything, app.HashSessionID(id)).Return(stored, nil)
	users := mocks.NewUserRepo(t)
	users.EXPECT().ByID(mock.Anything, owner).Return(user, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/me/tokens", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: id})
	loadSession(resolverOver(users, sessions), &testLog{t: t}, requireFullSession(okHandler())).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: the live session was not restricted by a "+
			"temporary password issued after it was opened", rec.Code)
	}
}

// Blocking a user ends their session now, not when its window closes twelve hours
// later. Same predicate that refuses them at sign-in, so a service account that
// somehow held a cookie is refused too.
func TestBlockingAUserEndsTheirLiveSession(t *testing.T) {
	const id = "a-session-id"
	owner := uuid.New()
	stored := app.Session{IDHash: app.HashSessionID(id), UserID: owner}

	blocked := activeUser(owner)
	blocked.Status = identity.StatusBlocked

	sessions := mocks.NewSessionRepo(t)
	sessions.EXPECT().ByHash(mock.Anything, app.HashSessionID(id)).Return(stored, nil)
	users := mocks.NewUserRepo(t)
	users.EXPECT().ByID(mock.Anything, owner).Return(blocked, nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/me/password", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: id})
	loadSession(resolverOver(users, sessions), &testLog{t: t}, requireSession(okHandler())).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: a blocked user kept their session", rec.Code)
	}
}

// A lookup that failed is not a verdict. Treating a database outage as "not signed
// in" would silently sign everyone out and hide the outage. Both lookups, because
// either one can be the one that is down.
func TestLoadSessionFailsLoudlyWhenAStoreIsUnreachable(t *testing.T) {
	const id = "a-session-id"
	owner := uuid.New()
	down := errors.New("database unreachable")

	t.Run("the session store", func(t *testing.T) {
		sessions := mocks.NewSessionRepo(t)
		sessions.EXPECT().ByHash(mock.Anything, mock.Anything).Return(app.Session{}, down)
		users := mocks.NewUserRepo(t)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: id})
		loadSession(resolverOver(users, sessions), &testLog{t: t}, requireSession(okHandler())).ServeHTTP(rec, req)

		apiError(t, rec, http.StatusInternalServerError, codeInternal)
	})

	t.Run("the user store", func(t *testing.T) {
		sessions := mocks.NewSessionRepo(t)
		sessions.EXPECT().ByHash(mock.Anything, mock.Anything).
			Return(app.Session{IDHash: app.HashSessionID(id), UserID: owner}, nil)
		users := mocks.NewUserRepo(t)
		users.EXPECT().ByID(mock.Anything, owner).Return(identity.User{}, down)

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: id})
		loadSession(resolverOver(users, sessions), &testLog{t: t}, requireSession(okHandler())).ServeHTTP(rec, req)

		apiError(t, rec, http.StatusInternalServerError, codeInternal)
	})
}

// A request with no cookie reaches the handler without a session rather than being
// rejected: the guards decide what needs one.
func TestLoadSessionPassesAnAnonymousRequestThrough(t *testing.T) {
	sessions := mocks.NewSessionRepo(t)
	users := mocks.NewUserRepo(t)

	var seen bool
	handler := loadSession(resolverOver(users, sessions), &testLog{t: t}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, seen = callerFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/health", nil))

	if seen {
		t.Fatal("a request with no cookie arrived with a session")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

// resolverOver is an AuthService that can resolve sessions and nothing else.
func resolverOver(users app.UserRepo, sessions app.SessionRepo) *app.AuthService {
	return app.NewAuthService(users, nil, nil, nil, sessions, nil, nil)
}
