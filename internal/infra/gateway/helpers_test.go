package gateway

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// The tests in this package must stay serial: none may call t.Parallel().
// Several change process-wide state for their duration — withBodyBudget
// swaps the package's body budget and wait, the heap-peak test lowers the GC
// percentage (debug.SetGCPercent), and t.Setenv pins the environment — and
// every gateway shares upstream's process-global model registry, token
// store, usage manager and its plugins. A parallel test would see another's
// state and fail far from the cause.

// gateEngine is a bare gin engine behind the policy gate, for tests serving
// it through httptest recorders, which offer no read deadline: the gate is
// handed a controller whose deadlines are accepted and ignored. Tests of the
// deadline itself serve the real engine (startWith).
func gateEngine(resolver Resolver, catalog access.Catalog) *gin.Engine {
	engine := gin.New()
	engine.Use(func(c *gin.Context) {
		c.Set(readDeadlineKey, http.NewResponseController(deadlineIgnored{c.Writer}))
	}, policyGate(resolver, catalog, nil, nil))

	return engine
}

// deadlineIgnored is a response writer accepting any read deadline.
type deadlineIgnored struct{ gin.ResponseWriter }

func (deadlineIgnored) SetReadDeadline(time.Time) error { return nil }

// resolverFunc is a Resolver stub. It is not a mock: tests assert on what the
// gateway does with its answer, not on how it was called.
type resolverFunc func(ctx context.Context, secret string) (app.Principal, access.Policy, error)

func (f resolverFunc) Resolve(ctx context.Context, secret string) (app.Principal, access.Policy, error) {
	return f(ctx, secret)
}

// mustPolicy is the policy rules parse to; a malformed rule is a broken test.
func mustPolicy(rules ...string) access.Policy {
	policy := make(access.Policy, 0, len(rules))
	for _, s := range rules {
		rule, err := access.ParseRule(s)
		if err != nil {
			panic(err)
		}

		policy = append(policy, rule)
	}

	return policy
}

// staticResolver accepts exactly secret, as principal whose owner's policy is rules,
// and refuses everything else the way app.TokenResolver refuses.
func staticResolver(secret string, principal app.Principal, rules ...string) resolverFunc {
	policy := mustPolicy(rules...)

	return func(_ context.Context, presented string) (app.Principal, access.Policy, error) {
		if presented != secret {
			return app.Principal{}, nil, app.ErrInvalidCredentials
		}

		return principal, policy, nil
	}
}

// switchableResolver accepts wireSecret as wirePrincipal, whose policy a test
// changes between requests.
type switchableResolver struct {
	mu    sync.Mutex
	rules []string
}

func (r *switchableResolver) Resolve(ctx context.Context, secret string) (app.Principal, access.Policy, error) {
	r.mu.Lock()
	rules := r.rules
	r.mu.Unlock()

	return staticResolver(wireSecret, wirePrincipal, rules...)(ctx, secret)
}

func (r *switchableResolver) set(rules ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.rules = rules
}

// wireSecret is the one API token the gateways under test accept, as
// wirePrincipal allowed every model, unless a test supplies its own Resolver.
const wireSecret = "sk-wire-client-secret"

var (
	wirePrincipal = app.Principal{
		UserID:  uuid.MustParse("0b6f3c1e-5d7a-4c2e-9f11-2a3b4c5d6e70"),
		TokenID: uuid.MustParse("7e6d5c4b-3a29-4f18-8e07-f6e5d4c3b2a1"),
	}
	wireResolver = staticResolver(wireSecret, wirePrincipal, "*:*")
)
