package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
)

// catalogFunc is an access.Catalog stub.
type catalogFunc func(model string) []string

func (f catalogFunc) ProvidersFor(model string) []string { return f(model) }

// fixedCatalog serves each model by the providers listed for it.
func fixedCatalog(served map[string][]string) catalogFunc {
	return func(model string) []string { return served[model] }
}

const gateSecret = "sk-gate-secret"

var gatePrincipal = app.Principal{UserID: uuid.New(), TokenID: uuid.New()}

// gated is a gin engine serving every route upstream registers behind the
// gate; reached reports whether a request got past it. A handler that is
// reached answers 200 with the image-edit form's model when there is one.
func gated(resolver Resolver, catalog access.Catalog) (*gin.Engine, *bool) {
	reached := new(bool)
	engine := gateEngine(resolver, catalog)

	for key := range routes {
		method, pattern, _ := strings.Cut(key, " ")
		engine.Handle(method, pattern, func(c *gin.Context) {
			*reached = true

			c.String(http.StatusOK, c.PostForm("model"))
		})
	}

	return engine, reached
}

func chat(engine *gin.Engine, key, model string) *httptest.ResponseRecorder {
	return post(engine, key, "/v1/chat/completions", "application/json", `{"model":"`+model+`","messages":[]}`)
}

func post(engine *gin.Engine, key, path, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)

	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	return rec
}

// TestGateSeesAProviderTheMomentItIsRegistered: when a second provider starts
// serving a model, a user allowed only the first must be refused from the
// instant upstream could route to the second — not once some copy of the
// registry catches up. The first registration is given time to be seen (a
// copy would lag there too, harmlessly); the second is followed at once by
// the request, on the same goroutine as the registration.
func TestGateSeesAProviderTheMomentItIsRegistered(t *testing.T) {
	model := "growing-" + t.Name()
	engine, reached := gated(staticResolver(gateSecret, gatePrincipal, "gatea:*"), registryCatalog(t))

	registerClient(t, "growing-client-a", "openai-compatible-gatea", model)

	deadline := time.Now().Add(5 * time.Second)
	for rec := chat(engine, gateSecret, model); rec.Code != http.StatusOK; rec = chat(engine, gateSecret, model) {
		if time.Now().After(deadline) {
			t.Fatalf("served by gatea alone = %d, want 200", rec.Code)
		}

		time.Sleep(5 * time.Millisecond)
	}

	*reached = false

	registerClient(t, "growing-client-b", "openai-compatible-gateb", model)

	if rec := chat(engine, gateSecret, model); rec.Code != http.StatusForbidden || *reached {
		t.Fatalf("served by gatea and gateb, straight after gateb registered = %d (reached %t), want 403", rec.Code, *reached)
	}
}

// TestGateDecidesImagesOnTheRoutedModel: image requests are decided on the
// model upstream routes them by — a JSON body's, upstream's default when it
// names none, or a multipart edit's form field, which the handler then still
// reads.
func TestGateDecidesImagesOnTheRoutedModel(t *testing.T) {
	catalog := fixedCatalog(map[string][]string{
		"gpt-image-2": {"chatgpt"}, "gpt-image-2.5": {"chatgpt"},
		"grok-imagine-image": {"xai"}, "grok-imagine-image-quality": {"xai"},
	})
	engine, reached := gated(staticResolver(gateSecret, gatePrincipal, "chatgpt:gpt-image-*"), catalog)

	const generations, edits = "/v1/images/generations", "/v1/images/edits"

	for _, tc := range []struct {
		what, path, contentType, body string
		want                          int
		denied                        string
	}{
		{"a generation of an allowed model", generations, "application/json", `{"model":"gpt-image-2.5","prompt":"a cat"}`, http.StatusOK, ""},
		{"a generation naming no model, as gpt-image-2", generations, "application/json", `{"prompt":"a cat"}`, http.StatusOK, ""},
		{"a generation of a denied model", generations, "application/json", `{"model":"xai/grok-imagine-image-quality","prompt":"a cat"}`, http.StatusForbidden, "grok-imagine-image-quality"},
		{"a JSON edit of a denied model", edits, "application/json", `{"model":"grok-imagine-image","prompt":"a cat"}`, http.StatusForbidden, "grok-imagine-image"},
	} {
		*reached = false

		rec := post(engine, gateSecret, tc.path, tc.contentType, tc.body)
		if rec.Code != tc.want || *reached != (tc.want == http.StatusOK) {
			t.Errorf("%s = %d %s (reached %t), want %d", tc.what, rec.Code, rec.Body, *reached, tc.want)
		}

		if tc.denied != "" && !strings.Contains(rec.Body.String(), "model "+tc.denied+" is not allowed") {
			t.Errorf("%s: 403 body %s does not name %s", tc.what, rec.Body, tc.denied)
		}
	}

	body, contentType := imageForm(t, [][2]string{{"model", "gpt-image-2"}, {"prompt", "a cat"}})
	*reached = false

	if rec := post(engine, gateSecret, edits, contentType, body); rec.Code != http.StatusOK || rec.Body.String() != "gpt-image-2" {
		t.Fatalf("a multipart edit of an allowed model = %d %q, want 200 and the form still readable", rec.Code, rec.Body)
	}

	body, contentType = imageForm(t, [][2]string{{"model", "grok-imagine-image"}, {"prompt", "a cat"}})

	*reached = false
	if rec := post(engine, gateSecret, edits, contentType, body); rec.Code != http.StatusForbidden || *reached {
		t.Fatalf("a multipart edit of a denied model = %d (reached %t), want 403", rec.Code, *reached)
	}
}

// TestGateRequiresEveryProviderOfAModel: upstream may route a model to any
// provider serving it, so a policy missing one of them must not admit it.
func TestGateRequiresEveryProviderOfAModel(t *testing.T) {
	catalog := fixedCatalog(map[string][]string{"shared-model": {"acme", "chatgpt"}})

	for _, only := range []string{"acme:*", "chatgpt:*"} {
		engine, reached := gated(staticResolver(gateSecret, gatePrincipal, only), catalog)
		if rec := chat(engine, gateSecret, "shared-model"); rec.Code != http.StatusForbidden || *reached {
			t.Fatalf("a model served by acme and chatgpt, policy %s only = %d (reached %t), want 403", only, rec.Code, *reached)
		}
	}

	engine, reached := gated(staticResolver(gateSecret, gatePrincipal, "chatgpt:*", "acme:shared-*"), catalog)
	if rec := chat(engine, gateSecret, "shared-model"); rec.Code != http.StatusOK || !*reached {
		t.Fatalf("a model served by acme and chatgpt, policy allowing both = %d (reached %t), want 200", rec.Code, *reached)
	}
}

// TestGateNamesOnlyTheRequestedModel: a model no provider serves and a model
// the policy does not allow get the same 403, naming the requested model and
// nothing the caller may use.
func TestGateNamesOnlyTheRequestedModel(t *testing.T) {
	catalog := fixedCatalog(map[string][]string{"gpt-5.6": {"chatgpt"}, "claude-sonnet-5": {"claude"}})
	engine, reached := gated(staticResolver(gateSecret, gatePrincipal, "chatgpt:*"), catalog)

	for _, model := range []string{"claude-sonnet-5", "no-such-model"} {
		rec := chat(engine, gateSecret, model)

		want := `{"error":{"message":"model ` + model + ` is not allowed","type":"permission_error"}}`
		if rec.Code != http.StatusForbidden || rec.Body.String() != want || *reached {
			t.Fatalf("%s = %d %s (reached %t), want 403 %s", model, rec.Code, rec.Body, *reached, want)
		}
	}
}

// TestGateResolvesTheModelAsUpstreamRoutesIt: a thinking suffix is decided on
// its base model, like upstream routes it, and "auto" — which upstream turns
// into whichever model it finds first — is never admitted, even when a
// provider registers a model of that name.
func TestGateResolvesTheModelAsUpstreamRoutesIt(t *testing.T) {
	catalog := fixedCatalog(map[string][]string{"gpt-5.6": {"chatgpt"}, "auto": {"chatgpt"}})
	engine, reached := gated(staticResolver(gateSecret, gatePrincipal, "chatgpt:gpt-*"), catalog)

	if rec := chat(engine, gateSecret, "gpt-5.6(high)"); rec.Code != http.StatusOK || !*reached {
		t.Fatalf("gpt-5.6(high) = %d, want 200", rec.Code)
	}

	*reached = false
	for _, model := range []string{"auto", "auto(high)"} {
		if rec := chat(engine, gateSecret, model); rec.Code != http.StatusForbidden || *reached {
			t.Fatalf("%s = %d (reached %t), want 403", model, rec.Code, *reached)
		}
	}
}

// TestModelRequestReadsEachRepositoryOnce: through the real resolver, a model
// request — admitted or refused by policy — reads the token once and its
// owner once; the policy the gate applies is the one the resolver read.
func TestModelRequestReadsEachRepositoryOnce(t *testing.T) {
	owner := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Status: identity.StatusActive, Policy: mustPolicy("chatgpt:*")}
	tok := credentials.Token{ID: uuid.New(), UserID: owner.ID, Hash: credentials.HashSecret(gateSecret)}
	catalog := fixedCatalog(map[string][]string{"gpt-5.6": {"chatgpt"}, "claude-sonnet-5": {"claude"}})

	for _, tc := range []struct {
		model string
		want  int
	}{{"gpt-5.6", http.StatusOK}, {"claude-sonnet-5", http.StatusForbidden}} {
		users, tokens := mocks.NewUserRepo(t), mocks.NewTokenRepo(t)
		tokens.EXPECT().ByHash(mock.Anything, tok.Hash).Return(tok, nil).Once()
		users.EXPECT().ByID(mock.Anything, owner.ID).Return(owner, nil).Once()

		engine, _ := gated(app.NewTokenResolver(users, tokens), catalog)
		if rec := chat(engine, gateSecret, tc.model); rec.Code != tc.want {
			t.Fatalf("%s = %d %s, want %d", tc.model, rec.Code, rec.Body, tc.want)
		}
	}
}

// TestGateAppliesTheDomainRule: the gate decides a model served by two
// providers exactly as access.Policy.Covers does — the rule the admin
// screens preview policies with.
func TestGateAppliesTheDomainRule(t *testing.T) {
	providers := []string{"acme", "chatgpt"}

	catalog := fixedCatalog(map[string][]string{"shared-model": providers})
	for _, rules := range [][]string{{"acme:*"}, {"chatgpt:*"}, {"acme:*", "chatgpt:shared-*"}, nil} {
		engine, _ := gated(staticResolver(gateSecret, gatePrincipal, rules...), catalog)

		admitted := chat(engine, gateSecret, "shared-model").Code == http.StatusOK
		if covers := mustPolicy(rules...).Covers("shared-model", providers); admitted != covers {
			t.Errorf("policy %v: gate admitted %t, Covers says %t", rules, admitted, covers)
		}
	}
}

// TestGateRefusalsAreUpstreamsOwn: every token refusal, through the real
// resolver, is upstream's own 401 body, so a gate refusal cannot be told from
// a provider refusal — and a revoked token or a blocked owner cannot be told
// from a token that never existed.
func TestGateRefusalsAreUpstreamsOwn(t *testing.T) {
	const missing, invalid = `{"error":"Missing API key"}`, `{"error":"Invalid API key"}`

	revokedAt := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	blocked := identity.User{ID: uuid.New(), Kind: identity.KindHuman, Status: identity.StatusBlocked}
	token := func(owner uuid.UUID) credentials.Token {
		return credentials.Token{ID: uuid.New(), UserID: owner, Hash: credentials.HashSecret(gateSecret)}
	}

	for _, tc := range []struct {
		name   string
		key    string
		expect func(users *mocks.UserRepo, tokens *mocks.TokenRepo)
		want   string
	}{
		{"no token", "", func(*mocks.UserRepo, *mocks.TokenRepo) {}, missing},
		{"unknown token", gateSecret, func(_ *mocks.UserRepo, tokens *mocks.TokenRepo) {
			tokens.EXPECT().ByHash(mock.Anything, mock.Anything).Return(credentials.Token{}, app.ErrNotFound)
		}, invalid},
		{"revoked token", gateSecret, func(_ *mocks.UserRepo, tokens *mocks.TokenRepo) {
			tok := token(uuid.New())
			tok.RevokedAt = &revokedAt
			tokens.EXPECT().ByHash(mock.Anything, mock.Anything).Return(tok, nil)
		}, invalid},
		{"blocked owner", gateSecret, func(users *mocks.UserRepo, tokens *mocks.TokenRepo) {
			tokens.EXPECT().ByHash(mock.Anything, mock.Anything).Return(token(blocked.ID), nil)
			users.EXPECT().ByID(mock.Anything, blocked.ID).Return(blocked, nil)
		}, invalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			users, tokens := mocks.NewUserRepo(t), mocks.NewTokenRepo(t)
			tc.expect(users, tokens)
			engine, reached := gated(app.NewTokenResolver(users, tokens), fixedCatalog(map[string][]string{"gpt-5.6": {"chatgpt"}}))

			rec := chat(engine, tc.key, "gpt-5.6")
			if rec.Code != http.StatusUnauthorized || rec.Body.String() != tc.want || *reached {
				t.Fatalf("= %d %s (reached %t), want 401 %s", rec.Code, rec.Body, *reached, tc.want)
			}
		})
	}
}

// TestGateResolvesTheTokenOnce: the gate hands the principal on, and the
// access provider behind it admits the request as that principal without
// looking the token up again.
func TestGateResolvesTheTokenOnce(t *testing.T) {
	lookups := 0
	resolver := resolverFunc(func(ctx context.Context, secret string) (app.Principal, access.Policy, error) {
		lookups++

		return staticResolver(gateSecret, gatePrincipal, "chatgpt:*")(ctx, secret)
	})
	engine := gateEngine(resolver, fixedCatalog(map[string][]string{"gpt-5.6": {"chatgpt"}}))

	var admitted string

	engine.POST("/v1/chat/completions", func(c *gin.Context) {
		res, err := NewAccessProvider(resolver).Authenticate(c.Request.Context(), c.Request)
		if err != nil {
			t.Errorf("access provider refused a request the gate admitted: %v", err)

			return
		}

		admitted = res.Principal
	})

	chat(engine, gateSecret, "gpt-5.6")

	if admitted != gatePrincipal.String() || lookups != 1 {
		t.Fatalf("admitted as %q after %d lookups, want %q after 1", admitted, lookups, gatePrincipal)
	}
}
