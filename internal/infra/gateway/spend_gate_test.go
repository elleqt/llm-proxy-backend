package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/limits"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/gate"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// spendEngine is a gated engine enforcing spend limits through a strict
// SpendGate mock, for an owner whose own set is custom and whose policy admits
// everything; reached reports whether a chat request got past the gate.
func spendEngine(t *testing.T, custom *limits.Set, catalog catalogFunc, prices *app.PriceTable) (*gin.Engine, *bool, *mocks.SpendGate) {
	t.Helper()

	limited := mocks.NewSpendGate(t)
	resolver := resolverFunc(func(_ context.Context, secret string) (app.Principal, app.Grant, error) {
		if secret != gateSecret {
			return app.Principal{}, app.Grant{}, app.ErrInvalidCredentials
		}

		return gatePrincipal, app.Grant{Policy: mustPolicy("*:*"), SpendLimits: custom}, nil
	})
	engine := gateEngineWith(resolver, catalog, &spendCheck{limits: limited, prices: prices, catalog: catalog}, nil)
	reached := new(bool)

	engine.POST("/v1/chat/completions", func(c *gin.Context) { *reached = true; c.Status(http.StatusOK) })

	return engine, reached, limited
}

// pricedOn is a price table holding a price for model on each of providers.
func pricedOn(model string, providers ...string) *app.PriceTable {
	prices := make([]app.ModelPrice, 0, len(providers))
	for _, provider := range providers {
		prices = append(prices, app.ModelPrice{Provider: provider, Model: model, Input: 1, Output: 1})
	}

	table := &app.PriceTable{}
	table.SetPrices(prices)

	return table
}

// tenPerTwoHours is a spend-limit set of one rule: $10 per 2h.
var tenPerTwoHours = limits.Set{{Window: 2 * time.Hour, AmountUSD: 10}}

// blockedUntilNoon is the decision of an exhausted tenPerTwoHours window that
// resets 90.001s from now.
var blockedUntilNoon = limits.Decision{
	Blocked:  true,
	Rule:     tenPerTwoHours[0],
	ResetsAt: time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC),
	Wait:     90*time.Second + time.Millisecond,
}

// TestSpendLimitRefusesWithRetryAfter: an exhausted window is a 429 naming the
// rule and when it resets, with a Retry-After rounded up to whole seconds and
// X-Should-Retry: false so SDKs do not retry a refusal that lasts hours.
func TestSpendLimitRefusesWithRetryAfter(t *testing.T) {
	engine, reached, limited := spendEngine(t, nil, fixedCatalog(map[string][]string{"m": {"vendora"}}), pricedOn("m", "vendora"))
	limited.EXPECT().Effective((*limits.Set)(nil)).Return(tenPerTwoHours)
	limited.EXPECT().Admit(mock.Anything, gatePrincipal.UserID, tenPerTwoHours).Return(blockedUntilNoon, nil)

	rec := chat(engine, gateSecret, "m")

	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.JSONEq(t,
		`{"error":{"message":"spend limit $10.00 per 2h reached; resets at 2026-09-28T12:00:00Z","type":"rate_limit_error"}}`,
		rec.Body.String())
	assert.Equal(t, "91", rec.Header().Get("Retry-After"))
	assert.Equal(t, "false", rec.Header().Get("X-Should-Retry"))
	assert.False(t, *reached, "a refused request reached the handler")
}

// TestUnpricedModelRefusedOnlyWithLimits: a model without a price cannot be
// charged against a window, so an owner with limits in force is refused it
// before any window is opened; an owner without limits is not.
func TestUnpricedModelRefusedOnlyWithLimits(t *testing.T) {
	catalog := fixedCatalog(map[string][]string{"m": {"vendora"}})

	engine, reached, limited := spendEngine(t, nil, catalog, &app.PriceTable{})
	limited.EXPECT().Effective((*limits.Set)(nil)).Return(tenPerTwoHours)

	rec := chat(engine, gateSecret, "m")
	require.Equal(t, http.StatusForbidden, rec.Code, "limited")
	assert.JSONEq(t, `{"error":{"message":"model m has no price","type":"permission_error"}}`, rec.Body.String(), "limited")
	assert.False(t, *reached, "limited: an unpriced model reached the handler")

	engine, reached, limited = spendEngine(t, nil, catalog, &app.PriceTable{})
	limited.EXPECT().Effective((*limits.Set)(nil)).Return(limits.Set{})

	rec = chat(engine, gateSecret, "m")
	require.Equal(t, http.StatusOK, rec.Code, "unlimited")
	assert.True(t, *reached, "unlimited: an unpriced model did not reach the handler")
}

// TestTheOwnersOwnSetDecides: the gate asks for the set in force by the
// owner's own set, not the defaults' — an owner whose own set is empty is
// unlimited even where the defaults are not, and an owner's own rules are the
// ones admitted against.
func TestTheOwnersOwnSetDecides(t *testing.T) {
	catalog := fixedCatalog(map[string][]string{"m": {"vendora"}})

	unlimited := &limits.Set{}
	engine, reached, limited := spendEngine(t, unlimited, catalog, &app.PriceTable{})
	limited.EXPECT().Effective(unlimited).Return(limits.Set{})

	rec := chat(engine, gateSecret, "m")
	require.Equal(t, http.StatusOK, rec.Code, "own empty set")
	assert.True(t, *reached, "own empty set: an unpriced model did not reach the handler")

	own := &limits.Set{{Window: time.Hour, AmountUSD: 5}}
	engine, reached, limited = spendEngine(t, own, catalog, pricedOn("m", "vendora"))
	limited.EXPECT().Effective(own).Return(*own)
	limited.EXPECT().Admit(mock.Anything, gatePrincipal.UserID, *own).Return(limits.Decision{}, nil)

	rec = chat(engine, gateSecret, "m")
	require.Equal(t, http.StatusOK, rec.Code, "own set")
	assert.True(t, *reached, "own set: an admitted request did not reach the handler")
}

// TestModelPricedOnOneOfTwoProvidersIsRefused: upstream may route to either
// provider, and the one without a price could not be charged.
func TestModelPricedOnOneOfTwoProvidersIsRefused(t *testing.T) {
	engine, reached, limited := spendEngine(t, nil, fixedCatalog(map[string][]string{"m": {"a", "b"}}), pricedOn("m", "a"))
	limited.EXPECT().Effective((*limits.Set)(nil)).Return(tenPerTwoHours)

	rec := chat(engine, gateSecret, "m")

	require.Equal(t, http.StatusForbidden, rec.Code)
	assert.False(t, *reached, "a model unpriced on one provider reached the handler")
}

// TestAdmittedRequestReachesTheHandler: a priced model whose windows all have
// room passes the gate untouched.
func TestAdmittedRequestReachesTheHandler(t *testing.T) {
	engine, reached, limited := spendEngine(t, nil, fixedCatalog(map[string][]string{"m": {"vendora"}}), pricedOn("m", "vendora"))
	limited.EXPECT().Effective((*limits.Set)(nil)).Return(tenPerTwoHours)
	limited.EXPECT().Admit(mock.Anything, gatePrincipal.UserID, tenPerTwoHours).Return(limits.Decision{}, nil)

	rec := chat(engine, gateSecret, "m")

	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, *reached, "an admitted request did not reach the handler")
}

// TestSpendLimitStorageFailureRefuses: limits that cannot be checked are not
// waived; the failure is the gateway's, so a 500 without its cause.
func TestSpendLimitStorageFailureRefuses(t *testing.T) {
	engine, reached, limited := spendEngine(t, nil, fixedCatalog(map[string][]string{"m": {"vendora"}}), pricedOn("m", "vendora"))
	limited.EXPECT().Effective((*limits.Set)(nil)).Return(tenPerTwoHours)
	limited.EXPECT().Admit(mock.Anything, gatePrincipal.UserID, tenPerTwoHours).
		Return(limits.Decision{}, errors.New("postgres: open windows: connection refused"))

	rec := chat(engine, gateSecret, "m")

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.JSONEq(t, `{"error":{"message":"spend limits unavailable","type":"server_error"}}`, rec.Body.String())
	assert.False(t, *reached, "a request whose limits could not be checked reached the handler")
}

// TestListingHidesUnpricedModelsOnlyWhenLimited: a limited owner is not listed
// a model the gate would refuse them; an owner without limits is listed both.
func TestListingHidesUnpricedModelsOnlyWhenLimited(t *testing.T) {
	catalog := fixedCatalog(map[string][]string{"priced": {"vendora"}, "unpriced": {"vendora"}})

	for _, tc := range []struct {
		what      string
		effective limits.Set
		want      []string
	}{
		{"limited", tenPerTwoHours, []string{"priced"}},
		{"unlimited", limits.Set{}, []string{"priced", "unpriced"}},
	} {
		engine, _, limited := spendEngine(t, nil, catalog, pricedOn("priced", "vendora"))
		limited.EXPECT().Effective((*limits.Set)(nil)).Return(tc.effective)
		engine.GET("/v1/models", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"object": "list", "data": []gin.H{{"id": "priced"}, {"id": "unpriced"}}})
		})

		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/models", http.NoBody)
		req.Header.Set("Authorization", "Bearer "+gateSecret)

		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, tc.what)
		assert.Equal(t, tc.want, arrayNames("data", "id", same)(t, rec.Body.String()), tc.what)
	}
}

// TestSpendRefusalsAreObserved: both spend refusals are reported under the
// owner's label and the model, each by its own reason.
func TestSpendRefusalsAreObserved(t *testing.T) {
	owner := app.Principal{UserID: gatePrincipal.UserID, TokenID: gatePrincipal.TokenID, Owner: "alice@example.com"}
	resolver := resolverFunc(func(_ context.Context, secret string) (app.Principal, app.Grant, error) {
		if secret != gateSecret {
			return app.Principal{}, app.Grant{}, app.ErrInvalidCredentials
		}

		return owner, app.Grant{Policy: mustPolicy("*:*")}, nil
	})
	catalog := fixedCatalog(map[string][]string{"m": {"vendora"}})

	for _, tc := range []struct {
		what   string
		prices *app.PriceTable
		admit  bool
		status int
		reason gate.DenyReason
	}{
		{"unpriced", &app.PriceTable{}, false, http.StatusForbidden, gate.DenyUnpricedModel},
		{"exhausted", pricedOn("m", "vendora"), true, http.StatusTooManyRequests, gate.DenySpendLimit},
	} {
		limited := mocks.NewSpendGate(t)
		limited.EXPECT().Effective((*limits.Set)(nil)).Return(tenPerTwoHours)

		if tc.admit {
			limited.EXPECT().Admit(mock.Anything, owner.UserID, tenPerTwoHours).Return(blockedUntilNoon, nil)
		}

		observer := &recordingObserver{}
		engine := gateEngineWith(resolver, catalog, &spendCheck{limits: limited, prices: tc.prices, catalog: catalog}, observer)
		engine.POST("/v1/chat/completions", func(c *gin.Context) { c.Status(http.StatusOK) })

		rec := chat(engine, gateSecret, "m")

		require.Equal(t, tc.status, rec.Code, tc.what)
		assert.Equal(t, []observed{{owner: "alice@example.com", model: "m", reason: tc.reason, denied: true}}, observer.seen(), tc.what)
	}
}
