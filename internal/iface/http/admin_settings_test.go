package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
	"github.com/google/uuid"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func runningConfig(t *testing.T, doc string) *sdkconfig.Config {
	t.Helper()

	cfg, err := sdkconfig.ParseConfigBytes([]byte(doc))
	require.NoError(t, err, "ParseConfigBytes")

	return cfg
}

// An administrator reads the stored document as stored, proxy credentials and all:
// a redacted copy sent back whole would overwrite them.
func TestSettingsAreTheStoredDocumentUnredacted(t *testing.T) {
	env := newEnv(t)

	const doc = "# upstream\nproxy-url: http://user:hunter2@proxy.example.com:8080\nrequest-retry: 3\n"
	env.settings.EXPECT().UpstreamDocument(mock.Anything).Return(doc, nil)

	var got api.Settings
	decodeBody(t, env.do(http.MethodGet, "/api/admin/settings", "", withCookie(env.signedIn(admin()))), http.StatusOK, &got)

	require.Equal(t, doc, got.Yaml, "yaml is not the stored document")

	fields := got.Fields
	require.NotNil(t, fields.ProxyURL, "proxyURL")
	require.Equal(t, "http://user:hunter2@proxy.example.com:8080", *fields.ProxyURL, "proxyURL")
	require.NotNil(t, fields.RequestRetry, "requestRetry")
	require.Equal(t, 3, *fields.RequestRetry, "requestRetry")
	require.NotNil(t, fields.MaxRetryInterval, "maxRetryInterval")
	require.Equal(t, 0, *fields.MaxRetryInterval, "maxRetryInterval")
}

// A dry run answers the diff and the proposed settings and touches nothing: no push,
// no write (the mocks have no expectation for either). It reads the stored document
// it would replace.
func TestADrySettingsRunAppliesNothing(t *testing.T) {
	env := newEnv(t)
	env.settings.EXPECT().UpstreamDocument(mock.Anything).Return("request-retry: 1\n", nil)
	env.gateway.EXPECT().CurrentConfig().Return(runningConfig(t, "request-retry: 1\n"))

	var got api.SettingsUpdateResult
	decodeBody(t, env.do(http.MethodPut, "/api/admin/settings", `{"yaml":"request-retry: 5\n","dryRun":true}`,
		withCookie(env.signedIn(admin()))), http.StatusOK, &got)

	require.False(t, got.Applied, "a dry run was applied")
	require.Contains(t, got.Diff, "+request-retry: 5", "diff")
	require.Contains(t, got.Diff, "-request-retry: 1", "diff")
	require.Equal(t, "request-retry: 5\n", got.Settings.Yaml, "proposed yaml")
	require.NotNil(t, got.Settings.Fields.RequestRetry, "proposed requestRetry")
	require.Equal(t, 5, *got.Settings.Fields.RequestRetry, "proposed requestRetry")
}

func TestApplyingATypedPatchPushesAndStoresIt(t *testing.T) {
	env := newEnv(t)
	self := admin()

	env.settings.EXPECT().UpstreamDocument(mock.Anything).Return("request-retry: 1\n", nil)
	env.gateway.EXPECT().CurrentConfig().Return(runningConfig(t, "request-retry: 1\n"))

	var pushed *sdkconfig.Config

	env.gateway.EXPECT().PushConfig(mock.Anything).RunAndReturn(func(c *sdkconfig.Config) error {
		pushed = c

		return nil
	})

	var stored string

	env.settings.EXPECT().SetUpstreamDocument(mock.Anything, mock.Anything, self.ID, mock.Anything).
		RunAndReturn(func(_ context.Context, doc string, _ uuid.UUID, _ time.Time) error {
			stored = doc

			return nil
		})

	var got api.SettingsUpdateResult
	decodeBody(t, env.do(http.MethodPut, "/api/admin/settings", `{"fields":{"requestRetry":4}}`, withCookie(env.signedIn(self))),
		http.StatusOK, &got)

	require.True(t, got.Applied, "the patch was not applied")
	require.NotNil(t, pushed, "nothing was pushed")
	require.Equal(t, 4, pushed.RequestRetry, "pushed retry")
	require.Equal(t, got.Settings.Yaml, stored, "stored document")
	require.NotNil(t, got.Settings.Fields.RequestRetry, "answered requestRetry")
	require.Equal(t, 4, *got.Settings.Fields.RequestRetry, "answered requestRetry")
}

func TestSettingsRefusalsNameTheField(t *testing.T) {
	cases := []struct {
		name, body, code, field string
	}{
		{"gateway-owned", `{"yaml":"port: 1234\n"}`, codeForbiddenSetting, "port"},
		{"yaml and fields", `{"yaml":"request-retry: 1\n","fields":{"requestRetry":2}}`, codeInvalidSettings, "fields"},
		{"negative field", `{"fields":{"maxRetryInterval":-1}}`, codeInvalidSettings, "maxRetryInterval"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			rec := e.do(http.MethodPut, "/api/admin/settings", c.body, withCookie(e.signedIn(admin())))
			wantField(t, apiError(t, rec, http.StatusUnprocessableEntity, c.code), c.field)
		})
	}
}

// Rates are float64 end to end: a price that float32 cannot hold exactly reaches the
// store as sent, and comes back as sent, as a manual row.
func TestPricesAreReplacedAtFullPrecision(t *testing.T) {
	env := newEnv(t, withoutPriceCatalog)

	var stored []app.ModelPrice

	env.prices.EXPECT().Replace(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, l []app.ModelPrice, _ time.Time) error {
		stored = l

		return nil
	})
	env.priceSet.EXPECT().SetPrices(mock.Anything).Return()
	env.prices.EXPECT().List(mock.Anything).RunAndReturn(func(context.Context) ([]app.ModelPrice, error) { return stored, nil })

	const body = `[{"provider":"claude","model":"m","input":0.15,"output":1.2,"cacheRead":0.015,"cacheWrite":0.1875}]`

	rec := env.do(http.MethodPut, "/api/admin/prices", body, withCookie(env.signedIn(admin())))

	var got api.PriceList
	decodeBody(t, rec, http.StatusOK, &got)

	want := app.ModelPrice{Provider: "claude", Model: "m", Input: 0.15, Output: 1.2, CacheRead: 0.015, CacheWrite: 0.1875}

	require.Len(t, stored, 1, "stored")

	require.Equal(t, want, stored[0], "stored")

	require.Len(t, got.Prices, 1, "answered")
	require.Equal(t, api.PriceEntry{
		Provider: "claude", Model: "m", Input: 0.15, Output: 1.2,
		CacheRead: 0.015, CacheWrite: 0.1875, Source: api.PriceEntrySourceManual,
	}, got.Prices[0], "answered the list not as sent")
}

// GET answers the contract's PriceList: a manual row over a catalog row carries
// the catalog's rates, a catalog row does not, and the catalog's status has null
// for what never happened.
func TestGetPrices(t *testing.T) {
	env := newEnv(t)
	checked := env.clock.Now().Add(-time.Hour)
	catalogSonnet := app.ModelPrice{Provider: "claude", Model: "claude-sonnet-5", Input: 3, Output: 15, UpdatedAt: checked}
	env.prices.EXPECT().List(mock.Anything).Return([]app.ModelPrice{{Provider: "claude", Model: "claude-sonnet-5", Input: 2, UpdatedAt: checked}}, nil)
	env.priceCat.EXPECT().List(mock.Anything).Return([]app.ModelPrice{
		catalogSonnet,
		{Provider: "chatgpt", Model: "gpt-6", Input: 1.25, UpdatedAt: checked},
	}, nil)
	env.priceCat.EXPECT().State(mock.Anything).Return(app.CatalogState{CheckedAt: checked, LastError: "the catalog answered 503"}, nil)
	env.priceMet.EXPECT().SetPriceCatalog(2, checked).Return()
	env.priceSet.EXPECT().SetPrices(mock.Anything).Return()

	require.NoError(t, env.deps.Prices.Load(context.Background()), "Load")

	rec := env.do(http.MethodGet, "/api/admin/prices", "", withCookie(env.signedIn(admin())))

	var got api.PriceList
	decodeBody(t, rec, http.StatusOK, &got)

	require.Len(t, got.Prices, 2, "prices")

	gpt, sonnet := got.Prices[0], got.Prices[1]
	require.Equal(t, "gpt-6", gpt.Model, "the catalog row comes first")
	require.Equal(t, api.PriceEntrySourceCatalog, gpt.Source, "gpt-6 source")
	require.Nil(t, gpt.CatalogRates, "gpt-6 catalog rates")
	require.True(t, gpt.UpdatedAt.Equal(checked), "gpt-6 updated at = %v, want %v", gpt.UpdatedAt, checked)

	require.Equal(t, api.PriceEntrySourceManual, sonnet.Source, "sonnet source")
	require.Equal(t, 2.0, sonnet.Input, "sonnet input")
	require.NotNil(t, sonnet.CatalogRates, "sonnet catalog rates")
	require.Equal(t, api.PriceRates{Input: 3, Output: 15}, *sonnet.CatalogRates, "sonnet catalog rates")

	catalog := got.Catalog
	require.True(t, catalog.Enabled, "catalog enabled")
	require.Equal(t, 2, catalog.Models, "catalog models")
	require.NotNil(t, catalog.CheckedAt, "catalog checked at")
	require.True(t, catalog.CheckedAt.Equal(checked), "catalog checked at = %v, want %v", catalog.CheckedAt, checked)
	require.Nil(t, catalog.ChangedAt, "catalog changed at")
	require.NotNil(t, catalog.LastError, "catalog last error")
	require.Equal(t, "the catalog answered 503", *catalog.LastError, "catalog last error")
}

// Without a catalog source a refresh is a conflict, not a failed check.
func TestRefreshWithoutACatalogIsRefused(t *testing.T) {
	e := newEnv(t, withoutPriceCatalog)
	apiError(t, e.do(http.MethodPost, "/api/admin/prices/refresh", "", withCookie(e.signedIn(admin()))),
		http.StatusConflict, codeCatalogDisabled)
}

// A failed check is still answered 200: the reason is in catalog.lastError.
func TestRefreshReportsAFailedCheckInTheStatus(t *testing.T) {
	env := newEnv(t)
	env.priceSrc.EXPECT().Fingerprint().Return("fp")
	env.priceSrc.EXPECT().Fetch(mock.Anything, mock.Anything).Return(app.CatalogFetch{}, errors.New("the catalog answered 502"))
	env.priceMet.EXPECT().ObservePriceCatalogFailure().Return().Once()
	env.priceCat.EXPECT().SetState(mock.Anything, mock.Anything).Return(nil)

	var got api.PriceList
	decodeBody(t, env.do(http.MethodPost, "/api/admin/prices/refresh", "", withCookie(env.signedIn(admin()))), http.StatusOK, &got)

	require.True(t, got.Catalog.Enabled, "catalog enabled")
	require.NotNil(t, got.Catalog.LastError, "catalog last error")
	require.Equal(t, "the catalog answered 502", *got.Catalog.LastError, "catalog last error")
}

// A refused list replaces nothing (the store mock has no expectation).
func TestReplacePricesRefusals(t *testing.T) {
	cases := []struct{ name, body, field string }{
		{"negative rate", `[{"provider":"a","model":"m"},{"provider":"a","model":"n","input":-1}]`, "[1].input"},
		{"listed twice", `[{"provider":"a","model":"m"},{"provider":"a","model":"m"}]`, "[1]"},
		{"null", `null`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)

			got := apiError(t, e.do(http.MethodPut, "/api/admin/prices", tc.body, withCookie(e.signedIn(admin()))),
				http.StatusUnprocessableEntity, codeInvalidInput)
			if tc.field != "" {
				wantField(t, got, tc.field)
			}
		})
	}
}

// A refresh outlasts the server's write timeout: it may wait for a scheduled
// check and then fetch, so the route extends its own deadline.
func TestRefreshOutlastsTheWriteTimeout(t *testing.T) {
	env := newEnv(t)

	const slow = 300 * time.Millisecond

	env.priceSrc.EXPECT().Fingerprint().Return("fp")
	env.priceSrc.EXPECT().Fetch(mock.Anything, mock.Anything).RunAndReturn(
		func(context.Context, app.CatalogValidators) (app.CatalogFetch, error) {
			time.Sleep(slow)

			return app.CatalogFetch{}, errors.New("the catalog answered 503")
		})
	env.priceMet.EXPECT().ObservePriceCatalogFailure().Return()
	env.priceCat.EXPECT().SetState(mock.Anything, mock.Anything).Return(nil)
	srv := httptest.NewUnstartedServer(env.handler)
	srv.Config.WriteTimeout = slow / 3
	srv.Start()
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/admin/prices/refresh", http.NoBody)
	require.NoError(t, err, "NewRequest")

	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(env.signedIn(admin()))

	resp, err := srv.Client().Do(req)
	require.NoError(t, err, "no answer after %s with a %s write timeout", slow, srv.Config.WriteTimeout)

	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "status")
}
