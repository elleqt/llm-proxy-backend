package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/stretchr/testify/mock"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
)

func runningConfig(t *testing.T, doc string) *sdkconfig.Config {
	t.Helper()
	cfg, err := sdkconfig.ParseConfigBytes([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// An administrator reads the stored document as stored, proxy credentials and all:
// a redacted copy sent back whole would overwrite them.
func TestSettingsAreTheStoredDocumentUnredacted(t *testing.T) {
	e := newEnv(t)
	const doc = "# upstream\nproxy-url: http://user:hunter2@proxy.example.com:8080\nrequest-retry: 3\n"
	e.settings.EXPECT().UpstreamDocument(mock.Anything).Return(doc, nil)
	var got api.Settings
	decodeBody(t, e.do(http.MethodGet, "/api/admin/settings", "", withCookie(e.signedIn(admin()))), http.StatusOK, &got)
	if got.Yaml != doc {
		t.Fatalf("yaml = %q, want the stored document %q", got.Yaml, doc)
	}
	f := got.Fields
	if f.ProxyURL == nil || *f.ProxyURL != "http://user:hunter2@proxy.example.com:8080" ||
		f.RequestRetry == nil || *f.RequestRetry != 3 || f.MaxRetryInterval == nil || *f.MaxRetryInterval != 0 {
		t.Fatalf("fields = %+v", f)
	}
}

// A dry run answers the diff and the proposed settings and touches nothing: no push,
// no write (the mocks have no expectation for either).
func TestADrySettingsRunAppliesNothing(t *testing.T) {
	e := newEnv(t)
	e.gateway.EXPECT().CurrentConfig().Return(runningConfig(t, "request-retry: 1\n"))
	var got api.SettingsUpdateResult
	decodeBody(t, e.do(http.MethodPut, "/api/admin/settings", `{"yaml":"request-retry: 5\n","dryRun":true}`,
		withCookie(e.signedIn(admin()))), http.StatusOK, &got)
	if got.Applied || !strings.Contains(got.Diff, "+request-retry: 5") || !strings.Contains(got.Diff, "-request-retry: 1") ||
		got.Settings.Yaml != "request-retry: 5\n" || *got.Settings.Fields.RequestRetry != 5 {
		t.Fatalf("result = %+v", got)
	}
}

func TestApplyingATypedPatchPushesAndStoresIt(t *testing.T) {
	e := newEnv(t)
	self := admin()
	e.settings.EXPECT().UpstreamDocument(mock.Anything).Return("request-retry: 1\n", nil)
	e.gateway.EXPECT().CurrentConfig().Return(runningConfig(t, "request-retry: 1\n"))
	var pushed *sdkconfig.Config
	e.gateway.EXPECT().PushConfig(mock.Anything).RunAndReturn(func(c *sdkconfig.Config) error {
		pushed = c
		return nil
	})
	var stored string
	e.settings.EXPECT().SetUpstreamDocument(mock.Anything, mock.Anything, self.ID, mock.Anything).
		RunAndReturn(func(_ context.Context, doc string, _ uuid.UUID, _ time.Time) error {
			stored = doc
			return nil
		})
	var got api.SettingsUpdateResult
	decodeBody(t, e.do(http.MethodPut, "/api/admin/settings", `{"fields":{"requestRetry":4}}`, withCookie(e.signedIn(self))),
		http.StatusOK, &got)
	if !got.Applied || pushed == nil || pushed.RequestRetry != 4 || stored != got.Settings.Yaml || *got.Settings.Fields.RequestRetry != 4 {
		t.Fatalf("result = %+v, pushed retry %v, stored %q", got, pushed, stored)
	}
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
	e := newEnv(t, withoutPriceCatalog)
	var stored []app.ModelPrice
	e.prices.EXPECT().Replace(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, l []app.ModelPrice, _ time.Time) error {
		stored = l
		return nil
	})
	e.priceSet.EXPECT().SetPrices(mock.Anything).Return()
	e.prices.EXPECT().List(mock.Anything).RunAndReturn(func(context.Context) ([]app.ModelPrice, error) { return stored, nil })
	const body = `[{"provider":"claude","model":"m","input":0.15,"output":1.2,"cacheRead":0.015,"cacheWrite":0.1875}]`
	rec := e.do(http.MethodPut, "/api/admin/prices", body, withCookie(e.signedIn(admin())))
	var got api.PriceList
	decodeBody(t, rec, http.StatusOK, &got)
	want := app.ModelPrice{Provider: "claude", Model: "m", Input: 0.15, Output: 1.2, CacheRead: 0.015, CacheWrite: 0.1875}
	if len(stored) != 1 || stored[0] != want {
		t.Fatalf("stored %+v, want %+v", stored, want)
	}
	if len(got.Prices) != 1 || got.Prices[0] != (api.PriceEntry{Provider: "claude", Model: "m", Input: 0.15, Output: 1.2,
		CacheRead: 0.015, CacheWrite: 0.1875, Source: api.PriceEntrySourceManual}) {
		t.Fatalf("answered %+v, want the list as sent", got.Prices)
	}
}

// GET answers the contract's PriceList: a manual row over a catalog row carries
// the catalog's rates, a catalog row does not, and the catalog's status has null
// for what never happened.
func TestGetPrices(t *testing.T) {
	e := newEnv(t)
	checked := e.clock.Now().Add(-time.Hour)
	catalogSonnet := app.ModelPrice{Provider: "claude", Model: "claude-sonnet-5", Input: 3, Output: 15, UpdatedAt: checked}
	e.prices.EXPECT().List(mock.Anything).Return([]app.ModelPrice{{Provider: "claude", Model: "claude-sonnet-5", Input: 2, UpdatedAt: checked}}, nil)
	e.priceCat.EXPECT().List(mock.Anything).Return([]app.ModelPrice{catalogSonnet,
		{Provider: "chatgpt", Model: "gpt-6", Input: 1.25, UpdatedAt: checked}}, nil)
	e.priceCat.EXPECT().State(mock.Anything).Return(app.CatalogState{CheckedAt: checked, LastError: "the catalog answered 503"}, nil)
	e.priceMet.EXPECT().SetPriceCatalog(2, checked).Return()
	e.priceSet.EXPECT().SetPrices(mock.Anything).Return()
	if err := e.deps.Prices.Load(context.Background()); err != nil {
		t.Fatalf("Load: %v", err)
	}

	rec := e.do(http.MethodGet, "/api/admin/prices", "", withCookie(e.signedIn(admin())))
	var got api.PriceList
	decodeBody(t, rec, http.StatusOK, &got)
	if len(got.Prices) != 2 {
		t.Fatalf("prices = %+v", got.Prices)
	}
	gpt, sonnet := got.Prices[0], got.Prices[1]
	if gpt.Model != "gpt-6" || gpt.Source != api.PriceEntrySourceCatalog || gpt.CatalogRates != nil || !gpt.UpdatedAt.Equal(checked) {
		t.Fatalf("gpt-6 = %+v, want the catalog row first", gpt)
	}
	if sonnet.Source != api.PriceEntrySourceManual || sonnet.Input != 2 ||
		sonnet.CatalogRates == nil || *sonnet.CatalogRates != (api.PriceRates{Input: 3, Output: 15}) {
		t.Fatalf("sonnet = %+v, want the override with the catalog's rates", sonnet)
	}
	c := got.Catalog
	if !c.Enabled || c.Models != 2 || c.CheckedAt == nil || !c.CheckedAt.Equal(checked) || c.ChangedAt != nil ||
		c.LastError == nil || *c.LastError != "the catalog answered 503" {
		t.Fatalf("catalog = %+v", c)
	}
}

// Without a catalog source a refresh is a conflict, not a failed check.
func TestRefreshWithoutACatalogIsRefused(t *testing.T) {
	e := newEnv(t, withoutPriceCatalog)
	apiError(t, e.do(http.MethodPost, "/api/admin/prices/refresh", "", withCookie(e.signedIn(admin()))),
		http.StatusConflict, codeCatalogDisabled)
}

// A failed check is still answered 200: the reason is in catalog.lastError.
func TestRefreshReportsAFailedCheckInTheStatus(t *testing.T) {
	e := newEnv(t)
	e.priceSrc.EXPECT().Fingerprint().Return("fp")
	e.priceSrc.EXPECT().Fetch(mock.Anything, mock.Anything).Return(app.CatalogFetch{}, errors.New("the catalog answered 502"))
	e.priceMet.EXPECT().ObservePriceCatalogFailure().Return().Once()
	e.priceCat.EXPECT().SetState(mock.Anything, mock.Anything).Return(nil)
	var got api.PriceList
	decodeBody(t, e.do(http.MethodPost, "/api/admin/prices/refresh", "", withCookie(e.signedIn(admin()))), http.StatusOK, &got)
	if !got.Catalog.Enabled || got.Catalog.LastError == nil || *got.Catalog.LastError != "the catalog answered 502" {
		t.Fatalf("catalog = %+v, want the failure", got.Catalog)
	}
}

// A refused list replaces nothing (the store mock has no expectation).
func TestReplacePricesRefusals(t *testing.T) {
	cases := []struct{ name, body, field string }{
		{"negative rate", `[{"provider":"a","model":"m"},{"provider":"a","model":"n","input":-1}]`, "[1].input"},
		{"listed twice", `[{"provider":"a","model":"m"},{"provider":"a","model":"m"}]`, "[1]"},
		{"null", `null`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			got := apiError(t, e.do(http.MethodPut, "/api/admin/prices", c.body, withCookie(e.signedIn(admin()))),
				http.StatusUnprocessableEntity, codeInvalidInput)
			if c.field != "" {
				wantField(t, got, c.field)
			}
		})
	}
}

// A refresh outlasts the server's write timeout: it may wait for a scheduled
// check and then fetch, so the route extends its own deadline.
func TestRefreshOutlastsTheWriteTimeout(t *testing.T) {
	e := newEnv(t)
	const slow = 300 * time.Millisecond
	e.priceSrc.EXPECT().Fingerprint().Return("fp")
	e.priceSrc.EXPECT().Fetch(mock.Anything, mock.Anything).RunAndReturn(
		func(context.Context, app.CatalogValidators) (app.CatalogFetch, error) {
			time.Sleep(slow)
			return app.CatalogFetch{}, errors.New("the catalog answered 503")
		})
	e.priceMet.EXPECT().ObservePriceCatalogFailure().Return()
	e.priceCat.EXPECT().SetState(mock.Anything, mock.Anything).Return(nil)
	srv := httptest.NewUnstartedServer(e.handler)
	srv.Config.WriteTimeout = slow / 3
	srv.Start()
	t.Cleanup(srv.Close)

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/api/admin/prices/refresh", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(e.signedIn(admin()))
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("no answer after %s with a %s write timeout: %v", slow, srv.Config.WriteTimeout, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}
