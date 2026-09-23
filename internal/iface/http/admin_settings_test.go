package http

import (
	"context"
	"net/http"
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
// store as sent, and comes back as sent.
func TestPricesAreReplacedAtFullPrecision(t *testing.T) {
	e := newEnv(t)
	var stored []app.ModelPrice
	e.prices.EXPECT().Replace(mock.Anything, mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, l []app.ModelPrice, _ time.Time) error {
		stored = l
		return nil
	})
	e.priceSet.EXPECT().SetPrices(mock.Anything).Return()
	e.prices.EXPECT().List(mock.Anything).RunAndReturn(func(context.Context) ([]app.ModelPrice, error) { return stored, nil })
	const body = `[{"provider":"claude","model":"m","input":0.15,"output":1.2,"cacheRead":0.015,"cacheWrite":0.1875}]`
	rec := e.do(http.MethodPut, "/api/admin/prices", body, withCookie(e.signedIn(admin())))
	var got []api.ModelPrice
	decodeBody(t, rec, http.StatusOK, &got)
	want := app.ModelPrice{Provider: "claude", Model: "m", Input: 0.15, Output: 1.2, CacheRead: 0.015, CacheWrite: 0.1875}
	if len(stored) != 1 || stored[0] != want {
		t.Fatalf("stored %+v, want %+v", stored, want)
	}
	if len(got) != 1 || got[0] != (api.ModelPrice{Provider: "claude", Model: "m", Input: 0.15, Output: 1.2, CacheRead: 0.015, CacheWrite: 0.1875}) {
		t.Fatalf("answered %+v, want the list as sent", got)
	}
}

func TestGetPrices(t *testing.T) {
	e := newEnv(t)
	cookie := withCookie(e.signedIn(admin()))
	e.prices.EXPECT().List(mock.Anything).Return(nil, nil).Once()
	if rec := e.do(http.MethodGet, "/api/admin/prices", "", cookie); strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("empty list = %s, want []", rec.Body)
	}
	e.prices.EXPECT().List(mock.Anything).Return([]app.ModelPrice{{Provider: "claude", Model: "m", Input: 3, Output: 15}}, nil).Once()
	var got []api.ModelPrice
	decodeBody(t, e.do(http.MethodGet, "/api/admin/prices", "", cookie), http.StatusOK, &got)
	if len(got) != 1 || got[0].Provider != "claude" || got[0].Input != 3 || got[0].Output != 15 {
		t.Fatalf("prices = %+v", got)
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
