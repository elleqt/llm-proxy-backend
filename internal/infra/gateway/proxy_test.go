package gateway

import (
	"context"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"github.com/stretchr/testify/require"
)

// proxyPassword is the password the account proxies here carry; nothing the
// admin API is built from may show it.
const proxyPassword = "proxy-pass-3e1f"

// forwardingProxy is an HTTP forward proxy on loopback: it counts the
// requests it carries and passes each on to its target.
func forwardingProxy(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()

	var carried atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, r *http.Request) {
		carried.Add(1)

		out := r.Clone(r.Context())
		out.RequestURI = ""
		out.Header.Del("Proxy-Authorization")

		resp, err := http.DefaultTransport.RoundTrip(out)
		if err != nil {
			writer.WriteHeader(http.StatusBadGateway)

			return
		}
		defer func() { _ = resp.Body.Close() }()

		maps.Copy(writer.Header(), resp.Header)

		writer.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(writer, resp.Body)
	}))
	t.Cleanup(srv.Close)

	return srv, &carried
}

// withPassword is proxy's URL with userinfo carrying proxyPassword.
func withPassword(proxy *httptest.Server) string {
	u, _ := url.Parse(proxy.URL)
	u.User = url.UserPassword("ops", proxyPassword)

	return u.String()
}

// accountByID is account id as Accounts lists it.
func accountByID(t *testing.T, g *Gateway, id string) app.VendorAccount {
	t.Helper()

	for _, a := range g.Accounts() {
		if a.ID == id {
			return a
		}
	}

	require.Failf(t, "account not listed", "%s", id)

	return app.VendorAccount{}
}

// TestCompatProviderProxyModes: an OpenAI-compatible provider's requests go
// through the global proxy-url by default, through its own proxy once set,
// straight to the vendor when direct, keep the proxy across a definition
// update that does not name one, and find it again after a restart. The
// account shows the proxy without its password.
func TestCompatProviderProxyModes(t *testing.T) {
	pool := pgtest.NewTestPool(t)
	vendor := compatVendor()
	vendorSrv := faketest.Start(t, vendor)
	global, viaGlobal := forwardingProxy(t)
	own, viaOwn := forwardingProxy(t)
	name, model := compatName(t, "px"), compatModel(t, "m")

	boot := func() *running {
		cfg := &cliproxyconfig.Config{AuthDir: t.TempDir()}
		cfg.ProxyURL = global.URL

		return startCompatWith(t, pool, cfg)
	}

	srv := boot()
	account, err := srv.gateway.AddCompatProvider(t.Context(), app.CompatProvider{
		Name: name, BaseURL: vendorSrv.URL, APIKey: compatKey, Models: []app.CompatModel{{Name: model}},
	})
	require.NoError(t, err)
	require.Equal(t, app.AccountProxy{Mode: app.ProxyInherit}, account.Proxy)
	awaitProviders(t, srv.gateway.catalog, model, []string{name})

	require.Equal(t, http.StatusOK, chatVia(t, srv, model))
	require.Equal(t, int64(1), viaGlobal.Load(), "inherit: the global proxy-url carries it")
	require.Zero(t, viaOwn.Load())

	require.NoError(t, srv.gateway.SetAccountProxy(t.Context(), account.ID, app.ProxyChoice{Mode: app.ProxyCustom, URL: withPassword(own)}))
	require.Equal(t, http.StatusOK, chatVia(t, srv, model))
	require.Equal(t, int64(1), viaOwn.Load(), "custom: the account's proxy carries it")
	require.Equal(t, int64(1), viaGlobal.Load(), "custom: the global proxy-url is passed by")

	shown := accountByID(t, srv.gateway, account.ID).Proxy
	require.Equal(t, app.AccountProxy{Mode: app.ProxyCustom, URL: own.URL, HasCredentials: true}, shown)
	require.NotContains(t, fmt.Sprintf("%+v", srv.gateway.Accounts()), proxyPassword, "the account list shows the proxy password")

	_, err = srv.gateway.UpdateCompatProvider(t.Context(), account.ID, app.CompatProviderUpdate{
		BaseURL: vendorSrv.URL, Models: []app.CompatModel{{Name: model}},
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, chatVia(t, srv, model))
	require.Equal(t, int64(2), viaOwn.Load(), "an update without a proxy dropped the stored one")

	require.NoError(t, srv.gateway.SetAccountProxy(t.Context(), account.ID, app.ProxyChoice{Mode: app.ProxyDirect}))
	require.Equal(t, http.StatusOK, chatVia(t, srv, model))
	require.Equal(t, int64(2), viaOwn.Load(), "direct: a proxy carried it")
	require.Equal(t, int64(1), viaGlobal.Load(), "direct: a proxy carried it")
	require.Len(t, vendor.Requests(), 4, "every request reached the vendor")

	require.NoError(t, srv.gateway.SetAccountProxy(t.Context(), account.ID, app.ProxyChoice{Mode: app.ProxyCustom, URL: withPassword(own)}))
	require.ErrorIs(t, srv.stop(), context.Canceled)

	again := boot()
	awaitProviders(t, again.gateway.catalog, model, []string{name})
	require.Equal(t, app.AccountProxy{Mode: app.ProxyCustom, URL: own.URL, HasCredentials: true}, accountByID(t, again.gateway, account.ID).Proxy)
	require.Equal(t, http.StatusOK, chatVia(t, again, model))
	require.Equal(t, int64(3), viaOwn.Load(), "after a restart: the stored proxy carries it")
}

// TestOAuthAccountProxy: a vendor sign-in's requests follow its own proxy
// too, through upstream's Claude executor.
func TestOAuthAccountProxy(t *testing.T) {
	vendor := &faketest.Vendor{Payload: []byte(`{"id":"msg_1","type":"message","role":"assistant","model":"m",` +
		`"content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":2}}`)}
	vendorSrv := faketest.Start(t, vendor)
	global, viaGlobal := forwardingProxy(t)
	own, viaOwn := forwardingProxy(t)

	params := productionParams(t)
	params.Config.ProxyURL = global.URL
	gw := startBooted(t, params)

	// A runtime-only account keeps its base_url (see TestClaudeRequestCarriesTheCLIBaseline).
	grant := claudeGrant(t)
	grant.Metadata["access_token"] = "sk-ant-oat01-fake"
	grant.Metadata["account_uuid"] = "5f0c6a2e-1b7d-4e3a-9c84-0d2b3a4c5e6f"
	grant.Attributes = map[string]string{"base_url": vendorSrv.URL, coreauth.AttributeRuntimeOnly: "true"}
	_, err := gw.gateway.AddAccount(context.Background(), grant)
	require.NoError(t, err)

	for _, a := range params.CoreAuth.List() {
		if a.ID != grant.ID {
			require.NoError(t, gw.gateway.SetAccountDisabled(context.Background(), a.ID, true))
		}
	}

	require.NoError(t, gw.gateway.SetAccountProxy(t.Context(), grant.ID, app.ProxyChoice{Mode: app.ProxyCustom, URL: own.URL}))

	models := cliproxy.GlobalModelRegistry().GetModelsForClient(grant.ID)
	require.NotEmpty(t, models)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gw.baseURL+"/v1/messages", strings.NewReader(
		`{"model":"`+models[0].ID+`","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+wireSecret)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, int64(1), viaOwn.Load(), "the account's proxy carried it")
	require.Zero(t, viaGlobal.Load(), "the global proxy-url carried it")
}

// TestSetAccountProxyRefusals: an unknown account and a choice upstream would
// not read change nothing.
func TestSetAccountProxyRefusals(t *testing.T) {
	srv := startCompat(t, pgtest.NewTestPool(t))

	err := srv.gateway.SetAccountProxy(t.Context(), "no-such.json", app.ProxyChoice{Mode: app.ProxyDirect})
	require.ErrorIs(t, err, app.ErrNotFound)

	for _, bad := range []app.ProxyChoice{{Mode: "sideways"}, {Mode: app.ProxyCustom, URL: "ftp://proxy.example.com"}} {
		var invalid *app.InvalidInputError
		require.ErrorAs(t, srv.gateway.SetAccountProxy(t.Context(), "no-such.json", bad), &invalid, "%+v", bad)
	}
}

// TestAccountProxyView: the admin view of each stored form.
func TestAccountProxyView(t *testing.T) {
	for raw, want := range map[string]app.AccountProxy{
		"":       {Mode: app.ProxyInherit},
		"direct": {Mode: app.ProxyDirect},
		"none":   {Mode: app.ProxyDirect},
		"socks5://u:p@proxy.example.com:1080/path?token=x": {Mode: app.ProxyCustom, URL: "socks5://proxy.example.com:1080", HasCredentials: true},
		"http://proxy.example.com":                         {Mode: app.ProxyCustom, URL: "http://proxy.example.com"},
		"ftp://proxy.example.com":                          {Mode: app.ProxyCustom},
	} {
		require.Equal(t, want, accountProxy(raw), "%q", raw)
	}
}

// TestDiscoverModelsGoesThroughTheChosenProxy: discovery takes the request's
// proxy, else the provider's own, else the global proxy-url; inherit in the
// request means the global one.
func TestDiscoverModelsGoesThroughTheChosenProxy(t *testing.T) {
	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"m"}]}`))
	}))
	t.Cleanup(vendor.Close)

	global, viaGlobal := forwardingProxy(t)
	own, viaOwn := forwardingProxy(t)

	cfg := &cliproxyconfig.Config{AuthDir: t.TempDir()}
	cfg.ProxyURL = global.URL
	srv := startCompatWith(t, pgtest.NewTestPool(t), cfg)

	account, err := srv.gateway.AddCompatProvider(t.Context(), app.CompatProvider{
		Name: compatName(t, "dp"), BaseURL: vendor.URL, Models: []app.CompatModel{{Name: compatModel(t, "m")}},
		Proxy: &app.ProxyChoice{Mode: app.ProxyCustom, URL: own.URL},
	})
	require.NoError(t, err)

	_, err = srv.gateway.DiscoverModels(t.Context(), vendor.URL, "", account.ID, nil)
	require.NoError(t, err)
	require.Equal(t, int64(1), viaOwn.Load(), "the provider's own proxy")

	// No stored key: another base URL is not refused, and still goes through the provider's proxy.
	_, err = srv.gateway.DiscoverModels(t.Context(), vendor.URL+"/v1", "", account.ID, nil)
	require.NoError(t, err)
	require.Equal(t, int64(2), viaOwn.Load())

	_, err = srv.gateway.DiscoverModels(t.Context(), vendor.URL, "", account.ID, &app.ProxyChoice{Mode: app.ProxyInherit})
	require.NoError(t, err)
	require.Equal(t, int64(1), viaGlobal.Load(), "inherit in the request: the global proxy-url")

	_, err = srv.gateway.DiscoverModels(t.Context(), vendor.URL, "", "", &app.ProxyChoice{Mode: app.ProxyDirect})
	require.NoError(t, err)
	require.Equal(t, int64(1), viaGlobal.Load(), "direct: a proxy carried it")
	require.Equal(t, int64(2), viaOwn.Load(), "direct: a proxy carried it")

	_, err = srv.gateway.DiscoverModels(t.Context(), vendor.URL, "", "", nil)
	require.NoError(t, err)
	require.Equal(t, int64(2), viaGlobal.Load(), "no account, no choice: the global proxy-url")

	// A link-local target stays refused whatever the proxy.
	for _, p := range []*app.ProxyChoice{{Mode: app.ProxyDirect}, {Mode: app.ProxyCustom, URL: own.URL}} {
		_, err = srv.gateway.DiscoverModels(t.Context(), "http://169.254.169.254/latest", "", "", p)

		var invalid *app.InvalidInputError
		require.ErrorAs(t, err, &invalid)
		require.Equal(t, "baseURL", invalid.Field)
	}

	require.Equal(t, int64(2), viaOwn.Load(), "a link-local target reached a proxy")
}
