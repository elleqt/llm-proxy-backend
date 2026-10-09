package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/vendorcreds"
	"github.com/jackc/pgx/v5/pgxpool"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// compatKey is the vendor key the OpenAI-compatible providers here are added
// with; nothing the admin API shows may contain it.
const compatKey = "compat-vendor-key-9f2c"

// compatVendor answers chat completions as a vendor does. Upstream answers a
// successful reply it cannot translate, such as an empty body, with 502.
func compatVendor() *faketest.Vendor {
	return &faketest.Vendor{Payload: []byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"m",` +
		`"choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}],` +
		`"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)}
}

// startCompat boots a gateway the way production does over the vendor
// credentials in pool: a Postgres credential store, listed once, and the
// listing handed to New.
func startCompat(t *testing.T, pool *pgxpool.Pool) *running {
	t.Helper()

	return startCompatWith(t, pool, &cliproxyconfig.Config{AuthDir: t.TempDir()})
}

// startCompatWith is startCompat on cfg, for a test that needs a global
// proxy-url or another boot setting.
func startCompatWith(t *testing.T, pool *pgxpool.Pool, cfg *cliproxyconfig.Config) *running {
	t.Helper()

	clock := mocks.NewClock(t)
	clock.EXPECT().Now().Return(storeNow).Maybe()

	store, err := NewCredentialStore(vendorcreds.New(pool), testSealer(t, 'c'), clock, t.TempDir())
	require.NoError(t, err)

	stored, err := store.List(t.Context())
	require.NoError(t, err, "list the credential store")

	manager, cooldown := NewCoreAuthManager(cfg, store)

	return startWith(t, Params{Config: cfg, CoreAuth: manager, Store: store, Cooldown: cooldown, Stored: stored})
}

// compatModel names a model after the test, so the process-global registry
// keeps tests apart.
func compatModel(t *testing.T, suffix string) string {
	t.Helper()

	return strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")) + "-" + suffix
}

// compatName is a provider name unique to the test.
func compatName(t *testing.T, suffix string) string {
	t.Helper()

	return "c" + strconv.FormatInt(wireSeq.Add(1), 10) + suffix
}

// chatVia sends a chat completion for model through the gateway with the
// wire client's key and returns the status.
func chatVia(t *testing.T, srv *running, model string) int {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.baseURL+"/v1/chat/completions",
		strings.NewReader(`{"model":"`+model+`","messages":[{"role":"user","content":"hi"}]}`))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+wireSecret)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	_ = resp.Body.Close()

	return resp.StatusCode
}

// assertNoKey fails when anything the admin API is built from shows key.
func assertNoKey(t *testing.T, g *Gateway, key string) {
	t.Helper()

	for _, account := range g.Accounts() {
		assert.NotContains(t, fmt.Sprintf("%+v %+v", account, account.Compat), key, "account %s shows its key", account.ID)
	}
}

func heldCompatAuths(g *Gateway, name string) int {
	count := 0

	for _, auth := range g.coreAuth.List() {
		if strings.EqualFold(auth.Attributes[compatAttrName], name) {
			count++
		}
	}

	return count
}

// TestCompatProviderServesLiveAndAfterARestart: an added provider serves its
// models at once with its key, and a restart loads it back from the store —
// routing attributes rebuilt from the sealed metadata, and no keyless copy
// of it held beside it.
func TestCompatProviderServesLiveAndAfterARestart(t *testing.T) {
	pool := pgtest.NewTestPool(t)
	vendor := compatVendor()
	vendorSrv := faketest.Start(t, vendor)
	name, alias := compatName(t, "live"), compatModel(t, "alias")

	first := startCompat(t, pool)

	account, err := first.gateway.AddCompatProvider(t.Context(), app.CompatProvider{
		Name: name, BaseURL: vendorSrv.URL, APIKey: compatKey,
		Models: []app.CompatModel{{Name: "upstream-live", Alias: alias}},
	})
	require.NoError(t, err, "AddCompatProvider")
	require.Equal(t, name, account.Provider, "the account goes by the provider's name")
	require.NotNil(t, account.Compat)
	require.True(t, account.Compat.HasAPIKey)
	require.Equal(t, []app.CompatModel{{Name: "upstream-live", Alias: alias}}, account.Compat.Models)
	assertNoKey(t, first.gateway, compatKey)

	awaitProviders(t, first.gateway.catalog, alias, []string{name})
	require.Equal(t, http.StatusOK, chatVia(t, first, alias), "served straight after it was added")
	require.Equal(t, "Bearer "+compatKey, vendor.Requests()[0].Header.Get("Authorization"), "the vendor got the provider's key")

	require.ErrorIs(t, first.stop(), context.Canceled, "stop: Run must return context.Canceled")

	second := startCompat(t, pool)
	awaitProviders(t, second.gateway.catalog, alias, []string{name})
	require.Equal(t, 1, heldCompatAuths(second.gateway, name), "a keyless synthesised copy is held beside the stored provider")
	require.Equal(t, http.StatusOK, chatVia(t, second, alias), "served after a restart")

	reqs := vendor.Requests()
	require.Equal(t, "Bearer "+compatKey, reqs[len(reqs)-1].Header.Get("Authorization"), "the key after a restart")
}

// TestCompatProviderUpdateDisableRemove: an update replaces the models and
// the key at once, a nil key keeps the stored one, and disabling and removing
// take the models out of service.
func TestCompatProviderUpdateDisableRemove(t *testing.T) {
	pool := pgtest.NewTestPool(t)
	vendor := compatVendor()
	vendorSrv := faketest.Start(t, vendor)
	name, oldModel, newModel := compatName(t, "upd"), compatModel(t, "old"), compatModel(t, "new")

	srv := startCompat(t, pool)
	gw := srv.gateway

	account, err := gw.AddCompatProvider(t.Context(), app.CompatProvider{
		Name: name, BaseURL: vendorSrv.URL, APIKey: "first-key", Models: []app.CompatModel{{Name: oldModel}},
	})
	require.NoError(t, err)
	awaitProviders(t, gw.catalog, oldModel, []string{name})

	newKey := compatKey
	updated, err := gw.UpdateCompatProvider(t.Context(), account.ID, app.CompatProviderUpdate{
		BaseURL: vendorSrv.URL, APIKey: &newKey, Models: []app.CompatModel{{Name: newModel}},
	})
	require.NoError(t, err, "UpdateCompatProvider")
	require.Equal(t, []app.CompatModel{{Name: newModel}}, updated.Compat.Models)

	awaitProviders(t, gw.catalog, oldModel, nil)
	awaitProviders(t, gw.catalog, newModel, []string{name})
	require.Equal(t, http.StatusOK, chatVia(t, srv, newModel))
	require.Equal(t, "Bearer "+compatKey, vendor.Requests()[0].Header.Get("Authorization"), "the replaced key")

	kept, err := gw.UpdateCompatProvider(t.Context(), account.ID, app.CompatProviderUpdate{
		BaseURL: vendorSrv.URL, Models: []app.CompatModel{{Name: newModel}},
	})
	require.NoError(t, err)
	require.True(t, kept.Compat.HasAPIKey, "an update without a key dropped the stored one")
	require.Equal(t, http.StatusOK, chatVia(t, srv, newModel))
	require.Equal(t, "Bearer "+compatKey, vendor.Requests()[1].Header.Get("Authorization"), "the kept key")

	// The stored key does not follow the provider to another base URL.
	_, err = gw.UpdateCompatProvider(t.Context(), account.ID, app.CompatProviderUpdate{
		BaseURL: "https://elsewhere.example.com/v1", Models: []app.CompatModel{{Name: newModel}},
	})

	var invalid *app.InvalidInputError
	require.ErrorAs(t, err, &invalid, "the stored key was kept for another base URL")
	require.Equal(t, "apiKey", invalid.Field)

	cleared := ""
	keyless, err := gw.UpdateCompatProvider(t.Context(), account.ID, app.CompatProviderUpdate{
		BaseURL: vendorSrv.URL, APIKey: &cleared, Models: []app.CompatModel{{Name: newModel}},
	})
	require.NoError(t, err)
	require.False(t, keyless.Compat.HasAPIKey, "an empty key did not remove the stored one")

	require.NoError(t, gw.SetAccountDisabled(t.Context(), account.ID, true))
	awaitProviders(t, gw.catalog, newModel, nil)
	require.NoError(t, gw.SetAccountDisabled(t.Context(), account.ID, false))
	awaitProviders(t, gw.catalog, newModel, []string{name})

	require.NoError(t, gw.RemoveAccount(t.Context(), account.ID))
	awaitProviders(t, gw.catalog, newModel, nil)
	require.False(t, storeLists(t, gw.store, account.ID), "a removed provider is still stored")
	assertNoKey(t, gw, compatKey)
}

// TestCompatProvidersPoolAModel: two providers serving one model name both
// receive its requests, and the policy names both.
func TestCompatProvidersPoolAModel(t *testing.T) {
	pool := pgtest.NewTestPool(t)
	va, vb := compatVendor(), compatVendor()
	sa, sb := faketest.Start(t, va), faketest.Start(t, vb)
	nameA, nameB, model := compatName(t, "a"), compatName(t, "b"), compatModel(t, "pooled")

	srv := startCompat(t, pool)

	for _, p := range []app.CompatProvider{
		{Name: nameA, BaseURL: sa.URL, APIKey: "key-a", Models: []app.CompatModel{{Name: model}}},
		{Name: nameB, BaseURL: sb.URL, APIKey: "key-b", Models: []app.CompatModel{{Name: model}}},
	} {
		_, err := srv.gateway.AddCompatProvider(t.Context(), p)
		require.NoError(t, err)
	}

	want := []string{nameA, nameB}
	if nameB < nameA {
		want = []string{nameB, nameA}
	}

	awaitProviders(t, srv.gateway.catalog, model, want)

	for range 8 {
		require.Equal(t, http.StatusOK, chatVia(t, srv, model))
	}

	assert.NotEmpty(t, va.Requests(), "the pooled model never reached the first provider")
	assert.NotEmpty(t, vb.Requests(), "the pooled model never reached the second provider")
}

// sentEffort sends a chat completion for model with reasoning_effort effort
// ("" leaves the key out), requires it served, and returns the body vendor
// last received.
func sentEffort(t *testing.T, srv *running, vendor *faketest.Vendor, model, effort string) map[string]any {
	t.Helper()

	payload := map[string]any{"model": model, "messages": []any{map[string]any{"role": "user", "content": "hi"}}}
	if effort != "" {
		payload["reasoning_effort"] = effort
	}

	raw, err := json.Marshal(payload)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.baseURL+"/v1/chat/completions", bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+wireSecret)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "reasoning_effort %q", effort)

	reqs := vendor.Requests()
	require.NotEmpty(t, reqs)

	var body map[string]any
	require.NoError(t, json.Unmarshal(reqs[len(reqs)-1].Body, &body))

	return body
}

// compatAccountModels is the models Accounts() reports for the account id.
func compatAccountModels(t *testing.T, g *Gateway, id string) []app.CompatModel {
	t.Helper()

	for _, account := range g.Accounts() {
		if account.ID == id {
			require.NotNil(t, account.Compat)

			return account.Compat.Models
		}
	}

	require.Failf(t, "account not listed", "%s", id)

	return nil
}

// TestCompatProviderPassesReasoningEffort: a model without its own list
// passes every level of the default set unchanged, sends "auto" as "medium",
// and adds nothing to a request without reasoning_effort.
func TestCompatProviderPassesReasoningEffort(t *testing.T) {
	vendor := compatVendor()
	vendorSrv := faketest.Start(t, vendor)
	name, model := compatName(t, "effort"), compatModel(t, "m")

	srv := startCompat(t, pgtest.NewTestPool(t))

	_, err := srv.gateway.AddCompatProvider(t.Context(), app.CompatProvider{
		Name: name, BaseURL: vendorSrv.URL, Models: []app.CompatModel{{Name: model}},
	})
	require.NoError(t, err)
	awaitProviders(t, srv.gateway.catalog, model, []string{name})

	for _, effort := range []string{"none", "minimal", "low", "medium", "high", "xhigh", "max"} {
		assert.Equal(t, effort, sentEffort(t, srv, vendor, model, effort)["reasoning_effort"], "sent %q", effort)
	}

	assert.Equal(t, "medium", sentEffort(t, srv, vendor, model, "auto")["reasoning_effort"], "sent auto")
	assert.NotContains(t, sentEffort(t, srv, vendor, model, ""), "reasoning_effort", "added to a request without it")
}

// TestCompatProviderOwnReasoningLevels: a model's own list is passed
// unchanged, a level off it goes out as the nearest listed one, and the list
// survives a restart; a model without one reports none.
func TestCompatProviderOwnReasoningLevels(t *testing.T) {
	pool := pgtest.NewTestPool(t)
	vendor := compatVendor()
	vendorSrv := faketest.Start(t, vendor)
	name, model, plain := compatName(t, "own"), compatModel(t, "m"), compatModel(t, "plain")
	own := []string{"none", "high", "ultra"}

	first := startCompat(t, pool)

	account, err := first.gateway.AddCompatProvider(t.Context(), app.CompatProvider{
		Name: name, BaseURL: vendorSrv.URL,
		Models: []app.CompatModel{{Name: model, ReasoningLevels: own}, {Name: plain}},
	})
	require.NoError(t, err)

	want := []app.CompatModel{{Name: model, ReasoningLevels: own}, {Name: plain}}
	require.Equal(t, want, account.Compat.Models)
	require.Equal(t, want, compatAccountModels(t, first.gateway, account.ID))

	check := func(srv *running) {
		t.Helper()
		awaitProviders(t, srv.gateway.catalog, model, []string{name})

		for _, effort := range own {
			assert.Equal(t, effort, sentEffort(t, srv, vendor, model, effort)["reasoning_effort"], "sent %q", effort)
		}

		assert.Equal(t, "high", sentEffort(t, srv, vendor, model, "max")["reasoning_effort"], "sent max")
	}

	check(first)
	require.ErrorIs(t, first.stop(), context.Canceled, "stop: Run must return context.Canceled")

	second := startCompat(t, pool)
	require.Equal(t, want, compatAccountModels(t, second.gateway, account.ID), "after a restart")
	check(second)
}

// TestCompatProviderUpdateReasoningLevels: an update that gives a model its
// own list applies it at once, and one that takes it away returns the model
// to the default set.
func TestCompatProviderUpdateReasoningLevels(t *testing.T) {
	vendor := compatVendor()
	vendorSrv := faketest.Start(t, vendor)
	name, model := compatName(t, "relevel"), compatModel(t, "m")

	srv := startCompat(t, pgtest.NewTestPool(t))

	account, err := srv.gateway.AddCompatProvider(t.Context(), app.CompatProvider{
		Name: name, BaseURL: vendorSrv.URL, Models: []app.CompatModel{{Name: model}},
	})
	require.NoError(t, err)
	awaitProviders(t, srv.gateway.catalog, model, []string{name})

	own := []app.CompatModel{{Name: model, ReasoningLevels: []string{"none", "high"}}}
	_, err = srv.gateway.UpdateCompatProvider(t.Context(), account.ID, app.CompatProviderUpdate{BaseURL: vendorSrv.URL, Models: own})
	require.NoError(t, err)
	require.Equal(t, own, compatAccountModels(t, srv.gateway, account.ID))
	awaitProviders(t, srv.gateway.catalog, model, []string{name})
	assert.Equal(t, "high", sentEffort(t, srv, vendor, model, "max")["reasoning_effort"], "sent max with an own list")

	plain := []app.CompatModel{{Name: model}}
	_, err = srv.gateway.UpdateCompatProvider(t.Context(), account.ID, app.CompatProviderUpdate{BaseURL: vendorSrv.URL, Models: plain})
	require.NoError(t, err)
	require.Equal(t, plain, compatAccountModels(t, srv.gateway, account.ID))
	awaitProviders(t, srv.gateway.catalog, model, []string{name})
	assert.Equal(t, "max", sentEffort(t, srv, vendor, model, "max")["reasoning_effort"], "sent max without one")
}

// TestCompatProviderNames: a name a built-in provider goes by is refused as
// invalid input, and a taken one as a conflict.
func TestCompatProviderNames(t *testing.T) {
	srv := startCompat(t, pgtest.NewTestPool(t))
	models := []app.CompatModel{{Name: compatModel(t, "m")}}

	for _, reserved := range []string{"claude", "chatgpt", "codex", "gemini"} {
		_, err := srv.gateway.AddCompatProvider(t.Context(), app.CompatProvider{Name: reserved, BaseURL: "http://example.com", Models: models})

		var invalid *app.InvalidInputError
		require.ErrorAs(t, err, &invalid, "name %q", reserved)
		require.Equal(t, "name", invalid.Field)
	}

	name := compatName(t, "taken")
	_, err := srv.gateway.AddCompatProvider(t.Context(), app.CompatProvider{Name: name, BaseURL: "http://example.com", Models: models})
	require.NoError(t, err)

	_, err = srv.gateway.AddCompatProvider(t.Context(), app.CompatProvider{Name: name, BaseURL: "http://example.com", Models: models})
	require.ErrorIs(t, err, app.ErrConflict)
}

// TestDiscoverModels: the model list comes back sorted and without
// duplicates, the key goes along as a bearer token, and every failure is one
// of two stable refusals that carry nothing the vendor said.
func TestDiscoverModels(t *testing.T) {
	const vendorSecret = "internal-detail-7d1e"

	var gotAuth string

	mux := http.NewServeMux()
	mux.HandleFunc("GET /ok/models", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"b"},{"id":"a"},{"id":"b"}]}`))
	})
	mux.HandleFunc("GET /denied/models", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, vendorSecret, http.StatusUnauthorized)
	})
	mux.HandleFunc("GET /broken/models", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, vendorSecret, http.StatusInternalServerError)
	})
	mux.HandleFunc("GET /html/models", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>" + vendorSecret + "</html>"))
	})
	mux.HandleFunc("GET /huge/models", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"` + strings.Repeat("x", discoverMaxBytes) + `"}]}`))
	})

	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"leaked"}]}`))
	}))
	t.Cleanup(elsewhere.Close)
	mux.HandleFunc("GET /away/models", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+"/models", http.StatusFound)
	})
	mux.HandleFunc("GET /here/models", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ok/models", http.StatusFound)
	})

	vendor := httptest.NewServer(mux)
	t.Cleanup(vendor.Close)

	gw := &Gateway{}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ids, err := gw.DiscoverModels(ctx, vendor.URL+"/ok/", "sk-discover", "", nil)
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, ids)
	require.Equal(t, "Bearer sk-discover", gotAuth)

	ids, err = gw.DiscoverModels(ctx, vendor.URL+"/here", "", "", nil)
	require.NoError(t, err, "a redirect on the same host is followed")
	require.Equal(t, []string{"a", "b"}, ids)
	require.Empty(t, gotAuth, "a key was sent though none was given")

	_, err = gw.DiscoverModels(ctx, vendor.URL+"/denied", "sk-discover", "", nil)
	require.ErrorIs(t, err, app.ErrProviderAuthFailed)
	require.NotContains(t, err.Error(), vendorSecret)

	for _, path := range []string{"/broken", "/html", "/huge", "/away"} {
		_, err = gw.DiscoverModels(ctx, vendor.URL+path, "sk-discover", "", nil)
		require.ErrorIs(t, err, app.ErrProviderUnreachable, path)
		require.NotContains(t, err.Error(), vendorSecret, path)
		require.NotContains(t, err.Error(), vendor.URL, "%s: the error names the URL", path)
	}
}

// TestDiscoverModelsRefusesLinkLocalTargets: a link-local target (where cloud
// metadata answers) is refused before anything is sent, directly and behind
// a proxy-url, where the dialer only ever sees the proxy; loopback, where a
// local vendor runs, stays allowed.
func TestDiscoverModelsRefusesLinkLocalTargets(t *testing.T) {
	var proxied atomic.Int64

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxied.Add(1)

		_, _ = w.Write([]byte(`{"data":[{"id":"m"}]}`))
	}))
	t.Cleanup(proxy.Close)

	for name, proxyURL := range map[string]string{"direct": "", "behind a proxy": proxy.URL} {
		t.Run(name, func(t *testing.T) {
			gw := &Gateway{current: &cliproxyconfig.Config{ProxyURL: proxyURL}}

			for _, base := range []string{"http://169.254.169.254/latest", "http://[fe80::1]/v1", "http://0.0.0.0:1/v1"} {
				_, err := gw.DiscoverModels(t.Context(), base, "sk-discover", "", nil)

				var invalid *app.InvalidInputError
				require.ErrorAs(t, err, &invalid, "%s was asked", base)
				require.Equal(t, "baseURL", invalid.Field)
			}

			require.Zero(t, proxied.Load(), "a link-local target reached the proxy")
		})
	}

	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"local"}]}`))
	}))
	t.Cleanup(vendor.Close)

	ids, err := (&Gateway{}).DiscoverModels(t.Context(), vendor.URL, "", "", nil)
	require.NoError(t, err, "a loopback vendor is allowed")
	require.Equal(t, []string{"local"}, ids)
}

// TestDiscoverModelsGivesUpOnASlowVendor: a vendor that does not answer in
// time is unreachable, not waited on.
func TestDiscoverModelsGivesUpOnASlowVendor(t *testing.T) {
	release := make(chan struct{})

	slow := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))

	t.Cleanup(func() { close(release); slow.Close() })

	started := time.Now()
	_, err := (&Gateway{discoverWait: 200 * time.Millisecond}).DiscoverModels(t.Context(), slow.URL, "", "", nil)
	require.ErrorIs(t, err, app.ErrProviderUnreachable)
	require.Less(t, time.Since(started), 5*time.Second, "discovery waited past its timeout")
}

// TestDiscoverModelsWithTheStoredKey: discovery for an existing provider
// sends its stored key when none is typed, and only to the provider's own
// base URL: another host an administrator types never receives it.
func TestDiscoverModelsWithTheStoredKey(t *testing.T) {
	var gotAuth string

	vendor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"data":[{"id":"m"}]}`))
	}))
	t.Cleanup(vendor.Close)

	var elsewhereAsked bool

	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhereAsked = true
		_, _ = w.Write([]byte(`{"data":[{"id":"m"}]}`))
	}))
	t.Cleanup(elsewhere.Close)

	srv := startCompat(t, pgtest.NewTestPool(t))
	account, err := srv.gateway.AddCompatProvider(t.Context(), app.CompatProvider{
		Name: compatName(t, "disc"), BaseURL: vendor.URL, APIKey: compatKey, Models: []app.CompatModel{{Name: compatModel(t, "m")}},
	})
	require.NoError(t, err)

	_, err = srv.gateway.DiscoverModels(t.Context(), vendor.URL+"/", "", account.ID, nil)
	require.NoError(t, err)
	require.Equal(t, "Bearer "+compatKey, gotAuth)

	_, err = srv.gateway.DiscoverModels(t.Context(), elsewhere.URL, "", account.ID, nil)

	var invalid *app.InvalidInputError
	require.ErrorAs(t, err, &invalid, "the stored key was offered to another host")
	require.Equal(t, "apiKey", invalid.Field)
	require.False(t, elsewhereAsked, "another host was asked with the stored key")
}

// TestReasoningLevelsFallBackOnCorruptMetadata: a stored list with no string
// left takes the default set rather than declaring no levels at all.
func TestReasoningLevelsFallBackOnCorruptMetadata(t *testing.T) {
	require.Nil(t, reasoningLevels([]any{1, true}))
	require.Nil(t, reasoningLevels([]any{}))
	require.Nil(t, reasoningLevels([]string{}))
	require.Equal(t, []string{"low"}, reasoningLevels([]any{"low", 2}))
}
