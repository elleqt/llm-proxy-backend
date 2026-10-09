package providers_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/app/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const compatSecret = "sk-compat-secret-3b9a"

var compatAccount = app.VendorAccount{
	ID: "openai-compatible-acme", Provider: "acme", Status: "active",
	Compat: &app.CompatDetails{Name: "acme", BaseURL: "https://api.example.com/v1", HasAPIKey: true, Models: []app.CompatModel{{Name: "m"}}},
}

// TestCreateCompatNormalisesAndAuditsWithoutTheKey: the definition reaches
// the gateway trimmed, and the audit record says there is a key without
// carrying it.
func TestCreateCompatNormalisesAndAuditsWithoutTheKey(t *testing.T) {
	fixture := newProvidersFixture(t)
	fixture.recordAudits()

	fixture.accounts.EXPECT().AddCompatProvider(mock.Anything, app.CompatProvider{
		Name: "acme", BaseURL: "https://api.example.com/v1", APIKey: compatSecret, Prefix: "team",
		Models: []app.CompatModel{{Name: "m"}, {Name: "m", Alias: "m-fast"}},
	}).Return(compatAccount, nil)

	account, err := fixture.svc.CreateCompat(context.Background(), providerAdmin(), app.CompatProvider{
		Name: " AcMe ", BaseURL: " https://api.example.com/v1/ ", APIKey: compatSecret, Prefix: " team ",
		Models: []app.CompatModel{{Name: " m "}, {Name: "m", Alias: " m-fast "}},
	})
	require.NoError(t, err)
	require.Equal(t, compatAccount, account)

	require.Len(t, fixture.events, 1)
	require.Equal(t, "provider.compat_add", fixture.events[0].Action)
	require.Equal(t, true, fixture.events[0].Detail["has_api_key"])
	assert.NotContains(t, fmt.Sprint(fixture.events[0]), compatSecret, "the audit record carries the key")
}

// TestCreateCompatRefusesABadDefinition names the field at fault and never
// reaches the gateway (the strict mock has no expectations).
func TestCreateCompatRefusesABadDefinition(t *testing.T) {
	good := app.CompatProvider{Name: "acme", BaseURL: "https://api.example.com/v1", Models: []app.CompatModel{{Name: "m"}}}

	for name, tc := range map[string]struct {
		edit  func(*app.CompatProvider)
		field string
	}{
		"name with a colon":  {func(p *app.CompatProvider) { p.Name = "acme:x" }, "name"},
		"empty name":         {func(p *app.CompatProvider) { p.Name = "" }, "name"},
		"relative base URL":  {func(p *app.CompatProvider) { p.BaseURL = "api.example.com/v1" }, "baseURL"},
		"ftp base URL":       {func(p *app.CompatProvider) { p.BaseURL = "ftp://example.com" }, "baseURL"},
		"credentials in URL": {func(p *app.CompatProvider) { p.BaseURL = "https://u:p@example.com/v1" }, "baseURL"},
		"query in URL":       {func(p *app.CompatProvider) { p.BaseURL = "https://example.com/v1?key=x" }, "baseURL"},
		"no models":          {func(p *app.CompatProvider) { p.Models = nil }, "models"},
		"blank model":        {func(p *app.CompatProvider) { p.Models = []app.CompatModel{{Name: " "}} }, "models"},
		"one name served twice": {func(p *app.CompatProvider) {
			p.Models = []app.CompatModel{{Name: "a", Alias: "x"}, {Name: "b", Alias: "x"}}
		}, "models"},
		"prefix with a slash": {func(p *app.CompatProvider) { p.Prefix = "a/b" }, "prefix"},
	} {
		t.Run(name, func(t *testing.T) {
			p := good
			tc.edit(&p)

			_, err := newProvidersFixture(t).svc.CreateCompat(context.Background(), providerAdmin(), p)

			var invalid *app.InvalidInputError
			require.ErrorAs(t, err, &invalid)
			require.Equal(t, tc.field, invalid.Field)
		})
	}
}

// TestCreateCompatWithdrawsAnUnauditedProvider: a provider must not serve
// unrecorded.
func TestCreateCompatWithdrawsAnUnauditedProvider(t *testing.T) {
	fixture := newProvidersFixture(t)
	auditDown := errors.New("audit store down")

	fixture.accounts.EXPECT().AddCompatProvider(mock.Anything, mock.Anything).Return(compatAccount, nil)
	fixture.audit.EXPECT().Record(mock.Anything, mock.Anything).Return(auditDown)
	fixture.accounts.EXPECT().RemoveAccount(mock.Anything, compatAccount.ID).Return(nil)

	_, err := fixture.svc.CreateCompat(context.Background(), providerAdmin(), app.CompatProvider{
		Name: "acme", BaseURL: "https://api.example.com/v1", Models: []app.CompatModel{{Name: "m"}},
	})
	require.ErrorIs(t, err, auditDown)
}

// TestUpdateCompatPassesTheKeyChangeThrough: nil keeps the stored key, and
// the audit record says whether it changed without carrying it.
func TestUpdateCompatPassesTheKeyChangeThrough(t *testing.T) {
	fixture := newProvidersFixture(t)
	fixture.recordAudits()
	fixture.quota.EXPECT().QuotaSignals().Return(nil)

	key := compatSecret
	fixture.accounts.EXPECT().UpdateCompatProvider(mock.Anything, compatAccount.ID, app.CompatProviderUpdate{
		BaseURL: "https://api.example.com/v1", APIKey: &key, Models: []app.CompatModel{{Name: "m"}},
	}).Return(compatAccount, nil)

	_, err := fixture.svc.UpdateCompat(context.Background(), providerAdmin(), compatAccount.ID, app.CompatProviderUpdate{
		BaseURL: "https://api.example.com/v1/", APIKey: &key, Models: []app.CompatModel{{Name: "m"}},
	})
	require.NoError(t, err)
	require.Len(t, fixture.events, 1)
	require.Equal(t, true, fixture.events[0].Detail["key_changed"])
	assert.NotContains(t, fmt.Sprint(fixture.events[0]), compatSecret)
}

// TestDiscoverCompatReportsModelsOtherProvidersServe: a discovered model
// another provider serves is flagged with that provider, and the provider
// being edited does not conflict with itself.
func TestDiscoverCompatReportsModelsOtherProvidersServe(t *testing.T) {
	fixture := newProvidersFixture(t)

	fixture.accounts.EXPECT().DiscoverModels(mock.Anything, "https://api.example.com/v1", "", compatAccount.ID, (*app.ProxyChoice)(nil)).
		Return([]string{"m", "shared", "fresh"}, nil)
	fixture.accounts.EXPECT().Accounts().Return([]app.VendorAccount{compatAccount})
	fixture.catalog.EXPECT().Models().Return(map[string][]string{
		"acme": {"m", "shared"}, "other": {"shared"}, "claude": {"claude-x"},
	})

	got, err := fixture.svc.DiscoverCompat(context.Background(), providerAdmin(), "https://api.example.com/v1/", "", compatAccount.ID, nil)
	require.NoError(t, err)
	require.Equal(t, providers.CompatDiscovery{
		Models:    []string{"m", "shared", "fresh"},
		Conflicts: map[string][]string{"shared": {"other"}},
	}, got)
}

// TestDiscoverCompatPassesTheRefusalThrough: the gateway's stable refusals
// reach the caller as they are.
func TestDiscoverCompatPassesTheRefusalThrough(t *testing.T) {
	accounts := mocks.NewVendorAccounts(t)
	svc := providers.New(accounts, mocks.NewVendorLogins(t), mocks.NewModelCatalog(t), mocks.NewVendorQuota(t),
		mocks.NewAccountMetrics(t), mocks.NewAuditSink(t), systemClock{}, discardLogger{})

	accounts.EXPECT().DiscoverModels(mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil, app.ErrProviderAuthFailed)

	_, err := svc.DiscoverCompat(context.Background(), providerAdmin(), "https://api.example.com/v1", "k", "", nil)
	require.ErrorIs(t, err, app.ErrProviderAuthFailed)
}

// compatProxySecret is a proxy URL with credentials: an audit record must
// never carry it.
const compatProxySecret = "http://ops:proxy-pass@proxy.example.com:3128"

// TestCreateCompatRefusesABadProxy names the proxy field and never reaches the
// gateway (the strict mock has no expectations).
func TestCreateCompatRefusesABadProxy(t *testing.T) {
	fixture := newProvidersFixture(t)

	_, err := fixture.svc.CreateCompat(context.Background(), providerAdmin(), app.CompatProvider{
		Name: "acme", BaseURL: "https://api.example.com/v1", Models: []app.CompatModel{{Name: "m"}},
		Proxy: &app.ProxyChoice{Mode: app.ProxyCustom, URL: "ftp://x.example.com"},
	})

	var invalid *app.InvalidInputError
	require.ErrorAs(t, err, &invalid)
	require.Equal(t, app.FieldProxyURL, invalid.Field)
}

// TestCreateCompatPassesTheProxyThrough: a valid proxy reaches the gateway
// normalised, and the audit record carries its mode only.
func TestCreateCompatPassesTheProxyThrough(t *testing.T) {
	fixture := newProvidersFixture(t)
	fixture.recordAudits()

	fixture.accounts.EXPECT().AddCompatProvider(mock.Anything, app.CompatProvider{
		Name: "acme", BaseURL: "https://api.example.com/v1", Models: []app.CompatModel{{Name: "m"}},
		Proxy: &app.ProxyChoice{Mode: app.ProxyCustom, URL: compatProxySecret},
	}).Return(compatAccount, nil)

	_, err := fixture.svc.CreateCompat(context.Background(), providerAdmin(), app.CompatProvider{
		Name: "acme", BaseURL: "https://api.example.com/v1", Models: []app.CompatModel{{Name: "m"}},
		Proxy: &app.ProxyChoice{Mode: app.ProxyCustom, URL: " " + compatProxySecret + " "},
	})
	require.NoError(t, err)
	require.Len(t, fixture.events, 1)
	require.Equal(t, "custom", fixture.events[0].Detail["proxy_mode"])
	assert.NotContains(t, fmt.Sprintf("%+v", fixture.events), "proxy-pass")
}

// TestCreateCompatWithoutAProxyInherits: no proxy is audited as inherit.
func TestCreateCompatWithoutAProxyInherits(t *testing.T) {
	fixture := newProvidersFixture(t)
	fixture.recordAudits()

	fixture.accounts.EXPECT().AddCompatProvider(mock.Anything, app.CompatProvider{
		Name: "acme", BaseURL: "https://api.example.com/v1", Models: []app.CompatModel{{Name: "m"}},
	}).Return(compatAccount, nil)

	_, err := fixture.svc.CreateCompat(context.Background(), providerAdmin(), app.CompatProvider{
		Name: "acme", BaseURL: "https://api.example.com/v1", Models: []app.CompatModel{{Name: "m"}},
	})
	require.NoError(t, err)
	require.Len(t, fixture.events, 1)
	require.Equal(t, "inherit", fixture.events[0].Detail["proxy_mode"])
}

// TestUpdateCompatRefusesABadProxy names the proxy field and never reaches the
// gateway (the strict mock has no expectations).
func TestUpdateCompatRefusesABadProxy(t *testing.T) {
	fixture := newProvidersFixture(t)

	_, err := fixture.svc.UpdateCompat(context.Background(), providerAdmin(), compatAccount.ID, app.CompatProviderUpdate{
		BaseURL: "https://api.example.com/v1", Models: []app.CompatModel{{Name: "m"}},
		Proxy: &app.ProxyChoice{Mode: "sideways"},
	})

	var invalid *app.InvalidInputError
	require.ErrorAs(t, err, &invalid)
	require.Equal(t, app.FieldProxyMode, invalid.Field)
}

// TestUpdateCompatAuditsTheProxyChange: a proxy change is passed through and
// audited by its mode only.
func TestUpdateCompatAuditsTheProxyChange(t *testing.T) {
	fixture := newProvidersFixture(t)
	fixture.recordAudits()
	fixture.quota.EXPECT().QuotaSignals().Return(nil)

	fixture.accounts.EXPECT().UpdateCompatProvider(mock.Anything, compatAccount.ID, app.CompatProviderUpdate{
		BaseURL: "https://api.example.com/v1", Models: []app.CompatModel{{Name: "m"}},
		Proxy: &app.ProxyChoice{Mode: app.ProxyDirect},
	}).Return(compatAccount, nil)

	_, err := fixture.svc.UpdateCompat(context.Background(), providerAdmin(), compatAccount.ID, app.CompatProviderUpdate{
		BaseURL: "https://api.example.com/v1", Models: []app.CompatModel{{Name: "m"}},
		Proxy: &app.ProxyChoice{Mode: app.ProxyDirect},
	})
	require.NoError(t, err)
	require.Len(t, fixture.events, 1)
	require.Equal(t, true, fixture.events[0].Detail["proxy_changed"])
	require.Equal(t, "direct", fixture.events[0].Detail["proxy_mode"])
}

// TestDiscoverCompatRefusesABadProxy names the proxy field and never reaches
// the gateway (the strict mock has no expectations).
func TestDiscoverCompatRefusesABadProxy(t *testing.T) {
	fixture := newProvidersFixture(t)

	_, err := fixture.svc.DiscoverCompat(context.Background(), providerAdmin(), "https://api.example.com/v1", "k", "",
		&app.ProxyChoice{Mode: app.ProxyCustom, URL: "http://proxy.example.com:70000"})

	var invalid *app.InvalidInputError
	require.ErrorAs(t, err, &invalid)
	require.Equal(t, app.FieldProxyURL, invalid.Field)
}

// TestDiscoverCompatPassesTheProxyThrough: discovery asks through the proxy
// it is given, normalised.
func TestDiscoverCompatPassesTheProxyThrough(t *testing.T) {
	fixture := newProvidersFixture(t)

	fixture.accounts.EXPECT().DiscoverModels(mock.Anything, "https://api.example.com/v1", "k", "",
		&app.ProxyChoice{Mode: app.ProxyCustom, URL: compatProxySecret}).Return([]string{"m"}, nil)
	fixture.accounts.EXPECT().Accounts().Return(nil)
	fixture.catalog.EXPECT().Models().Return(nil)

	got, err := fixture.svc.DiscoverCompat(context.Background(), providerAdmin(), "https://api.example.com/v1", "k", "",
		&app.ProxyChoice{Mode: app.ProxyCustom, URL: " " + compatProxySecret + " "})
	require.NoError(t, err)
	require.Equal(t, []string{"m"}, got.Models)
}
