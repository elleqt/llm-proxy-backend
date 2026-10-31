package http

import (
	"net/http"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestProviderResponsesUseSharedPriority(t *testing.T) {
	env := newEnv(t)
	env.accounts.EXPECT().Accounts().Return([]app.VendorAccount{
		{ID: "claude-a.json", Provider: "claude", Status: "active", Priority: 1},
		{
			ID: "openai-compatible-acme", Provider: "acme", Status: "active", Priority: -1,
			Compat: &app.CompatDetails{Name: "acme", BaseURL: "https://api.example.com/v1", Models: []app.CompatModel{{Name: "m"}}},
		},
	})
	env.quota.EXPECT().QuotaSignals().Return(nil)

	var accounts []map[string]any
	decodeBody(t, env.do(http.MethodGet, "/api/admin/providers", "", withCookie(env.signedIn(admin()))), http.StatusOK, &accounts)
	require.Len(t, accounts, 2)
	require.Equal(t, float64(1), accounts[0]["priority"])
	require.Equal(t, float64(-1), accounts[1]["priority"])
	details, ok := accounts[1]["compat"].(map[string]any)
	require.True(t, ok)
	require.NotContains(t, details, "priority")
}

func TestPriorityOnlyPatchAcceptsZeroAndKeepsOtherAccountSettings(t *testing.T) {
	env := newEnv(t)
	before := app.VendorAccount{
		ID: "codex-a.json", Provider: "chatgpt", Priority: 7, Disabled: true,
		Status: "disabled", Proxy: app.AccountProxy{Mode: app.ProxyDirect},
	}
	after := before
	after.Priority = 0

	env.accounts.EXPECT().Accounts().Return([]app.VendorAccount{before}).Once()
	env.accounts.EXPECT().SetAccountPriority(mock.Anything, before.ID, int32(0)).Return(nil)
	env.accounts.EXPECT().Accounts().Return([]app.VendorAccount{after}).Once()
	env.quota.EXPECT().QuotaSignals().Return(nil)

	var account api.ProviderAccount
	decodeBody(t, env.do(http.MethodPatch, "/api/admin/providers/"+before.ID, `{"priority":0}`,
		withCookie(env.signedIn(admin()))), http.StatusOK, &account)
	require.True(t, account.Disabled)
	require.Equal(t, api.AccountProxyMode("direct"), account.Proxy.Mode)
}
