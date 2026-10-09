package e2e

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
	"github.com/stretchr/testify/require"
)

// e2eProxyPassword is the password in the account proxy's URL; no answer and
// no output may show it.
const e2eProxyPassword = "e2e-proxy-pass-41a"

// TestAProviderProxySetInTheAdminPanel: the administrator gives an
// OpenAI-compatible provider its own proxy through the admin API; the
// provider's requests then go through it, the list shows it without its
// password, and setting it back to inherit takes it out of the path.
func TestAProviderProxySetInTheAdminPanel(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}

	fake := &faketest.Vendor{Payload: []byte(vendorPayload)}
	vendor := faketest.Start(t, fake)

	var carried atomic.Int64

	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, r *http.Request) {
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

		writer.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(writer, resp.Body)
	}))
	t.Cleanup(proxy.Close)

	proxyURL, err := url.Parse(proxy.URL)
	require.NoError(t, err)

	proxyURL.User = url.UserPassword("ops", e2eProxyPassword)

	proc := startProcess(t, "", nil)
	proc.signInAsBootstrapAdmin(t)

	const name, model = "proxied", "e2e-proxied-model"

	var created api.ProviderAccount
	proc.webJSON(t, http.MethodPost, "/api/admin/providers/compat",
		`{"name":"`+name+`","baseURL":"`+vendor.URL+`","models":[{"name":"upstream","alias":"`+model+`"}],`+
			`"proxy":{"mode":"custom","url":"`+proxyURL.String()+`"}}`, http.StatusCreated, &created)
	require.Equal(t, api.AccountProxyMode("custom"), created.Proxy.Mode)

	_, list := proc.webCall(t, http.MethodGet, "/api/admin/providers", "")
	require.NotContains(t, string(list), e2eProxyPassword, "the provider list shows the proxy password")

	var accounts []api.ProviderAccount
	proc.webJSON(t, http.MethodGet, "/api/admin/providers", "", http.StatusOK, &accounts)

	at := slices.IndexFunc(accounts, func(a api.ProviderAccount) bool { return a.Provider == name })
	require.NotEqual(t, -1, at)
	require.Equal(t, proxy.URL, *accounts[at].Proxy.Url)
	require.True(t, *accounts[at].Proxy.HasCredentials)

	secret := proc.issueToken(t, "proxied").Secret
	proc.setPolicy(t, proc.adminEmail, name+":*")
	eventually(t, "the provider's model is listed", func() bool { return proc.models(t, secret)[model] })

	require.Equal(t, http.StatusOK, proc.chat(t, secret, model))
	require.Equal(t, int64(1), carried.Load(), "the provider's proxy carried the request")

	code, body := proc.webCall(t, http.MethodPatch, "/api/admin/providers/"+created.Id, `{"proxy":{"mode":"inherit"}}`)
	require.Equal(t, http.StatusOK, code, "%s", body)

	require.Equal(t, http.StatusOK, proc.chat(t, secret, model))
	require.Equal(t, int64(1), carried.Load(), "inherit: the provider's proxy still carried a request")
	require.Len(t, fake.Requests(), 2)
}
