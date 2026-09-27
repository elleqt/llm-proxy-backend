package e2e

import (
	"context"
	"net/http"
	"os"
	"slices"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// The compat test's parent hands each boot the vendor's URL through this variable.
const compatVendorEnv = "LLMPROXY_E2E_COMPAT_VENDOR"

// compatVendorKey is the key the provider is added with. It must never leave
// the process: not in an answer, not in the output.
const compatVendorKey = "sk-e2e-compat-vendor-6c0f"

// TestAnOpenAICompatibleProviderAddedInTheAdminPanel: the administrator adds
// an OpenAI-compatible provider through the admin API; it serves its model at
// once, with its key, under a policy naming it, and the usage row names it.
// Stopped and started again on the same database, it still serves: the
// provider lives in the credential store. The key appears in no answer and
// in no output.
func TestAnOpenAICompatibleProviderAddedInTheAdminPanel(t *testing.T) {
	if !isChild() {
		t.Parallel()

		pool := pgtest.NewTestPool(t)
		vendor := &faketest.Vendor{Payload: []byte(vendorPayload)}
		srv := faketest.Start(t, vendor)

		for _, which := range []string{"first", "second"} {
			out, err := runChildWith(t, restartDatabaseEnv+"="+pool.Config().ConnString(),
				compatVendorEnv+"="+srv.URL, restartBootEnv+"="+which)
			require.NoError(t, err, "the %s boot:\n%s", which, out)
			require.Contains(t, string(out), "--- PASS: "+t.Name(), "the %s boot", which)
			require.NotContains(t, string(out), compatVendorKey, "the %s boot's output shows the vendor key", which)
		}

		reqs := vendor.Requests()
		require.Len(t, reqs, 2, "one request per boot reached the vendor")

		for _, r := range reqs {
			require.Equal(t, "Bearer "+compatVendorKey, r.Header.Get("Authorization"), "the vendor key")
		}

		return
	}

	pool, err := pgxpool.New(context.Background(), os.Getenv(restartDatabaseEnv))
	require.NoError(t, err, "pool")
	t.Cleanup(pool.Close)

	proc := startProcessOn(t, pool, "", nil)
	first := os.Getenv(restartBootEnv) == "first"

	if first {
		proc.readBootstrapPassword(t)
		proc.claimTemporaryPassword(t, proc.adminPassword, restartPassword)
	} else {
		var me api.Me
		proc.webJSON(t, http.MethodPost, "/api/auth/login",
			`{"email":"`+proc.adminEmail+`","password":"`+restartPassword+`"}`, http.StatusOK, &me)
	}

	const name, model = "acme", "e2e-compat-model"

	if first {
		code, body := proc.webCall(t, http.MethodPost, "/api/admin/providers/compat",
			`{"name":"`+name+`","baseURL":"`+os.Getenv(compatVendorEnv)+`","apiKey":"`+compatVendorKey+`",`+
				`"models":[{"name":"upstream-compat","alias":"`+model+`"}]}`)
		require.Equal(t, http.StatusCreated, code, "create: %s", body)
		require.NotContains(t, string(body), compatVendorKey, "the create answer shows the key")
	}

	_, list := proc.webCall(t, http.MethodGet, "/api/admin/providers", "")
	require.NotContains(t, string(list), compatVendorKey, "the provider list shows the key")

	var accounts []api.ProviderAccount
	proc.webJSON(t, http.MethodGet, "/api/admin/providers", "", http.StatusOK, &accounts)

	at := slices.IndexFunc(accounts, func(a api.ProviderAccount) bool { return a.Provider == name })
	require.NotEqual(t, -1, at, "the admin API lists %+v without the provider", accounts)
	require.NotNil(t, accounts[at].Compat)
	require.True(t, accounts[at].Compat.HasApiKey)

	secret := proc.issueToken(t, "compat-"+os.Getenv(restartBootEnv)).Secret
	proc.setPolicy(t, proc.adminEmail, name+":*")

	eventually(t, "the provider's model is listed", func() bool { return proc.models(t, secret)[model] })
	require.Equal(t, http.StatusOK, proc.chat(t, secret, model), "a request to the provider's model")

	var provider, account string

	eventually(t, "the request reached the ledger", func() bool {
		err := pool.QueryRow(context.Background(),
			`SELECT provider, vendor_account_id FROM usage_events WHERE model = 'upstream-compat' ORDER BY id DESC LIMIT 1`).
			Scan(&provider, &account)

		return err == nil
	})
	require.Equal(t, name, provider, "the usage row's provider")
	require.Equal(t, accounts[at].Id, account, "the usage row's vendor account")
}
