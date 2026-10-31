package usage

import (
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
	"github.com/elleqt/llm-proxy-backend/internal/infra/metrics"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	pgtokens "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/tokens"
	pgusage "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/usage"
	pgusers "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/users"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"github.com/stretchr/testify/require"
)

func TestCompatFallbackAttributesSuccessfulUsage(t *testing.T) {
	if os.Getenv(usageWireChild) == "" {
		rerunInFreshProcess(t)

		return
	}

	pool := pgtest.NewTestPool(t)
	users, tokens := pgusers.New(pool), pgtokens.New(pool)
	user := identity.User{
		ID: uuid.New(), Kind: identity.KindHuman, Email: "fallback@example.com", DisplayName: "Fallback",
		Role: identity.RoleUser, Status: identity.StatusActive, Policy: mustPolicy("primary:*", "paidprovider:*"),
		PolicySource: identity.PolicyLocal, CreatedAt: time.Now().UTC(),
	}
	require.NoError(t, users.Create(t.Context(), user))
	token, secret, err := credentials.Generate(user.ID, "fallback")
	require.NoError(t, err)
	require.NoError(t, tokens.Create(t.Context(), token))

	catalog, err := gateway.NewCatalog()
	require.NoError(t, err)

	meter := metrics.New(prometheus.NewRegistry())
	sink := New(pgusage.New(pool), tokens, users, &app.PriceTable{}, catalog, meter, wallClock{}, discardLog{})
	primary := &faketest.Vendor{FailStatus: http.StatusServiceUnavailable, FailBody: []byte(`{"error":{"message":"unavailable"}}`)}
	fallback := &faketest.Vendor{Payload: []byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"fallback"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}`)}
	primaryServer, fallbackServer := faketest.Start(t, primary), faketest.Start(t, fallback)

	const alias = "fallback-ledger-alias"

	preferred := faketest.Compatibility("primary", primaryServer.URL, vendorKey, "primary-model", alias)
	preferred.Priority = 1
	secondary := faketest.Compatibility("paidprovider", fallbackServer.URL, vendorKey, "paid-model", alias)
	srv := startWith(t, gateway.Params{
		Config:      &cliproxyconfig.Config{OpenAICompatibility: []cliproxyconfig.OpenAICompatibility{preferred, secondary}},
		CoreAuth:    coreauth.NewManager(nil, nil, nil),
		UsagePlugin: sink, Resolver: app.NewTokenResolver(users, tokens),
	})
	awaitProviders(t, catalog, alias, []string{"paidprovider", "primary"})
	wire := &onTheWire{baseURL: srv.baseURL, alias: alias}
	status, body := wire.postMessages(t, secret)
	require.Equal(t, http.StatusOK, status, "%s", body)
	require.Contains(t, string(body), "fallback")
	require.Len(t, primary.Requests(), 1)
	require.Len(t, fallback.Requests(), 1)

	// The later user's row is a barrier for the process-global ordered usage queue.
	later := user
	later.ID, later.Email = uuid.New(), "barrier@example.com"
	require.NoError(t, users.Create(t.Context(), later))
	laterToken, laterSecret, err := credentials.Generate(later.ID, "barrier")
	require.NoError(t, err)
	require.NoError(t, tokens.Create(t.Context(), laterToken))
	status, body = wire.postMessages(t, laterSecret)
	require.Equal(t, http.StatusOK, status, "%s", body)
	awaitLedgerRow(t, pool, sink, later.ID, laterToken.ID)

	var (
		provider, accountID, model, publicAlias string
		total                                   int64
	)

	err = pool.QueryRow(t.Context(), `SELECT provider, vendor_account_id, model, alias, tokens_total
		FROM usage_events WHERE user_id = $1 AND NOT failed`, user.ID).
		Scan(&provider, &accountID, &model, &publicAlias, &total)
	require.NoError(t, err)
	require.Equal(t, "paidprovider", provider)
	require.Equal(t, "paid-model", model)
	require.Equal(t, alias, publicAlias)
	require.Equal(t, int64(7), total)

	accounts := make([]string, 0, 1)

	for _, account := range srv.gateway.Accounts() {
		if account.Label == "paidprovider" {
			accounts = append(accounts, account.ID)
		}
	}

	require.Equal(t, []string{accountID}, accounts)
}
