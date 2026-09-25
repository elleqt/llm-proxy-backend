package usage

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
	"github.com/elleqt/llm-proxy-backend/internal/infra/metrics"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/stretchr/testify/require"
)

// usageWireChild marks the fresh test process TestProxiedRequestWritesOneLedgerRow
// runs its body in.
const usageWireChild = "LLMPROXY_USAGE_WIRE_CHILD"

// TestProxiedRequestWritesOneLedgerRow drives one request through the real
// gateway to the wire-level fake vendor, authenticated by a real token in a
// real database, and checks the ledger gets exactly one row, attributed to the
// token's owner and the token, and the metrics name them by email and label.
//
// The body runs in a fresh process. Upstream delivers usage records through
// one process-global manager, and Service.Shutdown stops it for good
// (sdk/cliproxy/service_lifecycle.go usage.StopDefault; usage/manager.go Stop
// sets closed, and Publish then discards every record), so after any earlier
// test's gateway has stopped no record would ever reach this sink.
func TestProxiedRequestWritesOneLedgerRow(t *testing.T) {
	if os.Getenv(usageWireChild) == "" {
		rerunInFreshProcess(t)

		return
	}

	ctx := context.Background()
	pool := pgtest.NewTestPool(t)
	users, tokens := postgres.NewUserRepo(pool), postgres.NewTokenRepo(pool)

	alice := identity.User{
		ID: uuid.New(), Kind: identity.KindHuman, Email: "alice@example.com", DisplayName: "Alice",
		Role: identity.RoleUser, Status: identity.StatusActive, Policy: mustPolicy("fakevendor:*"),
		PolicySource: identity.PolicyLocal, CreatedAt: time.Now().UTC(),
	}
	require.NoError(t, users.Create(ctx, alice), "create user")

	tok, secret, err := credentials.Generate(alice.ID, "laptop")
	require.NoError(t, err, "generate token")

	require.NoError(t, tokens.Create(ctx, tok), "create token")

	meter := metrics.New(prometheus.NewRegistry())
	sink := New(postgres.NewUsageRepo(pool), tokens, users, &app.PriceTable{}, meter, wallClock{}, discardLog{})
	wire := startOnTheWireWith(t, &faketest.Vendor{
		Payload: []byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"m",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}`),
	}, gateway.Params{
		Config:      &cliproxyconfig.Config{},
		UsagePlugin: sink,
		Resolver:    app.NewTokenResolver(users, tokens),
	})

	status, body := wire.postMessages(t, secret)
	require.Equal(t, http.StatusOK, status, "POST /v1/messages (%s)", body)

	// Upstream publishes usage records asynchronously, through one queue
	// delivered in order (usage/manager.go). So once a later request's row is
	// written, every record the first request published has reached the sink
	// before it, a duplicate included.
	later := identity.User{
		ID: uuid.New(), Kind: identity.KindHuman, Email: "bob@example.com", DisplayName: "Bob",
		Role: identity.RoleUser, Status: identity.StatusActive, Policy: mustPolicy("fakevendor:*"),
		PolicySource: identity.PolicyLocal, CreatedAt: time.Now().UTC(),
	}
	require.NoError(t, users.Create(ctx, later), "create user")

	laterTok, laterSecret, err := credentials.Generate(later.ID, "desktop")
	require.NoError(t, err, "generate token")

	require.NoError(t, tokens.Create(ctx, laterTok), "create token")

	status, body = wire.postMessages(t, laterSecret)
	require.Equal(t, http.StatusOK, status, "later POST /v1/messages (%s)", body)

	awaitLedgerRow(t, pool, sink, later.ID, laterTok.ID)

	require.Equal(t, 1, ledgerRows(t, pool, sink, alice.ID, tok.ID), "ledger rows for the request")

	var (
		userID, tokenID        *uuid.UUID
		provider, model, alias string
		total                  int64
		failed                 bool
	)

	err = pool.QueryRow(ctx, `SELECT user_id, token_id, provider, model, alias, tokens_total, failed
		FROM usage_events WHERE user_id = $1`, alice.ID).Scan(&userID, &tokenID, &provider, &model, &alias, &total, &failed)
	require.NoError(t, err, "read row")

	require.NotNil(t, userID, "row's user")
	require.Equal(t, alice.ID, *userID, "row's user")
	require.NotNil(t, tokenID, "row's token")
	require.Equal(t, tok.ID, *tokenID, "row's token")
	// The vendor is the openai-compatibility entry "fakevendor": upstream keys it
	// openai-compatible-fakevendor, policies name it fakevendor.
	require.Equal(t, "fakevendor", provider, "row provider")
	require.Equal(t, wire.model, model, "row model")
	require.Equal(t, wire.alias, alias, "row alias")
	require.Equal(t, int64(7), total, "row tokens_total, want the vendor's 7 tokens")
	require.False(t, failed, "row failed")

	stamped, err := tokens.ByID(ctx, tok.ID)
	require.NoError(t, err, "token")
	require.NotNil(t, stamped.LastUsedAt, "the token's last use was not stamped")

	require.Contains(t, scrape(t, meter), `user="alice@example.com"} 1`, "no requests_total series for alice")
}

// rerunInFreshProcess runs the calling test alone in a fresh test process,
// with usageWireChild set, and fails unless it passes there.
func rerunInFreshProcess(t *testing.T) {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v")

	cmd.Env = append(os.Environ(), usageWireChild+"=1")

	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "in a fresh process:\n%s", out)
	require.Contains(t, string(out), "--- PASS: "+t.Name(), "in a fresh process")
}

// ledgerRows waits until sink has processed every record handed to it, then
// counts the ledger rows attributed to userID or tokenID.
func ledgerRows(t *testing.T, pool *pgxpool.Pool, sink *Sink, userID, tokenID uuid.UUID) int {
	t.Helper()
	flushed(t, sink)

	var count int

	err := pool.QueryRow(t.Context(), `SELECT count(*) FROM usage_events WHERE user_id = $1 OR token_id = $2`,
		userID, tokenID).Scan(&count)
	require.NoError(t, err, "count")

	return count
}

// awaitLedgerRow waits up to 10s for a ledger row attributed to userID or
// tokenID to appear.
func awaitLedgerRow(t *testing.T, pool *pgxpool.Pool, sink *Sink, userID, tokenID uuid.UUID) {
	t.Helper()

	for deadline := time.Now().Add(10 * time.Second); ledgerRows(t, pool, sink, userID, tokenID) == 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			require.Fail(t, "no ledger row for the later request")
		}
	}
}
