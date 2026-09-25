package gateway

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
	"github.com/elleqt/llm-proxy-backend/internal/infra/metrics"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
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
	if err := users.Create(ctx, alice); err != nil {
		t.Fatalf("create user: %v", err)
	}

	tok, secret, err := credentials.Generate(alice.ID, "laptop")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	if err := tokens.Create(ctx, tok); err != nil {
		t.Fatalf("create token: %v", err)
	}

	meter := metrics.New(prometheus.NewRegistry())
	sink := NewUsageSink(postgres.NewUsageRepo(pool), tokens, users, &app.PriceTable{}, meter, wallClock{}, discardLog{})
	wire := startOnTheWireWith(t, &faketest.Vendor{
		Payload: []byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"m",` +
			`"choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],` +
			`"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}`),
	}, Params{
		Config:      &cliproxyconfig.Config{},
		UsagePlugin: sink,
		Resolver:    app.NewTokenResolver(users, tokens),
	})

	if status, _, body := wire.postMessages(t, secret, false); status != http.StatusOK {
		t.Fatalf("POST /v1/messages = %d (%s), want 200", status, body)
	}

	// Upstream publishes usage records asynchronously, through one queue
	// delivered in order (usage/manager.go). So once a later request's row is
	// written, every record the first request published has reached the sink
	// before it, a duplicate included.
	later := identity.User{
		ID: uuid.New(), Kind: identity.KindHuman, Email: "bob@example.com", DisplayName: "Bob",
		Role: identity.RoleUser, Status: identity.StatusActive, Policy: mustPolicy("fakevendor:*"),
		PolicySource: identity.PolicyLocal, CreatedAt: time.Now().UTC(),
	}
	if err := users.Create(ctx, later); err != nil {
		t.Fatalf("create user: %v", err)
	}

	laterTok, laterSecret, err := credentials.Generate(later.ID, "desktop")
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	if err := tokens.Create(ctx, laterTok); err != nil {
		t.Fatalf("create token: %v", err)
	}

	if status, _, body := wire.postMessages(t, laterSecret, false); status != http.StatusOK {
		t.Fatalf("later POST /v1/messages = %d (%s), want 200", status, body)
	}

	awaitLedgerRow(t, pool, sink, later.ID, laterTok.ID)

	if n := ledgerRows(t, pool, sink, alice.ID, tok.ID); n != 1 {
		t.Fatalf("ledger holds %d rows for the request, want exactly 1", n)
	}

	var (
		userID, tokenID        *uuid.UUID
		provider, model, alias string
		total                  int64
		failed                 bool
	)
	if err := pool.QueryRow(ctx, `SELECT user_id, token_id, provider, model, alias, tokens_total, failed
		FROM usage_events WHERE user_id = $1`, alice.ID).Scan(&userID, &tokenID, &provider, &model, &alias, &total, &failed); err != nil {
		t.Fatalf("read row: %v", err)
	}

	if userID == nil || *userID != alice.ID || tokenID == nil || *tokenID != tok.ID {
		t.Fatalf("row attributed to user %v token %v, want %s / %s", userID, tokenID, alice.ID, tok.ID)
	}
	// The vendor is the openai-compatibility entry "fakevendor": upstream keys it
	// openai-compatible-fakevendor, policies name it fakevendor.
	if provider != "fakevendor" || model != wire.model || alias != wire.alias || total != 7 || failed {
		t.Fatalf("row provider=%q model=%q alias=%q tokens_total=%d failed=%t; want fakevendor, %q, %q, the vendor's 7 tokens and success",
			provider, model, alias, total, failed, wire.model, wire.alias)
	}

	stamped, err := tokens.ByID(ctx, tok.ID)
	if err != nil {
		t.Fatalf("token: %v", err)
	}

	if stamped.LastUsedAt == nil {
		t.Fatal("the token's last use was not stamped")
	}

	body := scrape(t, meter)
	if !strings.Contains(body, `user="alice@example.com"} 1`) {
		t.Fatalf("no requests_total series for alice:\n%s", body)
	}
}

// rerunInFreshProcess runs the calling test alone in a fresh test process,
// with usageWireChild set, and fails unless it passes there.
func rerunInFreshProcess(t *testing.T) {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^"+t.Name()+"$", "-test.count=1", "-test.v")

	cmd.Env = append(os.Environ(), usageWireChild+"=1")

	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: "+t.Name()) {
		t.Fatalf("in a fresh process: %v\n%s", err, out)
	}
}

// ledgerRows waits until sink has processed every record handed to it, then
// counts the ledger rows attributed to userID or tokenID.
func ledgerRows(t *testing.T, pool *pgxpool.Pool, sink *UsageSink, userID, tokenID uuid.UUID) int {
	t.Helper()
	flushed(t, sink)

	var count int
	if err := pool.QueryRow(t.Context(), `SELECT count(*) FROM usage_events WHERE user_id = $1 OR token_id = $2`,
		userID, tokenID).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}

	return count
}

// awaitLedgerRow waits up to 10s for a ledger row attributed to userID or
// tokenID to appear.
func awaitLedgerRow(t *testing.T, pool *pgxpool.Pool, sink *UsageSink, userID, tokenID uuid.UUID) {
	t.Helper()

	for deadline := time.Now().Add(10 * time.Second); ledgerRows(t, pool, sink, userID, tokenID) == 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no ledger row for the later request")
		}
	}
}
