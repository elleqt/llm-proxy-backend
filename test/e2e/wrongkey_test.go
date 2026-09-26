package e2e

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/boot"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	pgvendorcreds "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/vendorcreds"
	"github.com/stretchr/testify/require"
)

// TestBootStopsOnAnAccountTheKeyCannotOpen: a vendor account sealed under
// another LLMPROXY_CREDENTIALS_KEY stops the boot with an error that names the
// account and the variable, rather than a process serving without it.
func TestBootStopsOnAnAccountTheKeyCannotOpen(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}

	pool := pgtest.NewTestPool(t)

	const accountID = "claude-user@example.com.json"

	otherKey, err := credentials.NewSealer([]byte("another-credentials-key-of-at-least-32-bytes"))
	require.NoError(t, err)

	sealed, err := otherKey.Seal(accountID, []byte(`{"type":"claude","email":"user@example.com"}`))
	require.NoError(t, err)

	now := time.Now()
	require.NoError(t, pgvendorcreds.New(pool).Upsert(context.Background(), app.VendorCredential{
		ID: accountID, Provider: "claude", Sealed: sealed, CreatedAt: now, UpdatedAt: now,
	}), "seed the account")

	for k, v := range bootEnv(t, pool, freeAddr(t), freeAddr(t), freeAddr(t)) {
		t.Setenv(k, v)
	}

	var out bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err = boot.Run(ctx, boot.Options{Output: &out})
	require.Error(t, err, "boot with a key that cannot open the stored account; log:\n%s", out.String())
	require.Contains(t, err.Error(), accountID, "the error names the account")
	require.Contains(t, err.Error(), "LLMPROXY_CREDENTIALS_KEY", "the error names the variable")
	require.NotContains(t, err.Error(), hex.EncodeToString(sealed), "the error quotes the sealed row")
	require.NotContains(t, err.Error(), string(sealed), "the error quotes the sealed row")
}
