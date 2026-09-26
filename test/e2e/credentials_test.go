package e2e

// COMPAT(credentials-import): the first boot below relies on the one-shot import of the credential files; next release
// delete this test or seed the account through the credential store instead; remove next release (RELEASING.md).

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// The restart test's parent owns the database and the auth directory and
// hands them, and which boot it is, to each child through these variables.
const (
	restartDatabaseEnv = "LLMPROXY_E2E_DATABASE_URL"
	restartAuthDirEnv  = "LLMPROXY_E2E_AUTH_DIR"
	restartBootEnv     = "LLMPROXY_E2E_BOOT"
)

// importedAccountID is the account the credential file holds: the id the
// previous release's file store gave it, its file name.
const importedAccountID = "claude-user@example.com.json"

// restartPassword is the administrator's password from the first boot on.
const restartPassword = "a password for both boots"

// TestAVendorAccountOutlivesItsCredentialFile: a Claude credential file in the
// auth directory before the first boot is an account the admin API lists.
// Stopped, the file removed and started again on the same database, the
// process still lists it: the file was imported once, and the account lives
// in the database, loaded through the credential store.
func TestAVendorAccountOutlivesItsCredentialFile(t *testing.T) {
	if !isChild() {
		t.Parallel()

		pool := pgtest.NewTestPool(t)
		authDir := t.TempDir()
		file := filepath.Join(authDir, importedAccountID)
		require.NoError(t, os.WriteFile(file, claudeCredential(t), 0o600))

		boot := func(which string) {
			out, err := runChildWith(t, restartDatabaseEnv+"="+pool.Config().ConnString(),
				restartAuthDirEnv+"="+authDir, restartBootEnv+"="+which)
			require.NoError(t, err, "the %s boot:\n%s", which, out)
			require.Contains(t, string(out), "--- PASS: "+t.Name(), "the %s boot", which)
		}

		boot("first")
		require.NoError(t, os.Remove(file), "empty the auth directory")
		boot("second")

		return
	}

	pool, err := pgxpool.New(context.Background(), os.Getenv(restartDatabaseEnv))
	require.NoError(t, err, "pool")
	t.Cleanup(pool.Close)

	proc := startProcessOn(t, pool, "", map[string]string{"LLMPROXY_AUTH_DIR": os.Getenv(restartAuthDirEnv)})

	if os.Getenv(restartBootEnv) == "first" {
		proc.readBootstrapPassword(t)
		proc.claimTemporaryPassword(t, proc.adminPassword, restartPassword)
	} else {
		// The administrator exists since the first boot: no bootstrap this time.
		var me api.Me
		proc.webJSON(t, http.MethodPost, "/api/auth/login",
			`{"email":"`+proc.adminEmail+`","password":"`+restartPassword+`"}`, http.StatusOK, &me)
		require.False(t, me.Restricted, "the administrator's session is restricted")
	}

	var accounts []api.ProviderAccount
	proc.webJSON(t, http.MethodGet, "/api/admin/providers", "", http.StatusOK, &accounts)

	at := slices.IndexFunc(accounts, func(a api.ProviderAccount) bool { return a.Id == importedAccountID })
	require.NotEqual(t, -1, at, "the admin API lists %+v, without the account of the credential file", accounts)
	require.NotNil(t, accounts[at].Email, "the account's email")
	require.Equal(t, "user@example.com", *accounts[at].Email)
}

// claudeCredential is a Claude credential file as the previous release wrote
// it. The token is valid for two days, so nothing tries to refresh it.
func claudeCredential(t *testing.T) []byte {
	t.Helper()

	data, err := json.Marshal(map[string]any{
		"type":          "claude",
		"email":         "user@example.com",
		"id_token":      "",
		"access_token":  "fake-claude-access-token",
		"refresh_token": "fake-claude-refresh-token",
		"last_refresh":  time.Now().UTC().Format(time.RFC3339),
		"expired":       time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339),
		"disabled":      false,
	})
	require.NoError(t, err)

	return data
}
