package e2e

import (
	"bytes"
	"context"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestResetPasswordFromTheShellLetsALockedOutAdministratorBackIn is the recovery an
// operator runs beside the serving process, as `gateway reset-password <email>`
// with nothing but the database's address in its environment: the administrator,
// locked out by failed sign-ins, gets a temporary password on stdout that the
// running server accepts at once — no restart — for a restricted session that a
// password change lifts. The session held before is gone and the API key still
// works. The command refuses what it cannot do with exit status 1, a command it does
// not know with 2 and its usage, and a schema the server has not migrated.
func TestResetPasswordFromTheShellLetsALockedOutAdministratorBackIn(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}

	bin := filepath.Join(t.TempDir(), "gateway")
	out, err := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "github.com/elleqt/llm-proxy-backend/cmd/gateway").CombinedOutput()
	require.NoError(t, err, "go build:\n%s", out)

	proc := startProcess(t, "", nil)
	// env is what the command's environment holds beyond the database's address.
	var env []string

	gateway := func(args ...string) (int, string, string) {
		t.Helper()

		var stdout, stderr bytes.Buffer

		cmd := exec.CommandContext(t.Context(), bin, args...)

		cmd.Env = append([]string{"LLMPROXY_DATABASE_URL=" + proc.pool.Config().ConnString()}, env...)
		cmd.Stdout, cmd.Stderr = &stdout, &stderr

		if err := cmd.Run(); err != nil {
			var exit *exec.ExitError
			require.ErrorAs(t, err, &exit, "gateway %v", args)
		}

		return cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()
	}

	proc.signInAsBootstrapAdmin(t)

	secret := proc.issueToken(t, "ops").Secret
	for range 5 {
		proc.webJSON(t, http.MethodPost, "/api/auth/login",
			`{"email":"`+proc.adminEmail+`","password":"a wrong guess"}`, http.StatusUnauthorized, nil)
	}

	proc.webJSON(t, http.MethodPost, "/api/auth/login",
		`{"email":"`+proc.adminEmail+`","password":"a password I chose myself"}`, http.StatusTooManyRequests, nil)

	code, stdout, stderr := gateway("reset-password", strings.ToUpper(proc.adminEmail))
	require.Zero(t, code, "reset-password exit status (stderr %q)", stderr)
	require.Empty(t, stderr, "reset-password stderr")

	match := bootstrapBanner.FindStringSubmatch(stdout)
	require.NotNil(t, match, "reset-password printed no temporary password banner:\n%s", stdout)
	require.Contains(t, stdout, "account:            "+proc.adminEmail+"\n", "reset-password banner")
	require.Contains(t, stdout, "expires:", "reset-password banner")

	t.Logf("reset-password stdout:\n%s", stdout)

	code, body := proc.webCall(t, http.MethodGet, "/api/me", "")
	require.Equal(t, http.StatusUnauthorized, code, "GET /api/me with the session held before the reset (%s)", body)

	proc.claimTemporaryPassword(t, match[1], "my new password after recovery")

	code, body = send(t, http.MethodGet, proc.apiURL+"/v1/models", secret, "")
	require.Equal(t, http.StatusOK, code, "GET /v1/models with the API key issued before the reset (%s)", body)

	code, stdout, stderr = gateway("reset-password", "nobody@example.com")
	require.Equal(t, 1, code, "unknown address: exit status (stderr %q)", stderr)
	require.Empty(t, stdout, "unknown address: stdout")
	require.Contains(t, stderr, "no account signs in with nobody@example.com", "unknown address: want a clear message")

	for _, args := range [][]string{{"help"}, {"reset-password"}, {"reset-password", "a@example.com", "b@example.com"}, {"reset-password", "--force", "a@example.com"}} {
		code, stdout, stderr := gateway(args...)
		require.Equal(t, 2, code, "gateway %v: exit status (stderr %q)", args, stderr)
		require.Empty(t, stdout, "gateway %v: stdout", args)
		require.Contains(t, stderr, "gateway reset-password [--unblock] <email>", "gateway %v: want the usage", args)
	}

	// With local sign-in off the password is still issued, and the operator is told
	// it cannot be used yet.
	env = []string{"LLMPROXY_LOCAL_LOGIN=false"}

	code, stdout, stderr = gateway("reset-password", proc.adminEmail)
	require.Zero(t, code, "local login off: exit status (stderr %q)", stderr)
	require.NotNil(t, bootstrapBanner.FindStringSubmatch(stdout), "local login off: no banner in stdout %q", stdout)
	require.Contains(t, stderr, "cannot be used until local sign-in is enabled", "local login off: want a warning")

	env = nil

	// A build newer than the schema: the server migrates as it starts, the command
	// does not.
	_, err = proc.pool.Exec(context.Background(),
		`DELETE FROM goose_db_version WHERE version_id = (SELECT max(version_id) FROM goose_db_version)`)
	require.NoError(t, err)

	code, stdout, stderr = gateway("reset-password", proc.adminEmail)
	require.Equal(t, 1, code, "unmigrated schema: exit status (stderr %q)", stderr)
	require.Empty(t, stdout, "unmigrated schema: stdout")
	require.Contains(t, stderr, "not up to date", "unmigrated schema: want a clear message")
}
