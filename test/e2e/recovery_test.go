package e2e

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestResetPasswordFromTheShellLetsALockedOutAdministratorBackIn is the recovery an
// operator runs beside the serving process, as `gateway reset-password <email>`
// with nothing but the database's address in its environment: the administrator,
// locked out by failed sign-ins, gets a temporary password on stdout that the
// running server accepts at once — no restart — for a restricted session that a
// password change lifts. The session held before is gone and the API key still
// works. The command refuses what it cannot do with exit status 1, a command it does
// not know with 2 and its usage, and a schema the server has not migrated.
//
//nolint:cyclop // One linear recovery scenario; each step depends on the state the previous one left.
func TestResetPasswordFromTheShellLetsALockedOutAdministratorBackIn(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}

	bin := filepath.Join(t.TempDir(), "gateway")
	if out, err := exec.CommandContext(t.Context(), "go", "build", "-o", bin, "github.com/elleqt/llm-proxy-backend/cmd/gateway").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	proc := startProcess(t, "", nil)
	// env is what the command's environment holds beyond the database's address.
	var env []string

	gateway := func(args ...string) (int, string, string) {
		t.Helper()

		var stdout, stderr bytes.Buffer

		cmd := exec.CommandContext(t.Context(), bin, args...)

		cmd.Env = append([]string{"LLMPROXY_DATABASE_URL=" + proc.pool.Config().ConnString()}, env...)
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()

		var exit *exec.ExitError
		if err != nil && !errors.As(err, &exit) {
			t.Fatalf("gateway %v: %v", args, err)
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
	if code != 0 || stderr != "" {
		t.Fatalf("reset-password = exit %d, stderr %q", code, stderr)
	}

	match := bootstrapBanner.FindStringSubmatch(stdout)
	if match == nil || !strings.Contains(stdout, "account:            "+proc.adminEmail+"\n") || !strings.Contains(stdout, "expires:") {
		t.Fatalf("reset-password printed no temporary password banner:\n%s", stdout)
	}

	t.Logf("reset-password stdout:\n%s", stdout)

	if code, body := proc.webCall(t, http.MethodGet, "/api/me", ""); code != http.StatusUnauthorized {
		t.Fatalf("GET /api/me with the session held before the reset = %d (%s), want 401", code, body)
	}

	proc.claimTemporaryPassword(t, match[1], "my new password after recovery")

	if code, body := send(t, http.MethodGet, proc.apiURL+"/v1/models", secret, ""); code != http.StatusOK {
		t.Fatalf("GET /v1/models with the API key issued before the reset = %d (%s), want 200", code, body)
	}

	if code, stdout, stderr := gateway("reset-password", "nobody@example.com"); code != 1 || stdout != "" ||
		!strings.Contains(stderr, "no account signs in with nobody@example.com") {
		t.Fatalf("unknown address = exit %d, stdout %q, stderr %q; want 1 and a clear message", code, stdout, stderr)
	}

	for _, args := range [][]string{{"help"}, {"reset-password"}, {"reset-password", "a@example.com", "b@example.com"}, {"reset-password", "--force", "a@example.com"}} {
		if code, stdout, stderr := gateway(args...); code != 2 || stdout != "" || !strings.Contains(stderr, "gateway reset-password [--unblock] <email>") {
			t.Fatalf("gateway %v = exit %d, stdout %q, stderr %q; want 2 and the usage", args, code, stdout, stderr)
		}
	}

	// With local sign-in off the password is still issued, and the operator is told
	// it cannot be used yet.
	env = []string{"LLMPROXY_LOCAL_LOGIN=false"}

	if code, stdout, stderr := gateway("reset-password", proc.adminEmail); code != 0 ||
		bootstrapBanner.FindStringSubmatch(stdout) == nil || !strings.Contains(stderr, "cannot be used until local sign-in is enabled") {
		t.Fatalf("local login off = exit %d, stdout %q, stderr %q; want the banner and a warning", code, stdout, stderr)
	}

	env = nil

	// A build newer than the schema: the server migrates as it starts, the command
	// does not.
	if _, err := proc.pool.Exec(context.Background(),
		`DELETE FROM goose_db_version WHERE version_id = (SELECT max(version_id) FROM goose_db_version)`); err != nil {
		t.Fatal(err)
	}

	if code, stdout, stderr := gateway("reset-password", proc.adminEmail); code != 1 || stdout != "" ||
		!strings.Contains(stderr, "not up to date") {
		t.Fatalf("unmigrated schema = exit %d, stdout %q, stderr %q; want 1 and a clear message", code, stdout, stderr)
	}
}
