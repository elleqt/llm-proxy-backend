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
func TestResetPasswordFromTheShellLetsALockedOutAdministratorBackIn(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}
	bin := filepath.Join(t.TempDir(), "gateway")
	if out, err := exec.Command("go", "build", "-o", bin, "github.com/elleqt/llm-proxy-backend/cmd/gateway").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	p := startProcess(t, "", nil)
	gateway := func(args ...string) (int, string, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		cmd := exec.Command(bin, args...)
		cmd.Env = []string{"LLMPROXY_DATABASE_URL=" + p.pool.Config().ConnString()}
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		var exit *exec.ExitError
		if err != nil && !errors.As(err, &exit) {
			t.Fatalf("gateway %v: %v", args, err)
		}
		return cmd.ProcessState.ExitCode(), stdout.String(), stderr.String()
	}

	p.signInAsBootstrapAdmin(t)
	secret := p.issueToken(t, "ops").Secret
	for range 5 {
		p.webJSON(t, http.MethodPost, "/api/auth/login",
			`{"email":"`+p.adminEmail+`","password":"a wrong guess"}`, http.StatusUnauthorized, nil)
	}
	p.webJSON(t, http.MethodPost, "/api/auth/login",
		`{"email":"`+p.adminEmail+`","password":"a password I chose myself"}`, http.StatusTooManyRequests, nil)

	code, stdout, stderr := gateway("reset-password", strings.ToUpper(p.adminEmail))
	if code != 0 || stderr != "" {
		t.Fatalf("reset-password = exit %d, stderr %q", code, stderr)
	}
	m := bootstrapBanner.FindStringSubmatch(stdout)
	if m == nil || !strings.Contains(stdout, "account:            "+p.adminEmail+"\n") || !strings.Contains(stdout, "expires:") {
		t.Fatalf("reset-password printed no temporary password banner:\n%s", stdout)
	}
	t.Logf("reset-password stdout:\n%s", stdout)

	if code, body := p.webCall(t, http.MethodGet, "/api/me", ""); code != http.StatusUnauthorized {
		t.Fatalf("GET /api/me with the session held before the reset = %d (%s), want 401", code, body)
	}
	p.claimTemporaryPassword(t, m[1], "my new password after recovery")
	if code, body := send(t, http.MethodGet, p.apiURL+"/v1/models", secret, ""); code != http.StatusOK {
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

	// A build newer than the schema: the server migrates as it starts, the command
	// does not.
	if _, err := p.pool.Exec(context.Background(),
		`DELETE FROM goose_db_version WHERE version_id = (SELECT max(version_id) FROM goose_db_version)`); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := gateway("reset-password", p.adminEmail); code != 1 || stdout != "" ||
		!strings.Contains(stderr, "not up to date") {
		t.Fatalf("unmigrated schema = exit %d, stdout %q, stderr %q; want 1 and a clear message", code, stdout, stderr)
	}
}
