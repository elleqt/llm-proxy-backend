package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
)

// TestEndToEnd is the path a person takes through the process as cmd/gateway runs
// it: the bootstrap administrator signs in with the one-time password, is forced to
// change it, issues an API token in the cabinet, and uses it on the proxied API —
// where their policy decides which vendor's model they may call and see — then
// revokes it, and finds what they spent in the cabinet.
//
//nolint:cyclop // One linear user journey; each step depends on the state the previous one left.
func TestEndToEnd(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}

	proc := startProcess(t, "", nil)
	proc.signInAsBootstrapAdmin(t)

	// The administration API is served on the same listener, over the real stores:
	// the administrator finds their own account in the user list.
	var me api.Me
	proc.webJSON(t, http.MethodGet, "/api/me", "", http.StatusOK, &me)

	var accounts []api.AdminUser
	proc.webJSON(t, http.MethodGet, "/api/admin/users", "", http.StatusOK, &accounts)

	if len(accounts) != 1 || accounts[0].Id != me.Id || accounts[0].Role != api.Role("admin") {
		t.Fatalf("admin user list = %+v, want the bootstrap administrator", accounts)
	}

	// A token, shown once; the list shows its prefix and never the secret.
	issued := proc.issueToken(t, "laptop")
	secret := issued.Secret

	_, list := proc.webCall(t, http.MethodGet, "/api/me/tokens", "")
	if strings.Contains(string(list), secret) || !strings.Contains(string(list), issued.Token.Prefix) {
		t.Fatalf("token list %s: want the prefix %q and never the secret", list, issued.Token.Prefix)
	}

	// Both vendors registered: with a policy granting both, both are listed.
	proc.setPolicy(t, proc.adminEmail, proc.a.policyName+":*", proc.b.policyName+":*")
	eventually(t, "both vendors' models are listed", func() bool {
		m := proc.models(t, secret)

		return m[proc.a.alias] && m[proc.b.alias]
	})

	// The policy editor reads the catalogue the gate routes by: the preview of a
	// vendor-A-only policy covers A's model and not B's.
	var preview api.PolicyPreview
	proc.webJSON(t, http.MethodPost, "/api/admin/policy/preview", `{"rules":["`+proc.a.policyName+`:*"]}`, http.StatusOK, &preview)

	if len(preview.Covered) != 1 || preview.Covered[0].Provider != proc.a.policyName || preview.Covered[0].Model != proc.a.alias {
		t.Fatalf("preview = %+v, want only %s's %s", preview, proc.a.policyName, proc.a.alias)
	}

	var vendorAccounts []api.ProviderAccount
	proc.webJSON(t, http.MethodGet, "/api/admin/providers", "", http.StatusOK, &vendorAccounts)

	// Narrowed to vendor A: A is served and listed, B is refused and hidden.
	proc.setPolicy(t, proc.adminEmail, proc.a.policyName+":*")

	if code := proc.chat(t, secret, proc.a.alias); code != http.StatusOK {
		t.Fatalf("allowed model: status %d, want 200", code)
	}

	if code := proc.chat(t, secret, proc.b.alias); code != http.StatusForbidden {
		t.Fatalf("model of a vendor the policy does not grant: status %d, want 403", code)
	}

	if m := proc.models(t, secret); !m[proc.a.alias] || m[proc.b.alias] {
		t.Fatalf("/v1/models = %v, want %s listed and %s hidden", m, proc.a.alias, proc.b.alias)
	}

	// Widening the policy applies to the same token at once.
	proc.setPolicy(t, proc.adminEmail, proc.a.policyName+":*", proc.b.policyName+":*")

	if code := proc.chat(t, secret, proc.b.alias); code != http.StatusOK {
		t.Fatalf("after widening: status %d, want 200 with the same token", code)
	}

	// Revocation from the cabinet is immediate.
	proc.webJSON(t, http.MethodDelete, "/api/me/tokens/"+issued.Token.Id.String(), "", http.StatusNoContent, nil)

	if code := proc.chat(t, secret, proc.a.alias); code != http.StatusUnauthorized {
		t.Fatalf("after revocation: status %d, want 401", code)
	}

	// Two requests were served: the usage sink writes them to the ledger the
	// cabinet reads.
	var usage api.Usage

	eventually(t, "the cabinet shows both served requests", func() bool {
		proc.webJSON(t, http.MethodGet, "/api/me/usage", "", http.StatusOK, &usage)

		return usage.Totals.Requests >= 2
	})

	if usage.Totals.Requests != 2 || usage.Totals.TokensTotal != 14 {
		t.Fatalf("usage totals = %+v, want the 2 served requests and their 14 tokens", usage.Totals)
	}

	// Signing out ends the session on the server, not only in this browser: the old
	// cookie, presented again as a thief holding a copy would, no longer authenticates.
	old := proc.sessionCookie(t)
	proc.webJSON(t, http.MethodPost, "/api/auth/logout", "", http.StatusNoContent, nil)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proc.webURL+"/api/me", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	req.AddCookie(old)

	resp, err := http.DefaultClient.Do(req) // no jar: exactly the cookie given
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = resp.Body.Close() }()

	var gone api.Error
	if err := json.NewDecoder(resp.Body).Decode(&gone); err != nil ||
		resp.StatusCode != http.StatusUnauthorized || gone.Code != "unauthenticated" {
		t.Fatalf("the signed-out session's cookie: status %d, code %q (%v); want 401 unauthenticated",
			resp.StatusCode, gone.Code, err)
	}

	// The bootstrap password was shown once, in its banner, and the token secret
	// never reached the process's output.
	out := proc.out.String()
	if n := strings.Count(out, proc.adminPassword); n != 1 {
		t.Fatalf("the bootstrap password appears %d times in the process output, want once", n)
	}

	if strings.Contains(out, secret) {
		t.Fatal("the token secret reached the process output")
	}
}
