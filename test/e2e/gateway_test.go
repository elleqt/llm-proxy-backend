package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
	"github.com/stretchr/testify/require"
)

// TestEndToEnd is the path a person takes through the process as cmd/gateway runs
// it: the bootstrap administrator signs in with the one-time password, is forced to
// change it, issues an API token in the cabinet, and uses it on the proxied API —
// where their policy decides which vendor's model they may call and see — then
// revokes it, and finds what they spent in the cabinet.
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

	require.Len(t, accounts, 1, "admin user list: want the bootstrap administrator")
	require.Equal(t, me.Id, accounts[0].Id, "admin user list: want the bootstrap administrator")
	require.Equal(t, api.Role("admin"), accounts[0].Role, "admin user list: want the bootstrap administrator")

	// A token, shown once; the list shows its prefix and never the secret.
	issued := proc.issueToken(t, "laptop")
	secret := issued.Secret

	_, list := proc.webCall(t, http.MethodGet, "/api/me/tokens", "")
	require.NotContains(t, string(list), secret, "the token list shows the secret")
	require.Contains(t, string(list), issued.Token.Prefix, "the token list lacks the prefix")

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

	require.Len(t, preview.Covered, 1, "preview: want only %s's %s", proc.a.policyName, proc.a.alias)
	require.Equal(t, proc.a.policyName, preview.Covered[0].Provider, "preview provider")
	require.Equal(t, proc.a.alias, preview.Covered[0].Model, "preview model")

	var vendorAccounts []api.ProviderAccount
	proc.webJSON(t, http.MethodGet, "/api/admin/providers", "", http.StatusOK, &vendorAccounts)

	// Narrowed to vendor A: A is served and listed, B is refused and hidden.
	proc.setPolicy(t, proc.adminEmail, proc.a.policyName+":*")

	require.Equal(t, http.StatusOK, proc.chat(t, secret, proc.a.alias), "allowed model")
	require.Equal(t, http.StatusForbidden, proc.chat(t, secret, proc.b.alias), "model of a vendor the policy does not grant")

	listed := proc.models(t, secret)
	require.True(t, listed[proc.a.alias], "/v1/models = %v, want %s listed", listed, proc.a.alias)
	require.False(t, listed[proc.b.alias], "/v1/models = %v, want %s hidden", listed, proc.b.alias)

	// Widening the policy applies to the same token at once.
	proc.setPolicy(t, proc.adminEmail, proc.a.policyName+":*", proc.b.policyName+":*")

	require.Equal(t, http.StatusOK, proc.chat(t, secret, proc.b.alias), "after widening, with the same token")

	// Revocation from the cabinet is immediate.
	proc.webJSON(t, http.MethodDelete, "/api/me/tokens/"+issued.Token.Id.String(), "", http.StatusNoContent, nil)

	require.Equal(t, http.StatusUnauthorized, proc.chat(t, secret, proc.a.alias), "after revocation")

	// Two requests were served: the usage sink writes them to the ledger the
	// cabinet reads.
	var usage api.Usage

	eventually(t, "the cabinet shows both served requests", func() bool {
		proc.webJSON(t, http.MethodGet, "/api/me/usage", "", http.StatusOK, &usage)

		return usage.Totals.Requests >= 2
	})

	require.Equal(t, 2, usage.Totals.Requests, "usage totals: want the 2 served requests")
	require.Equal(t, 14, usage.Totals.TokensTotal, "usage totals: want the served requests' 14 tokens")

	// Signing out ends the session on the server, not only in this browser: the old
	// cookie, presented again as a thief holding a copy would, no longer authenticates.
	old := proc.sessionCookie(t)
	proc.webJSON(t, http.MethodPost, "/api/auth/logout", "", http.StatusNoContent, nil)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, proc.webURL+"/api/me", http.NoBody)
	require.NoError(t, err)

	req.AddCookie(old)

	resp, err := http.DefaultClient.Do(req) // no jar: exactly the cookie given
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	var gone api.Error

	decodeErr := json.NewDecoder(resp.Body).Decode(&gone)
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "the signed-out session's cookie")
	require.NoError(t, decodeErr, "the signed-out session's cookie: decode")
	require.Equal(t, "unauthenticated", gone.Code, "the signed-out session's cookie")

	// The bootstrap password was shown once, in its banner, and the token secret
	// never reached the process's output.
	out := proc.out.String()
	require.Equal(t, 1, strings.Count(out, proc.adminPassword), "times the bootstrap password appears in the process output")
	require.NotContains(t, out, secret, "the token secret reached the process output")
}
