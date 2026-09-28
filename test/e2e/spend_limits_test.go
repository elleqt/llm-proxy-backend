package e2e

import (
	"fmt"
	"math"
	"net/http"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
	"github.com/stretchr/testify/require"
)

// TestSpendLimitRefusesAndAdminResets is a spend limit as the whole process
// enforces it: an account with limits may not call a model without a price, nor
// see it listed; once the model the client asks for is priced, requests pass until
// the window's dollar is spent and are then refused, and the administrator's reset
// lets the next one through.
func TestSpendLimitRefusesAndAdminResets(t *testing.T) {
	if !inFreshProcess(t) {
		return
	}

	proc := startProcess(t, "", nil)
	proc.signInAsBootstrapAdmin(t)
	secret := proc.issueToken(t, "limits").Secret
	proc.setPolicy(t, proc.adminEmail, proc.a.policyName+":*")

	var me api.Me
	proc.webJSON(t, http.MethodGet, "/api/me", "", http.StatusOK, &me)
	limitsPath := "/api/admin/users/" + me.Id.String() + "/limits"

	// With limits, the model has no price yet: refused and not listed.
	proc.webJSON(t, http.MethodPut, limitsPath,
		`{"mode":"custom","limits":[{"windowMinutes":60,"amountUsd":1}]}`, http.StatusOK, nil)
	require.Equal(t, http.StatusForbidden, proc.chat(t, secret, proc.a.alias), "unpriced model with limits")
	require.False(t, proc.models(t, secret)[proc.a.alias], "unpriced model listed")

	// Priced on the name the client asks for; the vendor's upstream name stays
	// unpriced, so the sink must price by the alias. 3 + 4 tokens at $100000/M = $0.70.
	proc.webJSON(t, http.MethodPut, "/api/admin/prices",
		`[{"provider":"`+proc.a.policyName+`","model":"`+proc.a.alias+
			`","input":100000,"output":100000,"cacheRead":0,"cacheWrite":0}]`,
		http.StatusOK, nil)
	require.True(t, proc.models(t, secret)[proc.a.alias], "priced model listed")

	require.Equal(t, http.StatusOK, proc.chat(t, secret, proc.a.alias), "first request")
	awaitSpent(t, proc, limitsPath, 0.7)

	// The owner sees the share, never the dollars.
	var mine api.MySpendLimits
	proc.webJSON(t, http.MethodGet, "/api/me/limits", "", http.StatusOK, &mine)
	require.Len(t, mine.Windows, 1, "the cabinet's windows")
	require.Equal(t, 70, mine.Windows[0].SpentPercent, "the cabinet's share of $0.70 of $1")

	require.Equal(t, http.StatusOK, proc.chat(t, secret, proc.a.alias), "second request: $0.70 < $1")
	awaitSpent(t, proc, limitsPath, 1.4)
	require.Equal(t, http.StatusTooManyRequests, proc.chat(t, secret, proc.a.alias), "third request over the limit")

	proc.webJSON(t, http.MethodPost, limitsPath+"/reset", `{}`, http.StatusOK, nil)
	require.Equal(t, http.StatusOK, proc.chat(t, secret, proc.a.alias), "after the reset")
}

// awaitSpent waits until the usage sink has charged the account's one window up
// to want, read from the administrators' view of it at limitsPath: the charge
// lands after the response, so the next request must not race it.
func awaitSpent(t *testing.T, proc *process, limitsPath string, want float64) {
	t.Helper()
	eventually(t, fmt.Sprintf("the window has charged $%.2f", want), func() bool {
		var got api.SpendLimits
		proc.webJSON(t, http.MethodGet, limitsPath, "", http.StatusOK, &got)

		return len(got.Windows) == 1 && math.Abs(got.Windows[0].SpentUsd-want) < 1e-9
	})
}
