package gateway

import (
	"encoding/json"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/stretchr/testify/require"
)

// restoredPriorityAccount uses the actual credential loader, not a service fake.
func restoredPriorityAccount(t *testing.T, provider, id string, priority any) *coreauth.Auth {
	t.Helper()

	metadata := map[string]any{"type": provider, "access_token": "synthetic-token"}
	if priority != nil {
		metadata["priority"] = priority
	}

	if provider == OpenAICompatibilityKey {
		metadata[compatMetaName] = id
	}

	plaintext, err := json.Marshal(metadata)
	require.NoError(t, err)
	auth, err := authFromRow(app.VendorCredential{ID: id}, plaintext)
	require.NoError(t, err)

	return auth
}

func TestStoredAccountPriorityControlsSelection(t *testing.T) {
	for _, provider := range []string{"claude", "codex", OpenAICompatibilityKey} {
		t.Run(provider, func(t *testing.T) {
			for _, testcase := range []struct {
				name          string
				first         any
				second        any
				wantID        string
				firstPriority int32
			}{
				{name: "reserve", first: "-1", second: nil, wantID: "z-second", firstPriority: -1},
				{name: "preferred string", first: nil, second: "7", wantID: "z-second"},
				{name: "preferred number", first: nil, second: 7, wantID: "z-second"},
				{name: "missing is neutral", first: nil, second: nil, wantID: "a-first"},
				{name: "invalid is neutral", first: "invalid", second: nil, wantID: "a-first"},
				{name: "fractional is neutral", first: 1.5, second: nil, wantID: "a-first"},
				{name: "out of range is neutral", first: 1e30, second: nil, wantID: "a-first"},
			} {
				t.Run(testcase.name, func(t *testing.T) {
					first := restoredPriorityAccount(t, provider, "a-first", testcase.first)
					second := restoredPriorityAccount(t, provider, "z-second", testcase.second)
					selected, err := (&coreauth.RoundRobinSelector{}).Pick(t.Context(), provider, "priority-probe-model", cliproxyexecutor.Options{}, []*coreauth.Auth{first, second})
					require.NoError(t, err)
					require.Equal(t, testcase.wantID, selected.ID)
					require.Equal(t, testcase.firstPriority, VendorAccount(first).Priority)
				})
			}
		})
	}
}
