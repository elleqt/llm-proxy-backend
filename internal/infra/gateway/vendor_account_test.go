package gateway

import (
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/stretchr/testify/require"
)

// An account loaded from its file at boot has no in-process refresh yet; the
// card must still show when the credential was last refreshed, from the file.
func TestAccountCardShowsTheStoredLastRefresh(t *testing.T) {
	inProcess := time.Date(2026, 9, 23, 7, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		auth coreauth.Auth
		want time.Time
	}{
		{
			name: "loaded from file, never refreshed in this process",
			auth: coreauth.Auth{Metadata: map[string]any{"last_refresh": "2026-09-23T10:00:21+08:00"}},
			want: time.Date(2026, 9, 23, 2, 0, 21, 0, time.UTC),
		},
		{
			name: "refreshed in this process wins over the file",
			auth: coreauth.Auth{LastRefreshedAt: inProcess, Metadata: map[string]any{"last_refresh": "2026-09-22T10:00:00Z"}},
			want: inProcess,
		},
		{
			name: "no record anywhere",
			auth: coreauth.Auth{Metadata: map[string]any{}},
		},
		{
			name: "unreadable record",
			auth: coreauth.Auth{Metadata: map[string]any{"last_refresh": "yesterday"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := VendorAccount(&tc.auth).LastRefreshedAt
			require.True(t, got.Equal(tc.want), "LastRefreshedAt = %v, want %v", got, tc.want)
		})
	}
}
