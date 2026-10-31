package gateway

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// priorityGrant represents a synthetic subscription, never a duplicated live grant.
func priorityGrant(t *testing.T, provider string) *coreauth.Auth {
	t.Helper()
	id := provider + "-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")) + ".json"
	t.Cleanup(func() { cliproxy.GlobalModelRegistry().UnregisterClient(id) })

	return &coreauth.Auth{
		ID: id, FileName: id, Provider: provider, Status: coreauth.StatusActive,
		Metadata: map[string]any{
			"type": provider, "email": "priority@example.com", "access_token": "synthetic-access-token",
			"expired": time.Now().Add(48 * time.Hour).Format(time.RFC3339),
		},
	}
}

func TestManagedAccountPrioritySurvivesReloadAndReauthentication(t *testing.T) {
	for _, provider := range []string{"claude", "codex"} {
		t.Run(provider, func(t *testing.T) {
			pool := pgtest.NewTestPool(t)
			first := startCompat(t, pool)
			grant := priorityGrant(t, provider)
			_, err := first.gateway.AddAccount(t.Context(), grant)
			require.NoError(t, err)
			require.NoError(t, first.gateway.SetAccountProxy(t.Context(), grant.ID, app.ProxyChoice{Mode: app.ProxyDirect}))
			require.NoError(t, first.gateway.SetAccountDisabled(t.Context(), grant.ID, true))
			require.NoError(t, first.gateway.SetAccountPriority(t.Context(), grant.ID, 7))
			held, exists := first.gateway.coreAuth.GetByID(grant.ID)
			require.True(t, exists)

			view := VendorAccount(held)
			require.Equal(t, int32(7), view.Priority)
			require.True(t, view.Disabled)
			require.Equal(t, app.ProxyDirect, view.Proxy.Mode)

			require.NoError(t, first.gateway.SetAccountPriority(t.Context(), grant.ID, 0))
			held, exists = first.gateway.coreAuth.GetByID(grant.ID)
			require.True(t, exists)
			require.Equal(t, int32(0), VendorAccount(held).Priority)
			require.NoError(t, first.gateway.SetAccountPriority(t.Context(), grant.ID, -1))
			held, exists = first.gateway.coreAuth.GetByID(grant.ID)
			require.True(t, exists)

			held.Metadata["access_token"] = "refreshed-synthetic-token"
			_, err = first.gateway.coreAuth.Update(t.Context(), held)
			require.NoError(t, err)
			require.ErrorIs(t, first.stop(), context.Canceled)

			second := startCompat(t, pool)
			held, exists = second.gateway.coreAuth.GetByID(grant.ID)
			require.True(t, exists)

			view = VendorAccount(held)
			require.Equal(t, int32(-1), view.Priority)
			require.True(t, view.Disabled)
			require.Equal(t, app.ProxyDirect, view.Proxy.Mode)
			require.Equal(t, "refreshed-synthetic-token", held.Metadata["access_token"])

			again := priorityGrant(t, provider)
			again.Metadata["access_token"] = "reauthenticated-synthetic-token"
			account, err := second.gateway.AddAccount(t.Context(), again)
			require.NoError(t, err)

			view = VendorAccount(account)
			require.Equal(t, int32(-1), view.Priority)
			require.Equal(t, app.ProxyDirect, view.Proxy.Mode)

			held, exists = second.gateway.coreAuth.GetByID(grant.ID)
			require.True(t, exists)
			require.Equal(t, "reauthenticated-synthetic-token", held.Metadata["access_token"])
		})
	}
}

func TestCredentialSerializationPreservesAccountPriority(t *testing.T) {
	fixture := newStoreFixture(t)
	auth := &coreauth.Auth{
		ID: "a-serialized", Provider: "codex",
		Metadata: map[string]any{"priority": "-1"},
		Storage: &faketest.CredentialStorage{Fields: map[string]any{
			"type": "codex", "access_token": "serialized-new-token", "priority": 0,
		}},
	}

	var row app.VendorCredential
	fixture.repo.EXPECT().Upsert(mock.Anything, mock.Anything).RunAndReturn(keep(&row))
	_, err := fixture.store.Save(coreauth.WithAuthCreationIntent(t.Context()), auth)
	require.NoError(t, err)
	fixture.repo.EXPECT().List(mock.Anything).Return([]app.VendorCredential{row}, nil)
	loaded, err := fixture.store.List(t.Context())
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	normal := restoredPriorityAccount(t, "codex", "z-normal", nil)
	selected, err := (&coreauth.RoundRobinSelector{}).Pick(t.Context(), "codex", "priority-probe-model",
		cliproxyexecutor.Options{}, []*coreauth.Auth{loaded[0], normal})
	require.NoError(t, err)
	require.Equal(t, normal.ID, selected.ID)
	require.Equal(t, int32(-1), VendorAccount(loaded[0]).Priority)
	require.Equal(t, "serialized-new-token", loaded[0].Metadata["access_token"])
}

func TestTwoChatGPTAccountsShareNewSessionsAndHonorPriority(t *testing.T) {
	cfg := &cliproxyconfig.Config{AuthDir: t.TempDir()}
	cfg.Routing.SessionAffinity = true
	srv := startCompatWith(t, pgtest.NewTestPool(t), cfg)
	first := priorityGrant(t, "codex")
	second := first.Clone()
	second.ID = "second-" + first.ID
	second.FileName = second.ID
	second.Metadata["email"] = "second-priority@example.com"

	second.Metadata["access_token"] = "second-synthetic-access-token"
	for _, grant := range []*coreauth.Auth{first, second} {
		_, err := srv.gateway.AddAccount(t.Context(), grant)
		require.NoError(t, err)
	}

	for _, grant := range []*coreauth.Auth{first, second} {
		registerClient(t, grant.ID, "codex", "routing-priority-model")
	}

	srv.gateway.coreAuth.RegisterExecutor(&faketest.Executor{Provider: "codex", Payload: []byte(`{"ok":true}`)})

	execute := func(session string) string {
		t.Helper()

		var selectedID string

		metadata := map[string]any{
			cliproxyexecutor.SelectedAuthCallbackMetadataKey: func(id string) { selectedID = id },
			cliproxyexecutor.CanonicalSessionIDMetadataKey:   session,
		}
		_, err := srv.gateway.coreAuth.Execute(t.Context(), []string{"codex"},
			cliproxyexecutor.Request{Model: "routing-priority-model", Payload: []byte(`{"messages":[]}`)},
			cliproxyexecutor.Options{Metadata: metadata, Headers: http.Header{"X-Session-Id": {session}}})
		require.NoError(t, err)
		require.NotEmpty(t, selectedID)

		return selectedID
	}
	firstSelected := execute("equal-first")
	secondSelected := execute("equal-second")
	require.NotEqual(t, firstSelected, secondSelected)
	require.ElementsMatch(t, []string{first.ID, second.ID}, []string{firstSelected, secondSelected})
	require.Equal(t, firstSelected, execute("equal-first"))

	require.NoError(t, srv.gateway.SetAccountPriority(t.Context(), secondSelected, 1))
	require.Equal(t, secondSelected, execute("preferred-new"))
	require.Equal(t, firstSelected, execute("equal-first"), "priority edits must not move an established session")
	srv.gateway.coreAuth.MarkResult(t.Context(), coreauth.Result{
		AuthID: secondSelected, Provider: "codex", Model: "routing-priority-model", RouteModel: "routing-priority-model",
		Error: &coreauth.Error{HTTPStatus: http.StatusTooManyRequests, Message: "synthetic quota exhaustion"},
	})
	require.NoError(t, srv.gateway.SetAccountPriority(t.Context(), secondSelected, 7))
	require.Equal(t, firstSelected, execute("preferred-new"), "an unavailable preferred account must fail over")
}

func TestCanceledPriorityEditDoesNotPersistBeforeConcurrentTokenRotation(t *testing.T) {
	srv := startCompat(t, pgtest.NewTestPool(t))
	grant := priorityGrant(t, "codex")
	_, err := srv.gateway.AddAccount(t.Context(), grant)
	require.NoError(t, err)

	entered := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan error, 1)

	go func() {
		_, _, modifyErr := srv.gateway.coreAuth.Modify(t.Context(), grant.ID, 0, func(current *coreauth.Auth) error {
			close(entered)
			<-release

			current.Metadata["access_token"] = "concurrently-rotated-token"

			return nil
		})
		finished <- modifyErr
	}()

	<-entered

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	err = srv.gateway.SetAccountPriority(ctx, grant.ID, 1)

	close(release)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NoError(t, <-finished)
	stored, err := srv.gateway.store.List(t.Context())
	require.NoError(t, err)
	require.Len(t, stored, 1)
	require.Equal(t, int32(0), VendorAccount(stored[0]).Priority)
	require.Equal(t, "concurrently-rotated-token", stored[0].Metadata["access_token"])
}
