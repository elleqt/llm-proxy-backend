package gateway

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	"github.com/stretchr/testify/require"
)

func TestDiscoverModelsProtectsStoredHeaders(t *testing.T) {
	const secret = "discovery-header-secret"

	seen := make(chan http.Header, 8)
	vendor := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		seen <- req.Header.Clone()

		if req.Header.Get("X-Token") != secret {
			writer.WriteHeader(http.StatusUnauthorized)

			return
		}

		_, _ = writer.Write([]byte(`{"data":[{"id":"authorized-model"}]}`))
	}))
	t.Cleanup(vendor.Close)

	var elsewhereCalls atomic.Int64

	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhereCalls.Add(1)

		_, _ = w.Write([]byte(`{"data":[{"id":"elsewhere"}]}`))
	}))
	t.Cleanup(elsewhere.Close)

	srv := startCompat(t, pgtest.NewTestPool(t))
	account, err := srv.gateway.AddCompatProvider(t.Context(), app.CompatProvider{
		Name: compatName(t, "discheaders"), BaseURL: vendor.URL,
		Headers: map[string]string{"x-token": secret, "x-session": "$CPA-SESSION-ID", "x-copy": "$X-Session-ID"},
		Models:  []app.CompatModel{{Name: compatModel(t, "m")}},
	})
	require.NoError(t, err)
	ids, err := srv.gateway.DiscoverModels(t.Context(), vendor.URL, "", account.ID, nil, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"authorized-model"}, ids)

	headers := <-seen
	require.Equal(t, secret, headers.Get("X-Token"))
	require.Empty(t, headers.Get("X-Session"))
	require.Empty(t, headers.Get("X-Copy"))

	_, err = srv.gateway.DiscoverModels(t.Context(), elsewhere.URL, "new-explicit-key", account.ID, nil, nil)

	var invalid *app.InvalidInputError
	require.ErrorAs(t, err, &invalid)
	require.Equal(t, "headers", invalid.Field)
	require.Zero(t, elsewhereCalls.Load())
	require.NotContains(t, err.Error(), secret)

	_, err = srv.gateway.DiscoverModels(t.Context(), vendor.URL, "", account.ID, nil, map[string]string{})
	require.ErrorIs(t, err, app.ErrProviderAuthFailed)
	require.Empty(t, (<-seen).Get("X-Token"))
	ids, err = srv.gateway.DiscoverModels(t.Context(), vendor.URL, "", "", nil, map[string]string{"x-token": secret})
	require.NoError(t, err)
	require.Equal(t, []string{"authorized-model"}, ids)
	require.Equal(t, secret, (<-seen).Get("X-Token"))
}

func TestDiscoverModelsDoesNotRedirectHeaderSecrets(t *testing.T) {
	var targetCalls atomic.Int64

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetCalls.Add(1)

		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(target.Close)

	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/models", http.StatusFound)
	}))
	t.Cleanup(source.Close)
	_, err := (&Gateway{}).DiscoverModels(t.Context(), source.URL, "", "", nil, map[string]string{"x-token": "secret"})
	require.ErrorIs(t, err, app.ErrProviderUnreachable)
	require.Zero(t, targetCalls.Load())
}
