package gateway

import (
	"context"
	"net/http"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	"github.com/stretchr/testify/require"
)

func TestCompatProviderHeadersSurviveRestart(t *testing.T) {
	pool := pgtest.NewTestPool(t)
	vendor := compatVendor()
	endpoint := faketest.Start(t, vendor)
	name, alias := compatName(t, "headers"), compatModel(t, "headers")

	const secret = "vendor-header-secret"

	first := startCompat(t, pool)
	account, err := first.gateway.AddCompatProvider(t.Context(), app.CompatProvider{
		Name: name, BaseURL: endpoint.URL, Priority: 7,
		Headers: map[string]string{"x-vendor-token": secret},
		Models:  []app.CompatModel{{Name: "m", Alias: alias}},
	})
	require.NoError(t, err)
	awaitProviders(t, first.gateway.catalog, alias, []string{name})
	require.Equal(t, http.StatusOK, chatVia(t, first, alias))
	require.Equal(t, secret, vendor.Requests()[0].Header.Get("X-Vendor-Token"))
	require.Equal(t, int32(7), account.Compat.Priority)
	require.Equal(t, []string{"x-vendor-token"}, account.Compat.HeaderNames)
	assertNoKey(t, first.gateway, secret)
	require.ErrorIs(t, first.stop(), context.Canceled)

	second := startCompat(t, pool)
	awaitProviders(t, second.gateway.catalog, alias, []string{name})
	require.Equal(t, http.StatusOK, chatVia(t, second, alias))
	require.Equal(t, secret, vendor.Requests()[1].Header.Get("X-Vendor-Token"))
	assertNoKey(t, second.gateway, secret)

	kept, err := second.gateway.UpdateCompatProvider(t.Context(), account.ID, app.CompatProviderUpdate{
		BaseURL: endpoint.URL, Models: []app.CompatModel{{Name: "m", Alias: alias}},
	})
	require.NoError(t, err)
	require.Equal(t, int32(7), kept.Compat.Priority)
	require.Equal(t, http.StatusOK, chatVia(t, second, alias))
	require.Equal(t, secret, vendor.Requests()[2].Header.Get("X-Vendor-Token"))

	_, err = second.gateway.UpdateCompatProvider(t.Context(), account.ID, app.CompatProviderUpdate{
		BaseURL: "https://elsewhere.example.com/v1", Models: []app.CompatModel{{Name: "m", Alias: alias}},
	})

	var invalid *app.InvalidInputError
	require.ErrorAs(t, err, &invalid)
	require.Equal(t, "headers", invalid.Field)

	zero := int32(0)
	_, err = second.gateway.UpdateCompatProvider(t.Context(), account.ID, app.CompatProviderUpdate{
		BaseURL: endpoint.URL, Priority: &zero, Headers: map[string]string{"x-replaced": "replacement"},
		Models: []app.CompatModel{{Name: "m", Alias: alias}},
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, chatVia(t, second, alias))
	require.Empty(t, vendor.Requests()[3].Header.Get("X-Vendor-Token"))
	require.Equal(t, "replacement", vendor.Requests()[3].Header.Get("X-Replaced"))

	cleared, err := second.gateway.UpdateCompatProvider(t.Context(), account.ID, app.CompatProviderUpdate{
		BaseURL: endpoint.URL, Headers: map[string]string{}, Models: []app.CompatModel{{Name: "m", Alias: alias}},
	})
	require.NoError(t, err)
	require.Equal(t, int32(0), cleared.Compat.Priority)
	require.Equal(t, []string{}, cleared.Compat.HeaderNames)
	require.Equal(t, http.StatusOK, chatVia(t, second, alias))
	require.Empty(t, vendor.Requests()[4].Header.Get("X-Replaced"))
}
