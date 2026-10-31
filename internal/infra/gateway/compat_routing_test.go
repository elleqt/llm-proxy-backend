package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
	"github.com/stretchr/testify/require"
)

// compatRoute exercises production credential registration with two real vendors.
type compatRoute struct {
	server    *running
	alias     string
	primaryID string
	primary   *faketest.Vendor
	fallback  *faketest.Vendor
}

func startCompatRoute(t *testing.T, primary *faketest.Vendor) *compatRoute {
	t.Helper()
	cfg := &cliproxyconfig.Config{AuthDir: t.TempDir()}
	cfg.Routing.SessionAffinity = true
	srv := startCompatWith(t, pgtest.NewTestPool(t), cfg)
	fallback := routingVendor("fallback")
	alias := compatModel(t, "shared")
	names := []string{compatName(t, "primary"), compatName(t, "fallback")}

	var primaryID string

	for index, vendor := range []*faketest.Vendor{primary, fallback} {
		endpoint := faketest.Start(t, vendor)
		account, err := srv.gateway.AddCompatProvider(t.Context(), app.CompatProvider{
			Name: names[index], BaseURL: endpoint.URL, Priority: []int32{1, 0}[index],
			Headers: map[string]string{"x-opencode-session": "$CPA-SESSION-ID"},
			Models:  []app.CompatModel{{Name: "m", Alias: alias}},
		})
		require.NoError(t, err)

		if index == 0 {
			primaryID = account.ID
		}
	}

	slices.Sort(names)
	awaitProviders(t, srv.gateway.catalog, alias, names)

	return &compatRoute{server: srv, alias: alias, primaryID: primaryID, primary: primary, fallback: fallback}
}

func routingVendor(label string) *faketest.Vendor {
	vendor := compatVendor()
	vendor.Payload = []byte(strings.ReplaceAll(string(vendor.Payload), "hello", label))
	vendor.Chunks = [][]byte{streamChunk(label, ""), streamChunk("", "stop")}

	return vendor
}

func (route *compatRoute) request(t *testing.T, session string, stream bool) (int, []byte, error) {
	t.Helper()

	body, err := json.Marshal(map[string]any{
		"model": route.alias, "stream": stream,
		"messages": []map[string]string{{"role": "user", "content": "hello"}},
	})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, route.server.baseURL+"/v1/chat/completions", strings.NewReader(string(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+wireSecret)
	req.Header.Set("X-Session-Id", session)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)

	defer func() { _ = resp.Body.Close() }()

	out, err := io.ReadAll(resp.Body)

	return resp.StatusCode, out, err
}

func TestCompatPriorityAndDynamicSessionHeaders(t *testing.T) {
	route := startCompatRoute(t, routingVendor("primary"))

	for index, stream := range []bool{false, true, false, true} {
		session := fmt.Sprintf("priority-probe-%d", index)
		status, body, err := route.request(t, session, stream)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status, "%s", body)
		require.Contains(t, string(body), "primary")
		require.Len(t, route.primary.Requests(), index+1)
		require.Equal(t, "header:"+session, route.primary.Requests()[index].Header.Get("X-Opencode-Session"))
	}

	require.Empty(t, route.fallback.Requests())
}

func TestCompatNativeFailover(t *testing.T) {
	for _, status := range []int{401, 402, 403, 429, 503} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%d/stream=%t", status, stream), func(t *testing.T) {
				primary := routingVendor("primary")
				primary.FailStatus = status
				primary.FailBody = []byte(`{"error":{"type":"server_error","message":"provider unavailable"}}`)
				route := startCompatRoute(t, primary)
				gotStatus, body, err := route.request(t, "failover-probe", stream)
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, gotStatus, "%s", body)
				require.Contains(t, string(body), "fallback")
				require.NotContains(t, string(body), "primary")
				require.Len(t, primary.Requests(), 1)
				require.Len(t, route.fallback.Requests(), 1)
			})
		}
	}
}

func TestCompatSessionStaysOnFallbackAfterRecovery(t *testing.T) {
	route := startCompatRoute(t, routingVendor("primary"))
	status, body, err := route.request(t, "stable-probe", false)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "%s", body)
	require.Contains(t, string(body), "primary")
	require.NoError(t, route.server.gateway.SetAccountDisabled(t.Context(), route.primaryID, true))
	status, body, err = route.request(t, "stable-probe", false)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "%s", body)
	require.Contains(t, string(body), "fallback")
	require.NoError(t, route.server.gateway.SetAccountDisabled(t.Context(), route.primaryID, false))
	status, body, err = route.request(t, "stable-probe", false)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "%s", body)
	require.Contains(t, string(body), "fallback")
	status, body, err = route.request(t, "new-probe", false)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "%s", body)
	require.Contains(t, string(body), "primary")
	require.Len(t, route.primary.Requests(), 2)
	require.Len(t, route.fallback.Requests(), 2)
}

func TestCompatInvalidRequestDoesNotUseFallback(t *testing.T) {
	primary := routingVendor("primary")
	primary.FailStatus = http.StatusBadRequest
	primary.FailBody = []byte(`{"error":{"type":"invalid_request_error","message":"invalid messages"}}`)
	route := startCompatRoute(t, primary)
	status, body, err := route.request(t, "invalid-probe", false)
	require.NoError(t, err)
	require.Equal(t, http.StatusBadRequest, status, "%s", body)
	require.Empty(t, route.fallback.Requests())
}

func TestCompatPartialStreamDoesNotUseFallback(t *testing.T) {
	primary := routingVendor("primary")
	primary.Chunks = [][]byte{streamChunk("primary", "")}
	primary.DieMidStream = true
	route := startCompatRoute(t, primary)
	status, body, _ := route.request(t, "partial-probe", true)
	require.Equal(t, http.StatusOK, status, "%s", body)
	require.Contains(t, string(body), "primary")
	require.NotContains(t, string(body), "fallback")
	require.Empty(t, route.fallback.Requests())
}

func TestCompatCanceledRequestDoesNotUseFallback(t *testing.T) {
	primary := routingVendor("primary")
	primary.Latency = 20 * time.Millisecond
	route := startCompatRoute(t, primary)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	body := `{"model":"` + route.alias + `","stream":true,"messages":[{"role":"user","content":"hello"}]}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, route.server.baseURL+"/v1/chat/completions", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+wireSecret)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	_, err = bufio.NewReader(resp.Body).ReadString('\n')
	require.NoError(t, err)
	cancel()

	_ = resp.Body.Close()

	require.ErrorIs(t, route.server.stop(), context.Canceled)
	require.Len(t, route.primary.Requests(), 1)
	require.Empty(t, route.fallback.Requests())
}

func TestGenericPriorityEditChangesCompatibleRoutingWithoutMovingSessions(t *testing.T) {
	route := startCompatRoute(t, routingVendor("primary"))
	status, body, err := route.request(t, "before-role-edit", false)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "%s", body)
	require.Contains(t, string(body), "primary")
	require.NoError(t, route.server.gateway.SetAccountPriority(t.Context(), route.primaryID, -1))
	status, body, err = route.request(t, "after-role-edit", false)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "%s", body)
	require.Contains(t, string(body), "fallback")
	status, body, err = route.request(t, "before-role-edit", false)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "%s", body)
	require.Contains(t, string(body), "primary")
}
