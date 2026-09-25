package boot

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway"
	"github.com/elleqt/llm-proxy-backend/internal/infra/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// Each refusal the gate reports lands under its own reason, a refusal before
// authentication under the unknown user, and a reason nobody mapped as "other"
// rather than as some other reason.
func TestGateRefusalsReachTheMetricsUnderTheirReasons(t *testing.T) {
	meters := metrics.New(prometheus.NewRegistry(),
		metrics.WithKnownModel(func(model string) (string, bool) { return model, model == "served-model" }))
	gate := gateMetrics{meters}

	gate.AuthFailed(gateway.AuthMissing)
	gate.AuthFailed(gateway.AuthInvalid)
	gate.Denied("alice@example.com", "served-model", gateway.DenyModelNotAllowed)
	gate.Denied("alice@example.com", "Client-Invented-Model", gateway.DenyUnknownModel)
	gate.Denied("", "", gateway.DenyRouteNotAllowed)
	gate.Denied("alice@example.com", "served-model", gateway.DenyReason(200))

	rec := httptest.NewRecorder()
	meters.Handler().ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))

	body := rec.Body.String()
	for _, want := range []string{
		`llmproxy_auth_failures_total{reason="missing"} 1`,
		`llmproxy_auth_failures_total{reason="invalid"} 1`,
		`llmproxy_policy_denied_total{model="served-model",reason="model_not_allowed",user="alice@example.com"} 1`,
		`llmproxy_policy_denied_total{model="unknown",reason="unknown_model",user="alice@example.com"} 1`,
		`llmproxy_policy_denied_total{model="unknown",reason="route_not_allowed",user="unknown"} 1`,
		`llmproxy_policy_denied_total{model="served-model",reason="other",user="alice@example.com"} 1`,
	} {
		require.Contains(t, body, want, "scrape lacks %s", want)
	}
}
