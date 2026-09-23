package boot

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway"
	"github.com/elleqt/llm-proxy-backend/internal/infra/metrics"
)

// Each refusal the gate reports lands under its own reason, a refusal before
// authentication under the unknown user, and a reason nobody mapped as "other"
// rather than as some other reason.
func TestGateRefusalsReachTheMetricsUnderTheirReasons(t *testing.T) {
	m := metrics.New(prometheus.NewRegistry(),
		metrics.WithKnownModel(func(model string) (string, bool) { return model, model == "served-model" }))
	g := gateMetrics{m}

	g.AuthFailed(gateway.AuthMissing)
	g.AuthFailed(gateway.AuthInvalid)
	g.Denied("alice@example.com", "served-model", gateway.DenyModelNotAllowed)
	g.Denied("alice@example.com", "Client-Invented-Model", gateway.DenyUnknownModel)
	g.Denied("", "", gateway.DenyRouteNotAllowed)
	g.Denied("alice@example.com", "served-model", gateway.DenyReason(200))

	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		`llmproxy_auth_failures_total{reason="missing"} 1`,
		`llmproxy_auth_failures_total{reason="invalid"} 1`,
		`llmproxy_policy_denied_total{model="served-model",reason="model_not_allowed",user="alice@example.com"} 1`,
		`llmproxy_policy_denied_total{model="unknown",reason="unknown_model",user="alice@example.com"} 1`,
		`llmproxy_policy_denied_total{model="unknown",reason="route_not_allowed",user="unknown"} 1`,
		`llmproxy_policy_denied_total{model="served-model",reason="other",user="alice@example.com"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("scrape lacks %s:\n%s", want, body)
		}
	}
}
