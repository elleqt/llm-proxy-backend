package boot

import (
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway"
	"github.com/elleqt/llm-proxy-backend/internal/infra/metrics"
)

// gateMetrics reports the policy gate's refusals to the metrics collector: the
// adapter between gateway.GateObserver and *metrics.Metrics, which know nothing of
// each other.
type gateMetrics struct{ m *metrics.Metrics }

var _ gateway.GateObserver = gateMetrics{}

func (g gateMetrics) AuthFailed(reason string) { g.m.ObserveAuthFailure(reason) }

func (g gateMetrics) Denied(owner, model string, reason gateway.DenyReason) {
	g.m.ObservePolicyDenied(owner, model, denyReason(reason))
}

// denyReason is the metrics label set's name for a gate refusal. A reason the
// gateway adds later and nobody maps here is counted as "other", never as another
// reason.
func denyReason(r gateway.DenyReason) metrics.DenyReason {
	switch r {
	case gateway.DenyModelNotAllowed:
		return metrics.DenyModelNotAllowed
	case gateway.DenyUnknownModel:
		return metrics.DenyUnknownModel
	case gateway.DenyRouteNotAllowed:
		return metrics.DenyRouteNotAllowed
	default:
		return metrics.DenyReason(^uint8(0))
	}
}
