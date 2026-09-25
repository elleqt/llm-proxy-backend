package boot

import (
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/gate"
	"github.com/elleqt/llm-proxy-backend/internal/infra/metrics"
)

// gateMetrics reports the policy gate's refusals to the metrics collector: the
// adapter between gate.Observer and *metrics.Metrics, which know nothing of
// each other.
type gateMetrics struct{ m *metrics.Metrics }

var _ gate.Observer = gateMetrics{}

func (g gateMetrics) AuthFailed(reason string) { g.m.ObserveAuthFailure(reason) }

func (g gateMetrics) Denied(owner, model string, reason gate.DenyReason) {
	g.m.ObservePolicyDenied(owner, model, denyReason(reason))
}

// denyReason is the metrics label set's name for a gate refusal. A reason the
// gateway adds later and nobody maps here is counted as "other", never as another
// reason.
func denyReason(r gate.DenyReason) metrics.DenyReason {
	switch r {
	case gate.DenyModelNotAllowed:
		return metrics.DenyModelNotAllowed
	case gate.DenyUnknownModel:
		return metrics.DenyUnknownModel
	case gate.DenyRouteNotAllowed:
		return metrics.DenyRouteNotAllowed
	default:
		return metrics.DenyReason(^uint8(0))
	}
}
