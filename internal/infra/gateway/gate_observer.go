package gateway

// Why the gate refused a request's credentials: a closed set, never derived
// from what the request presented.
const (
	// AuthMissing: the request presented no credential.
	AuthMissing = "missing"
	// AuthInvalid: the credential is empty, unknown, revoked, or its owner may
	// not use the API — the resolver does not say which.
	AuthInvalid = "invalid"
)

// DenyReason is why the policy gate refused an authenticated request or a route.
// It is a closed set, so a client cannot choose what an observer is told.
type DenyReason uint8

const (
	// DenyModelNotAllowed: the model is known, but the policy does not allow the
	// owner every provider that serves it.
	DenyModelNotAllowed DenyReason = iota
	// DenyUnknownModel: no provider serves the requested model; the gate fails
	// closed.
	DenyUnknownModel
	// DenyRouteNotAllowed: the path is not on the proxied listener's allow-list.
	DenyRouteNotAllowed
)

// GateObserver is told what the policy gate refuses. The composition root adapts
// it to the metrics collector; this package knows nothing of metrics.
type GateObserver interface {
	// AuthFailed reports a request refused 401; reason is AuthMissing or
	// AuthInvalid.
	AuthFailed(reason string)
	// Denied reports a request refused by policy or route. owner is the label of
	// the token's owner the resolver returned (app.Principal.Owner), "" when the
	// request was refused before authentication; model is the model the
	// request named, "" when none: raw client input, not a safe label value.
	Denied(owner, model string, reason DenyReason)
}

// noGateObserver observes nothing.
type noGateObserver struct{}

func (noGateObserver) AuthFailed(string)                 {}
func (noGateObserver) Denied(string, string, DenyReason) {}
