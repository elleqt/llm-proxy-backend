package app

import (
	"errors"
	"strconv"
	"time"
)

// Refusals the services in app's subpackages return, beside the sentinels in
// ports.go: every one the web API maps (internal/iface/http/errors.go) is
// declared in this package, so callers match them without importing a service.

var (
	// ErrPolicyManagedByIDP refuses a policy edit the next IdP login would undo.
	ErrPolicyManagedByIDP = errors.New("app: policy is managed by the identity provider")
	// ErrSelfLockout refuses an administrator blocking or demoting themselves.
	ErrSelfLockout = errors.New("app: an administrator cannot block or demote themselves")
	// ErrNotLocal refuses a password for an account that cannot hold one.
	ErrNotLocal = errors.New("app: account cannot hold a password")
	// ErrInvalidRule is what an *InvalidRuleError unwraps to.
	ErrInvalidRule = errors.New("app: invalid policy rule")
	// ErrInvalidInput is what an *InvalidInputError unwraps to.
	ErrInvalidInput = errors.New("app: invalid input")
	// ErrAlreadyLinked refuses an invitation to an account that already signs in
	// through the identity provider.
	ErrAlreadyLinked = errors.New("app: account already has an identity provider link")
	// ErrNotInvitable refuses an invitation nobody could redeem: a service account,
	// an account without an address, or OIDC sign-in not configured.
	ErrNotInvitable = errors.New("app: account cannot be invited")
)

// InvalidRuleError names the first policy rule that does not parse.
type InvalidRuleError struct{ Rule string }

func (e *InvalidRuleError) Error() string {
	return ErrInvalidRule.Error() + ": " + strconv.Quote(e.Rule)
}
func (e *InvalidRuleError) Unwrap() error { return ErrInvalidRule }

// InvalidInputError names the request field that is missing or not acceptable.
type InvalidInputError struct{ Field string }

func (e *InvalidInputError) Error() string { return ErrInvalidInput.Error() + ": " + e.Field }
func (e *InvalidInputError) Unwrap() error { return ErrInvalidInput }

var (
	// ErrForbiddenSetting is what a *SettingError about a gateway-owned field
	// unwraps to.
	ErrForbiddenSetting = errors.New("app: setting is owned by the gateway")
	// ErrInvalidSettings is what a *SettingError about a malformed document or
	// field unwraps to.
	ErrInvalidSettings = errors.New("app: invalid settings")
	// ErrNoRunningConfig reports a gateway that holds no configuration yet, so
	// there is nothing to diff against or apply over.
	ErrNoRunningConfig = errors.New("app: the gateway has no running configuration")
)

// SettingError names the request field or top-level YAML key a settings update is
// refused for. It unwraps to ErrForbiddenSetting or ErrInvalidSettings; build one
// with ForbiddenSetting or InvalidSetting.
type SettingError struct {
	Field  string
	Reason string
	kind   error
}

func (e *SettingError) Error() string {
	msg := e.kind.Error()
	if e.Field != "" {
		msg += ": " + e.Field
	}

	if e.Reason != "" {
		msg += ": " + e.Reason
	}

	return msg
}

func (e *SettingError) Unwrap() error { return e.kind }

// ForbiddenSetting refuses field as owned by the gateway.
func ForbiddenSetting(field string) error {
	return &SettingError{Field: field, Reason: "owned by the gateway", kind: ErrForbiddenSetting}
}

// InvalidSetting refuses field as malformed or not acceptable, for reason.
func InvalidSetting(field, reason string) error {
	return &SettingError{Field: field, Reason: reason, kind: ErrInvalidSettings}
}

// ErrBlocked is what a *BlockedError unwraps to.
var ErrBlocked = errors.New("app: account is blocked")

// BlockedError refuses a recovery for a blocked account: a new password would not let
// it in, and unblocking is an administrator's decision.
type BlockedError struct {
	// CanUnblock reports that the recovery may unblock the account when asked to: it
	// is an administrator and no other active administrator exists who could.
	CanUnblock bool
}

func (e *BlockedError) Error() string { return ErrBlocked.Error() }
func (e *BlockedError) Unwrap() error { return ErrBlocked }

// LockedOutError is a sign-in refused because its address is locked. It satisfies
// errors.Is(err, ErrLockedOut) and carries the instant the lock lapses, so the
// transport can tell the client when to come back (Retry-After).
//
// The lockout is visible on purpose and is not an existence oracle: every address is
// charged the same, whether an account stands behind it or not, so "locked" says
// only that this address took maxFailures attempts — which the prober made.
type LockedOutError struct {
	Until time.Time
}

func (e *LockedOutError) Error() string { return ErrLockedOut.Error() }

func (e *LockedOutError) Unwrap() error { return ErrLockedOut }
