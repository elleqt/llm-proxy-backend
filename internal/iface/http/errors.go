package http

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/iface/http/api"
)

// The error codes this API answers with, from the contract. A client renders text from
// the code, never from the message, so these are the stable part of every error.
const (
	codeUnauthenticated        = "unauthenticated"
	codePasswordChangeRequired = "password_change_required"
	codeInvalidCredentials     = "invalid_credentials"
	codeLockedOut              = "locked_out"
	codeRateLimited            = "rate_limited"
	codeUnsupportedMediaType   = "unsupported_media_type"
	codePayloadTooLarge        = "payload_too_large"
	codeInvalidInput           = "invalid_input"
	codeWeakPassword           = "weak_password"
	codeEmptyPassword          = "empty_password"
	codeNotFound               = "not_found"
	codeOIDCDisabled           = "oidc_disabled"
	codeInternal               = "internal"

	// The administration API's codes.
	codeEmailTaken          = "email_taken"
	codeInvalidRule         = "invalid_rule"
	codePolicyManagedByIDP  = "policy_managed_by_idp"
	codeSelfLockout         = "self_lockout"
	codeNotLocal            = "not_local"
	codeAlreadyLinked       = "already_linked"
	codeNotInvitable        = "not_invitable"
	codeInvalidSettings     = "invalid_settings"
	codeForbiddenSetting    = "forbidden_setting"
	codeLoginBusy           = "login_busy"
	codeUnsupportedProvider = "unsupported_provider"
	codeLoginExpired        = "login_expired"
	codeLoginFailed         = "login_failed"
	codeTokenLimit          = "token_limit"
	codeCatalogDisabled     = "catalog_disabled"
)

// appRefusals is how the administration API answers every refusal its application
// services return: the error it matches (errors.Is), the contract's status and code,
// and a fixed diagnostic. An error that names a request field (*app.InvalidInputError,
// *app.InvalidRuleError, *app.SettingError) adds it as `field`, unless the row fixes
// one. Anything not listed is a failure, not a refusal: 500 internal. app.ErrConflict
// is not here: what a lost uniqueness race means depends on the route (createUser
// answers email_taken, renewUserInvitation 204), so each handler decides.
var appRefusals = []struct {
	err     error
	status  int
	code    string
	field   string
	message string
}{
	// The administration API does not exist for anyone but an administrator: an
	// actor the service refuses is answered exactly as the admin guard answers.
	{app.ErrForbidden, http.StatusNotFound, codeNotFound, "", "no such endpoint"},
	{app.ErrNotFound, http.StatusNotFound, codeNotFound, "", "no such resource"},
	{app.ErrPolicyManagedByIDP, http.StatusConflict, codePolicyManagedByIDP, "", "the policy is managed by the identity provider"},
	{app.ErrSelfLockout, http.StatusConflict, codeSelfLockout, "", "an administrator cannot block or demote themselves"},
	{app.ErrNotLocal, http.StatusConflict, codeNotLocal, "", "the account cannot hold a password"},
	{app.ErrAlreadyLinked, http.StatusConflict, codeAlreadyLinked, "", "the account already has an identity provider link"},
	{app.ErrNotInvitable, http.StatusConflict, codeNotInvitable, "", "the account cannot be invited"},
	{app.ErrInvalidRule, http.StatusUnprocessableEntity, codeInvalidRule, "", "a policy rule does not parse"},
	{app.ErrInvalidInput, http.StatusUnprocessableEntity, codeInvalidInput, "", "a field is missing or not acceptable"},
	{credentials.ErrInvalidLabel, http.StatusUnprocessableEntity, codeInvalidInput, "label",
		"the label must be 1 to 64 characters with no control characters"},
	{app.ErrForbiddenSetting, http.StatusUnprocessableEntity, codeForbiddenSetting, "", "the setting is owned by the gateway"},
	{app.ErrInvalidSettings, http.StatusUnprocessableEntity, codeInvalidSettings, "", "the settings are not valid"},
	{app.ErrLoginsBusy, http.StatusConflict, codeLoginBusy, "", "too many vendor logins are pending"},
	{app.ErrUnsupportedProvider, http.StatusUnprocessableEntity, codeUnsupportedProvider, "", "no vendor login exists for that provider"},
	{app.ErrLoginExpired, http.StatusGone, codeLoginExpired, "", "the vendor login timed out or was already used"},
	{app.ErrLoginFailed, http.StatusUnprocessableEntity, codeLoginFailed, "", "the vendor sign-in was not accepted"},
	{app.ErrTokenLimit, http.StatusConflict, codeTokenLimit, "", tokenLimitMessage},
	{app.ErrCatalogDisabled, http.StatusConflict, codeCatalogDisabled, "", "no price catalog source is configured"},
}

// tokenLimitMessage explains token_limit on both routes that issue tokens.
var tokenLimitMessage = fmt.Sprintf("the account already holds %d live tokens; revoke one first", app.MaxLiveTokensPerOwner)

// writeAppError answers err by appRefusals, or as an internal failure.
func writeAppError(w http.ResponseWriter, r *http.Request, log app.Logger, err error) {
	for _, ref := range appRefusals {
		if !errors.Is(err, ref.err) {
			continue
		}
		field := ref.field
		if field == "" {
			field = fieldOf(err)
		}
		if field == "" {
			writeError(w, ref.status, ref.code, ref.message)
		} else {
			writeFieldError(w, ref.status, ref.code, field, ref.message)
		}
		return
	}
	internalError(w, r, log, err)
}

// fieldOf is the request field err names, if it names one.
func fieldOf(err error) string {
	var input *app.InvalidInputError
	if errors.As(err, &input) {
		return input.Field
	}
	var rule *app.InvalidRuleError
	if errors.As(err, &rule) {
		return rule.Rule
	}
	var setting *app.SettingError
	if errors.As(err, &setting) {
		return setting.Field
	}
	return ""
}

// writeJSON is the one way a body leaves this API. no-store because several bodies
// carry a secret shown once, and none of them is worth a cache holding.
func writeJSON(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes the contract's Error. message is a fixed English diagnostic chosen
// at the call site — never an error's text, which could carry internals.
func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, api.Error{Code: code, Message: message})
}

// writeFieldError is writeError about one request field.
func writeFieldError(w http.ResponseWriter, status int, code, field, message string) {
	writeJSON(w, status, api.Error{Code: code, Message: message, Field: &field})
}

// writeRetryAfter is writeError for a refusal that lapses: Retry-After carries the
// wait in whole seconds, rounded up so a client that honours it is not refused again.
func writeRetryAfter(w http.ResponseWriter, wait time.Duration, code, message string) {
	secs := int(math.Ceil(wait.Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeError(w, http.StatusTooManyRequests, code, message)
}

// decodeJSON reads the request body into dst. It answers the request itself and
// returns false when the body is too large (413) or is not the JSON dst describes
// (422); the caller only returns.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	err := json.NewDecoder(r.Body).Decode(dst)
	if err == nil {
		return true
	}
	if tooLarge := new(http.MaxBytesError); errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, codePayloadTooLarge, "request body too large")
		return false
	}
	writeError(w, http.StatusUnprocessableEntity, codeInvalidInput, "request body is not the expected JSON")
	return false
}
