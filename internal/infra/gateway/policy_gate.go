package gateway

import (
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	"github.com/gin-gonic/gin"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
)

// policyGate is the proxied listener's default-deny guard, first in the
// embedded server's middleware. It does not rely on upstream's access check,
// which admits everything when it holds no provider:
//
//   - A route routes does not list as public, listing or model answers 404
//     before any upstream handler.
//   - A request with a Content-Encoding other than identity is refused (415)
//     unless its route's handler decodes one; there the gate decodes it after
//     authentication, bounded (413 over the limit), and passes it on
//     identity-encoded. Public and listing routes get no body at all.
//   - Every other route but the public one needs an active token, resolved
//     once through authenticate — the access provider's own sources, order and
//     errors — so a refusal has upstream's status and body byte for byte. The
//     principal goes on the request context (withPrincipal) and the access
//     provider accepts it without resolving again. The resolver returns the
//     owner's policy with it, so the owner is read once per request.
//   - A model route needs a body within its limit (413 otherwise) and
//     received within bodyReadTimeout (408 otherwise), which the gate holds
//     in memory under the process-wide body budget until the handler returns
//     (429 when its owner already holds their share, 503 when the budget is
//     not granted in time, see body_budget.go); the one model the request
//     names (400 without one, or when a JSON body names "model" twice); and
//     the owner's policy covering the model on every provider serving it
//     (403 otherwise, including a model no provider serves). The 403 names
//     the requested model and nothing else.
//   - A listing route lists only the models the same rule (access.Policy.Admits)
//     admits.
//
// observe is told of every 401 and every policy or route refusal; nil observes
// nothing. log receives the gate's own failures; nil discards them.
func policyGate(resolver Resolver, catalog access.Catalog, observe GateObserver, log *slog.Logger) gin.HandlerFunc {
	if observe == nil {
		observe = noGateObserver{}
	}

	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}

	return func(ginCtx *gin.Context) {
		matched := classify(ginCtx.Request.Method, ginCtx.FullPath())
		if matched.kind == routeDenied {
			observe.Denied("", "", DenyRouteNotAllowed)
			ginCtx.AbortWithStatus(http.StatusNotFound)

			return
		}
		// No encoded body leaves the gate (encoding.go): it is decoded below
		// on the routes whose handler would decode it, and refused on all
		// others before anything else is done with the request.
		encoding, encoded := contentEncoding(ginCtx.Request)

		decodes := matched.kind == routeModel && matched.decodes != nil && matched.decodes(ginCtx)
		if encoded && !decodes {
			abortWithError(ginCtx, http.StatusUnsupportedMediaType, "invalid_request_error", "unsupported content encoding")

			return
		}

		if matched.kind != routeModel {
			// Public and listing routes read no body.
			setBody(ginCtx.Request, nil)
			ginCtx.Request.Body = http.NoBody
		}

		if matched.kind == routePublic {
			ginCtx.Next()

			return
		}

		ctx := ginCtx.Request.Context()

		principal, policy, source, authErr := authenticate(ctx, resolver, ginCtx.Request)
		if authErr != nil {
			refuseAuthentication(ginCtx, authErr, observe, log)

			return
		}

		ginCtx.Request = ginCtx.Request.WithContext(withPrincipal(ctx, principal, source))

		var requested string

		if matched.kind == routeModel {
			limit := matched.bodyLimitFor(ginCtx)

			held := newBodyCharge(principal.UserID, bodyChargeCeiling(limit, encoded))
			// Held until the handler is done with the body, even if it
			// panics.
			defer held.release()

			var ok bool
			if requested, ok = requestedModel(ginCtx, matched, held, limit, encoding, encoded, log); !ok {
				return
			}
		}

		if matched.kind == routeListing {
			serveListing(ginCtx, matched.listing, func(model string) bool { return policy.Admits(catalog, model) }, log)

			return
		}

		model, providers := access.Routed(catalog, requested)
		if !policy.Covers(model, providers) {
			reason := DenyModelNotAllowed
			if len(providers) == 0 {
				reason = DenyUnknownModel
			}

			observe.Denied(principal.Owner, model, reason)
			abortWithError(ginCtx, http.StatusForbidden, "permission_error", "model "+requested+" is not allowed")

			return
		}

		ginCtx.Next()
	}
}

// refuseAuthentication answers a request authenticate refused, with
// upstream's status and body, telling observe of a missing or invalid
// credential and log of a failure on the gateway's side.
func refuseAuthentication(ginCtx *gin.Context, authErr *sdkaccess.AuthError, observe GateObserver, log *slog.Logger) {
	switch authErr.Code {
	case sdkaccess.AuthErrorCodeNoCredentials:
		observe.AuthFailed(AuthMissing)
	case sdkaccess.AuthErrorCodeInvalidCredential:
		observe.AuthFailed(AuthInvalid)
	case sdkaccess.AuthErrorCodeNotHandled, sdkaccess.AuthErrorCodeInternal:
		// Not a credential the client got wrong: nothing to observe.
	}

	if authErr.HTTPStatusCode() >= http.StatusInternalServerError {
		log.LogAttrs(ginCtx.Request.Context(), slog.LevelError, "policy gate: authentication failed", slog.Any("err", authErr))
	}

	ginCtx.AbortWithStatusJSON(authErr.HTTPStatusCode(), gin.H{"error": authErr.Message})
}

// bodyChargeCeiling is the most a model route's body may be charged: its
// limit, and decoding an encoded one a whole maxJSONBody on top of it.
func bodyChargeCeiling(limit int64, encoded bool) int64 {
	if encoded {
		return limit + maxJSONBody
	}

	return limit
}

// requestedModel receives a model route's body — within limit, in time and
// under held, decoded from encoding when encoded — puts it back on the
// request for the handler, and returns the one model it names. It answers
// the request itself, and reports false, when the body or its model is
// refused.
func requestedModel(ginCtx *gin.Context, matched route, held *bodyCharge, limit int64,
	encoding string, encoded bool, log *slog.Logger,
) (string, bool) {
	raw, ok := receiveBody(ginCtx, held, limit, encoding, encoded, log)
	if !ok {
		return "", false
	}

	model, ok := matched.model(ginCtx, raw)
	if !ok {
		abortWithError(ginCtx, http.StatusBadRequest, "invalid_request_error", "request must name exactly one model")

		return "", false
	}

	return model, true
}

// receiveBody reads the request's body whole, as requestedModel describes,
// and leaves it identity-encoded on the request. It answers the request
// itself, and reports false, when the body is refused.
func receiveBody(ginCtx *gin.Context, held *bodyCharge, limit int64,
	encoding string, encoded bool, log *slog.Logger,
) ([]byte, bool) {
	ctx := ginCtx.Request.Context()

	length := bodyLength(ginCtx.Request)
	if length > limit {
		abortWithError(ginCtx, http.StatusRequestEntityTooLarge, "invalid_request_error", "request body too large")

		return nil, false
	}

	if ginCtx.Request.Body == nil {
		ginCtx.Request.Body = http.NoBody
	}

	body := &limitedBody{ReadCloser: http.MaxBytesReader(ginCtx.Writer, ginCtx.Request.Body, limit)}

	var deadline *bodyDeadline

	if length != 0 {
		// Without a body the server already reads the connection
		// in the background, where a deadline would cut the reply.
		var err error
		if deadline, err = setBodyReadDeadline(ginCtx); err != nil {
			log.LogAttrs(ctx, slog.LevelError, "policy gate: request body deadline could not be set",
				slog.Any("err", err))
			abortWithError(ginCtx, http.StatusInternalServerError, "server_error", "request body cannot be received")

			return nil, false
		}
	}

	raw, err := bufferBody(ctx, held, body, length, limit)
	if deadline.stop() {
		err = errors.Join(err, os.ErrDeadlineExceeded)
	}

	if err == nil && encoded {
		raw, err = decodeRequestBody(ctx, raw, encoding, held)
	}

	if abortBodyError(ginCtx, body, err) {
		return nil, false
	}

	if encoded {
		setBody(ginCtx.Request, raw)
	} else {
		ginCtx.Request.Body = io.NopCloser(bytes.NewReader(raw))
	}

	return raw, true
}

// abortBodyError answers a request whose body could not be received or
// decoded, by what went wrong, and reports whether it did; a nil err answers
// nothing.
func abortBodyError(ginCtx *gin.Context, body *limitedBody, err error) bool {
	switch {
	case errors.Is(err, errBodyShare):
		ginCtx.Header("Retry-After", "1")
		abortWithError(ginCtx, http.StatusTooManyRequests, "rate_limit_error", "too many large requests in flight for this account; retry")
	case errors.Is(err, errBodyBusy):
		abortWithError(ginCtx, http.StatusServiceUnavailable, "server_error", "too many request bodies in flight; retry")
	case body.tooLarge || errors.Is(err, errBodyOverRead) || errors.Is(err, errDecodedTooLarge):
		abortWithError(ginCtx, http.StatusRequestEntityTooLarge, "invalid_request_error", "request body too large")
	case bodyTimedOut(err):
		// The rest of the body may still arrive: the connection
		// cannot carry another request.
		ginCtx.Header("Connection", "close")
		abortWithError(ginCtx, http.StatusRequestTimeout, "invalid_request_error", "request body not received in time")
	case errors.Is(err, errUnreadableBody):
		abortWithError(ginCtx, http.StatusBadRequest, "invalid_request_error", "request body cannot be decoded")
	case err != nil:
		abortWithError(ginCtx, http.StatusBadRequest, "invalid_request_error", "request body cannot be read")
	default:
		return false
	}

	return true
}

// serveListing runs the handler with its response held back, and sends what
// list keeps of it. A list that is too large or not of the expected shape is
// not sent: 502.
func serveListing(ginCtx *gin.Context, list listing, admitted func(string) bool, log *slog.Logger) {
	held := &bufferedWriter{ResponseWriter: ginCtx.Writer, status: http.StatusOK, limit: maxListingBody}
	ginCtx.Writer = held
	ginCtx.Next()
	ginCtx.Writer = held.ResponseWriter

	status, body, err := list(ginCtx, held.status, held.body.Bytes(), admitted)
	if held.overflow {
		err = errListingTooLarge
	}

	ginCtx.Writer.Header().Del("Content-Length")

	if err != nil {
		log.LogAttrs(ginCtx.Request.Context(), slog.LevelError, "policy gate: filtering a listing failed",
			slog.String("route", ginCtx.FullPath()), slog.Any("err", err))
		abortWithError(ginCtx, http.StatusBadGateway, "server_error", "model list unavailable")

		return
	}

	ginCtx.Writer.WriteHeader(status)
	_, _ = ginCtx.Writer.Write(body)
}

// limitedBody is a request body read through http.MaxBytesReader that
// remembers whether its limit was hit, so the gate can answer 413 whichever
// reader hit it.
type limitedBody struct {
	io.ReadCloser

	tooLarge bool
}

func (b *limitedBody) Read(p []byte) (int, error) {
	count, err := b.ReadCloser.Read(p)

	if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
		b.tooLarge = true
	}

	return count, err //nolint:wrapcheck // io.Reader contract: io.EOF must reach the caller unwrapped.
}

// abortWithError answers in the error shape upstream's handlers use.
func abortWithError(c *gin.Context, status int, kind, message string) {
	c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"message": message, "type": kind}})
}
