package gateway

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	log "github.com/sirupsen/logrus"

	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
)

// providerCatalog answers which providers serve a model; Catalog implements it.
type providerCatalog interface {
	ProvidersFor(model string) []string
}

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
//     (503 when its share is not granted in time, see body_budget.go); the
//     one model the request names (400 without one, or when a JSON body
//     names "model" twice); and the owner's policy covering the model on
//     every provider serving it (403 otherwise, including a model no
//     provider serves). The 403 names the requested model and nothing else.
//   - A listing route lists only the models the same rule (allows) admits.
//
// observe is told of every 401 and every policy or route refusal; nil observes
// nothing.
func policyGate(resolver Resolver, catalog providerCatalog, observe GateObserver) gin.HandlerFunc {
	if observe == nil {
		observe = noGateObserver{}
	}
	return func(c *gin.Context) {
		r := classify(c.Request.Method, c.FullPath())
		if r.kind == routeDenied {
			observe.Denied("", "", DenyRouteNotAllowed)
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		// No encoded body leaves the gate (encoding.go): it is decoded below
		// on the routes whose handler would decode it, and refused on all
		// others before anything else is done with the request.
		encoding, encoded := contentEncoding(c.Request)
		decodes := r.kind == routeModel && r.decodes != nil && r.decodes(c)
		if encoded && !decodes {
			abortWithError(c, http.StatusUnsupportedMediaType, "invalid_request_error", "unsupported content encoding")
			return
		}
		if r.kind != routeModel {
			// Public and listing routes read no body.
			setBody(c.Request, nil)
			c.Request.Body = http.NoBody
		}
		if r.kind == routePublic {
			c.Next()
			return
		}

		ctx := c.Request.Context()
		principal, policy, source, authErr := authenticate(ctx, resolver, c.Request)
		if authErr != nil {
			switch authErr.Code {
			case sdkaccess.AuthErrorCodeNoCredentials:
				observe.AuthFailed(AuthMissing)
			case sdkaccess.AuthErrorCodeInvalidCredential:
				observe.AuthFailed(AuthInvalid)
			}
			if authErr.HTTPStatusCode() >= http.StatusInternalServerError {
				log.Errorf("policy gate: authentication failed: %v", authErr)
			}
			c.AbortWithStatusJSON(authErr.HTTPStatusCode(), gin.H{"error": authErr.Message})
			return
		}
		c.Request = c.Request.WithContext(withPrincipal(ctx, principal, source))

		var requested string
		if r.kind == routeModel {
			limit := r.bodyLimitFor(c)
			length := bodyLength(c.Request)
			if length > limit {
				abortWithError(c, http.StatusRequestEntityTooLarge, "invalid_request_error", "request body too large")
				return
			}
			if c.Request.Body == nil {
				c.Request.Body = http.NoBody
			}
			body := &limitedBody{ReadCloser: http.MaxBytesReader(c.Writer, c.Request.Body, limit)}
			if length != 0 {
				// Without a body the server already reads the connection
				// in the background, where a deadline would cut the reply.
				if err := setBodyReadDeadline(c); err != nil {
					log.Errorf("policy gate: %v", err)
					abortWithError(c, http.StatusInternalServerError, "server_error", "request body cannot be received")
					return
				}
			}
			raw, held, err := bufferBody(ctx, body, length, limit)
			// Held until the handler is done with the body, even if it
			// panics.
			defer held.release()
			if err == nil && encoded {
				raw, err = decodeRequestBody(ctx, raw, encoding, held)
			}
			switch {
			case errors.Is(err, errBodyBusy):
				abortWithError(c, http.StatusServiceUnavailable, "server_error", "too many request bodies in flight; retry")
				return
			case body.tooLarge || errors.Is(err, errBodyOverRead) || errors.Is(err, errDecodedTooLarge):
				abortWithError(c, http.StatusRequestEntityTooLarge, "invalid_request_error", "request body too large")
				return
			case bodyTimedOut(err):
				abortWithError(c, http.StatusRequestTimeout, "invalid_request_error", "request body not received in time")
				return
			case errors.Is(err, errUnreadableBody):
				abortWithError(c, http.StatusBadRequest, "invalid_request_error", "request body cannot be decoded")
				return
			case err != nil:
				abortWithError(c, http.StatusBadRequest, "invalid_request_error", "request body cannot be read")
				return
			}
			if encoded {
				setBody(c.Request, raw)
			} else {
				c.Request.Body = io.NopCloser(bytes.NewReader(raw))
			}
			model, ok := r.model(c, raw)
			if !ok {
				abortWithError(c, http.StatusBadRequest, "invalid_request_error", "request must name exactly one model")
				return
			}
			requested = model
		}
		if r.kind == routeListing {
			serveListing(c, r.listing, func(model string) bool { return allows(policy, catalog, model) })
			return
		}
		model, providers := routedProviders(catalog, requested)
		if !policy.Covers(model, providers) {
			reason := DenyModelNotAllowed
			if len(providers) == 0 {
				reason = DenyUnknownModel
			}
			observe.Denied(principal.Owner, model, reason)
			abortWithError(c, http.StatusForbidden, "permission_error", "model "+requested+" is not allowed")
			return
		}
		c.Next()
	}
}

// serveListing runs the handler with its response held back, and sends what
// list keeps of it. A list that is too large or not of the expected shape is
// not sent: 502.
func serveListing(c *gin.Context, list listing, admitted func(string) bool) {
	held := &bufferedWriter{ResponseWriter: c.Writer, status: http.StatusOK, limit: maxListingBody}
	c.Writer = held
	c.Next()
	c.Writer = held.ResponseWriter

	status, body, err := list(c, held.status, held.body.Bytes(), admitted)
	if held.overflow {
		err = errListingTooLarge
	}
	c.Writer.Header().Del("Content-Length")
	if err != nil {
		log.Errorf("policy gate: filter %s: %v", c.FullPath(), err)
		abortWithError(c, http.StatusBadGateway, "server_error", "model list unavailable")
		return
	}
	c.Writer.WriteHeader(status)
	_, _ = c.Writer.Write(body)
}

// limitedBody is a request body read through http.MaxBytesReader that
// remembers whether its limit was hit, so the gate can answer 413 whichever
// reader hit it.
type limitedBody struct {
	io.ReadCloser
	tooLarge bool
}

func (b *limitedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		b.tooLarge = true
	}
	return n, err
}

// abortWithError answers in the error shape upstream's handlers use.
func abortWithError(c *gin.Context, status int, kind, message string) {
	c.AbortWithStatusJSON(status, gin.H{"error": gin.H{"message": message, "type": kind}})
}

// allows reports whether policy covers the model a request names, resolved
// as upstream routes it, on every provider that could serve it
// (access.Policy.Covers, the one rule the admin screens apply too).
func allows(policy access.Policy, catalog providerCatalog, requested string) bool {
	model, providers := routedProviders(catalog, requested)
	return policy.Covers(model, providers)
}

// routedProviders resolves requested as upstream does before routing
// (sdk/api/handlers/handlers_routing.go getRequestDetailsWithOptions): the
// name without its thinking suffix first, then the full name. It returns the
// registered model the providers were found for. "auto" names whichever model
// upstream finds available first, so it is never resolved.
func routedProviders(catalog providerCatalog, requested string) (string, []string) {
	base := thinkingBase(requested)
	if requested == "auto" || base == "auto" {
		return "", nil
	}
	trimmed := strings.TrimSpace(base)
	if providers := catalog.ProvidersFor(trimmed); len(providers) > 0 {
		return trimmed, providers
	}
	if trimmed != requested {
		return requested, catalog.ProvidersFor(requested)
	}
	return trimmed, nil
}
