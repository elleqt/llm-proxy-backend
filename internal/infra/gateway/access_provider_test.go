package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
)

func messagesRequest(target string) *http.Request {
	return httptest.NewRequest(http.MethodPost, target, nil)
}

// TestAccessProviderAcceptsEverySupportedSource covers every place upstream's
// built-in provider reads a key from (internal/access/config_access/provider.go),
// with upstream's source names.
func TestAccessProviderAcceptsEverySupportedSource(t *testing.T) {
	p := NewAccessProvider(wireResolver)
	for _, tc := range []struct {
		name   string
		source string
		build  func() *http.Request
	}{
		{"authorization bearer", "authorization", func() *http.Request {
			r := messagesRequest("/v1/messages")
			r.Header.Set("Authorization", "Bearer "+wireSecret)
			return r
		}},
		{"authorization lower-case scheme", "authorization", func() *http.Request {
			r := messagesRequest("/v1/messages")
			r.Header.Set("Authorization", "bearer "+wireSecret)
			return r
		}},
		{"authorization without a scheme", "authorization", func() *http.Request {
			r := messagesRequest("/v1/messages")
			r.Header.Set("Authorization", wireSecret)
			return r
		}},
		{"x-goog-api-key", "x-goog-api-key", func() *http.Request {
			r := messagesRequest("/v1/messages")
			r.Header.Set("X-Goog-Api-Key", wireSecret)
			return r
		}},
		{"x-api-key", "x-api-key", func() *http.Request {
			r := messagesRequest("/v1/messages")
			r.Header.Set("X-Api-Key", wireSecret)
			return r
		}},
		{"query key", "query-key", func() *http.Request {
			return messagesRequest("/v1/messages?key=" + wireSecret)
		}},
		{"query auth_token", "query-auth-token", func() *http.Request {
			return messagesRequest("/v1/messages?auth_token=" + wireSecret)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, authErr := p.Authenticate(context.Background(), tc.build())
			if authErr != nil {
				t.Fatalf("Authenticate: %v", authErr)
			}
			if res.Provider != "llmproxy-token" || res.Principal != wirePrincipal.String() || res.Metadata["source"] != tc.source {
				t.Fatalf("result = %+v, want provider llmproxy-token, principal %q, source %q", res, wirePrincipal, tc.source)
			}
		})
	}
}

// TestAccessProviderAdmitsAnyPresentedCredentialThatAuthenticates: like
// upstream, a request is not refused because one of several places carries
// something else — a client may send a vendor header alongside its token.
func TestAccessProviderAdmitsAnyPresentedCredentialThatAuthenticates(t *testing.T) {
	r := messagesRequest("/v1/messages")
	r.Header.Set("Authorization", "Bearer something-else")
	r.Header.Set("X-Api-Key", wireSecret)

	res, authErr := NewAccessProvider(wireResolver).Authenticate(context.Background(), r)
	if authErr != nil {
		t.Fatalf("Authenticate: %v", authErr)
	}
	if res.Principal != wirePrincipal.String() || res.Metadata["source"] != "x-api-key" {
		t.Fatalf("result = %+v, want the x-api-key token's principal", res)
	}
}

func TestAccessProviderRejectsAnUnknownSecret(t *testing.T) {
	r := messagesRequest("/v1/messages?key=sk-other")
	r.Header.Set("Authorization", "Bearer sk-unknown")

	_, authErr := NewAccessProvider(wireResolver).Authenticate(context.Background(), r)
	if !sdkaccess.IsAuthErrorCode(authErr, sdkaccess.AuthErrorCodeInvalidCredential) {
		t.Fatalf("err = %v, want invalid_credential", authErr)
	}
}

func TestAccessProviderWithoutACredentialReportsNone(t *testing.T) {
	p := NewAccessProvider(wireResolver)
	if _, authErr := p.Authenticate(context.Background(), messagesRequest("/v1/messages")); !sdkaccess.IsAuthErrorCode(authErr, sdkaccess.AuthErrorCodeNoCredentials) {
		t.Fatalf("no credential: err = %v, want no_credentials", authErr)
	}

	// An empty bearer token is a credential that is present and wrong, as upstream has it.
	r := messagesRequest("/v1/messages")
	r.Header.Set("Authorization", "Bearer ")
	if _, authErr := p.Authenticate(context.Background(), r); !sdkaccess.IsAuthErrorCode(authErr, sdkaccess.AuthErrorCodeInvalidCredential) {
		t.Fatalf("empty bearer: err = %v, want invalid_credential", authErr)
	}
}

// TestAccessProviderTrustsThePrincipalOnTheContext: the policy gate has
// already resolved the token and put the principal on the request context, so
// the provider must admit without a second lookup.
func TestAccessProviderTrustsThePrincipalOnTheContext(t *testing.T) {
	p := NewAccessProvider(resolverFunc(func(context.Context, string) (app.Principal, access.Policy, error) {
		t.Error("the resolver was called although the context carries a principal")
		return app.Principal{}, nil, app.ErrInvalidCredentials
	}))
	r := messagesRequest("/v1/messages")
	r.Header.Set("X-Api-Key", wireSecret)
	ctx := withPrincipal(context.Background(), wirePrincipal, "x-api-key")

	res, authErr := p.Authenticate(ctx, r)
	if authErr != nil {
		t.Fatalf("Authenticate: %v", authErr)
	}
	if res.Provider != "llmproxy-token" || res.Principal != wirePrincipal.String() || res.Metadata["source"] != "x-api-key" {
		t.Fatalf("result = %+v, want the gate's principal and source", res)
	}
}

// TestAccessProviderReportsAFailedLookupAsInternal: an outage must not tell a
// client holding a valid token that its key is wrong, and must not carry the
// secret into upstream's error log.
func TestAccessProviderReportsAFailedLookupAsInternal(t *testing.T) {
	p := NewAccessProvider(resolverFunc(func(context.Context, string) (app.Principal, access.Policy, error) {
		return app.Principal{}, nil, errors.New("app: resolve token: connection refused")
	}))
	r := messagesRequest("/v1/messages")
	r.Header.Set("Authorization", "Bearer "+wireSecret)

	_, authErr := p.Authenticate(context.Background(), r)
	if !sdkaccess.IsAuthErrorCode(authErr, sdkaccess.AuthErrorCodeInternal) || authErr.HTTPStatusCode() != http.StatusInternalServerError {
		t.Fatalf("err = %v, want internal_error with status 500", authErr)
	}
	if strings.Contains(authErr.Error(), wireSecret) || strings.Contains(authErr.Message, wireSecret) {
		t.Fatalf("error %q carries the secret", authErr)
	}
}
