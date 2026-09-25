package gateway

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/access"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
)

// accessProviderType is the key the provider is registered and made exclusive
// under in upstream's access registry, and its Result.Provider.
const accessProviderType = "llmproxy-token"

// Resolver authenticates an API token secret, and returns the policy of the
// token's owner with the principal. app.TokenResolver implements it: every
// refusal is app.ErrInvalidCredentials; any other error is a failed lookup.
type Resolver interface {
	Resolve(ctx context.Context, secret string) (app.Principal, access.Policy, error)
}

// AccessProvider is upstream's request authentication, answered by API tokens
// that belong to users. It is the only provider that may admit a request (see
// Gateway.claimAccess).
type AccessProvider struct {
	resolver Resolver
}

var _ sdkaccess.Provider = (*AccessProvider)(nil)

func NewAccessProvider(resolver Resolver) *AccessProvider {
	return &AccessProvider{resolver: resolver}
}

func (p *AccessProvider) Identifier() string { return accessProviderType }

// Authenticate admits a request that carries a principal the policy gate
// already resolved (see withPrincipal), or else one presenting a secret the
// resolver accepts (see authenticate). Every refusal is a 401 or a 500 from
// upstream's middleware; none carries the secret.
func (p *AccessProvider) Authenticate(ctx context.Context, r *http.Request) (*sdkaccess.Result, *sdkaccess.AuthError) {
	if principal, source, ok := principalFrom(ctx); ok {
		return result(principal, source), nil
	}

	principal, _, source, err := authenticate(ctx, p.resolver, r)
	if err != nil {
		return nil, err
	}

	return result(principal, source), nil
}

// authenticate resolves the credential r presents to the principal it
// authenticates and its owner's policy, and names where r presented it. No credential is
// no_credentials; a rejected one is invalid_credential; a failed lookup is an
// internal error, so an outage is not reported to a client as a bad key. The
// errors are upstream's own, so whoever answers with one — the access
// provider through upstream's middleware, or the policy gate itself — sends
// the same status and body.
func authenticate(ctx context.Context, resolver Resolver, r *http.Request) (app.Principal, access.Policy, string, *sdkaccess.AuthError) {
	candidates := credentialCandidates(r)
	if len(candidates) == 0 {
		// "Authorization: Bearer " presents a credential that is empty: upstream
		// calls that invalid, not missing.
		if r.Header.Get("Authorization") != "" {
			return app.Principal{}, nil, "", sdkaccess.NewInvalidCredentialError()
		}

		return app.Principal{}, nil, "", sdkaccess.NewNoCredentialsError()
	}

	for _, c := range candidates {
		principal, policy, err := resolver.Resolve(ctx, c.secret)
		if err == nil {
			return principal, policy, c.source, nil
		}

		if !errors.Is(err, app.ErrInvalidCredentials) {
			return app.Principal{}, nil, "", sdkaccess.NewInternalAuthError("", err)
		}
	}

	return app.Principal{}, nil, "", sdkaccess.NewInvalidCredentialError()
}

func result(p app.Principal, source string) *sdkaccess.Result {
	return &sdkaccess.Result{
		Provider:  accessProviderType,
		Principal: p.String(),
		Metadata:  map[string]string{"source": source},
	}
}

// candidate is one credential a request presents, and where it presented it.
type candidate struct {
	secret string
	source string
}

// credentialCandidates returns the credentials req presents, in the order and
// from exactly the places upstream's built-in provider reads them
// (internal/access/config_access/provider.go Authenticate, v7.3.15):
// Authorization (the token after "Bearer ", or the whole header when it has no
// Bearer scheme), X-Goog-Api-Key, X-Api-Key, then the key and auth_token query
// parameters. The source names are upstream's. Like upstream, any presented
// credential that authenticates admits the request; a value repeated in
// several places is resolved once. The policy gate reads credentials through
// this function too, so both resolve the same token.
func credentialCandidates(req *http.Request) []candidate {
	var query map[string][]string
	if req.URL != nil {
		query = req.URL.Query()
	}

	all := [...]candidate{
		{bearerToken(req.Header.Get("Authorization")), "authorization"},
		{req.Header.Get("X-Goog-Api-Key"), "x-goog-api-key"},
		{req.Header.Get("X-Api-Key"), "x-api-key"},
		{first(query["key"]), "query-key"},
		{first(query["auth_token"]), "query-auth-token"},
	}

	out := make([]candidate, 0, len(all))
	for _, c := range all {
		if c.secret == "" || seen(out, c.secret) {
			continue
		}

		out = append(out, c)
	}

	return out
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}

	return values[0]
}

func seen(cs []candidate, secret string) bool {
	for _, c := range cs {
		if c.secret == secret {
			return true
		}
	}

	return false
}

// bearerToken mirrors upstream's extractBearerToken.
func bearerToken(header string) string {
	scheme, token, ok := strings.Cut(header, " ")
	if !ok || !strings.EqualFold(scheme, "bearer") {
		return header
	}

	return strings.TrimSpace(token)
}

// principalKey is the request-context key the policy gate stores its resolved
// principal under. It is unexported, so nothing outside this package can put
// a principal on a request.
type principalKey struct{}

type resolvedPrincipal struct {
	principal app.Principal
	source    string
}

// withPrincipal records that the request has been authenticated as p, from
// the credential at source, so the access provider admits it without a second
// lookup.
func withPrincipal(ctx context.Context, p app.Principal, source string) context.Context {
	return context.WithValue(ctx, principalKey{}, resolvedPrincipal{principal: p, source: source})
}

// principalFrom returns what withPrincipal recorded on ctx.
func principalFrom(ctx context.Context) (app.Principal, string, bool) {
	v, ok := ctx.Value(principalKey{}).(resolvedPrincipal)

	return v.principal, v.source, ok
}

// accessMu serialises every read-modify of upstream's process-global access
// registry this package makes, together with the upstream step that reads it.
var accessMu sync.Mutex
