package gateway

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
)

// An OpenAI-compatible provider the administrator adds is an account like a
// vendor sign-in: one credential in the token store, provider
// OpenAICompatibilityKey, whose metadata holds its whole definition (name,
// base URL, optional key, prefix, models). It is the single source of truth:
// the gateway derives the provider's openai-compatibility configuration entry
// from the held account (compatConfig) and its routing attributes from the
// stored metadata (applyCompatAttributes).
//
// Upstream needs both to serve it. Model registration and the executor find
// the entry by the auth's compat_name attribute
// (sdk/cliproxy/service_models.go registerModelsForAuthWithCache,
// sdk/cliproxy/auth/conductor_models.go resolveOpenAICompatConfigForAuth; the
// config_index lookup applies to config-sourced auths only), and the executor
// reads base_url and api_key from the auth's attributes alone. Upstream builds
// such auths from configuration on Run only, never on the reload PushConfig
// drives, which is why the provider is an account and not a configuration
// entry with a key.

// Metadata keys of an OpenAI-compatible provider's credential.
const (
	compatMetaName    = "compat_name"
	compatMetaBaseURL = "base_url"
	compatMetaAPIKey  = "api_key"
	compatMetaPrefix  = "prefix"
	compatMetaModels  = "models"
	compatMetaLabel   = "label"
)

// Attributes upstream routes an openai-compatibility auth by
// (sdk/cliproxy/auth/conductor_models.go openAICompatProviderKey).
const (
	compatAttrName        = "compat_name"
	compatAttrProviderKey = "provider_key"
	compatAttrBaseURL     = "base_url"
	compatAttrAPIKey      = "api_key"
)

// Discovery bounds: an administrator waits on it, and the answer is a list of
// ids, so a vendor that is slow or answers at length is treated as unreachable.
const (
	discoverTimeout  = 10 * time.Second
	discoverMaxBytes = 1 << 20
)

// fieldBaseURL is the request field a refused discovery target is reported on.
const fieldBaseURL = "baseURL"

// errCompatNotHeld reports an update of an account that is not an
// OpenAI-compatible provider.
var errCompatNotHeld = fmt.Errorf("gateway: not an openai-compatible provider: %w", app.ErrNotFound)

// CompatAccountID is the account id, and credential key, of the
// OpenAI-compatible provider called name: upstream's provider key for it,
// unique per name.
func CompatAccountID(name string) string { return compatProviderKey(name) }

// isCompatAccount reports whether auth is an OpenAI-compatible provider the
// administrator added. Upstream's own config-derived openai-compatibility
// auths go by the provider key ("openai-compatible-<name>"), never by
// OpenAICompatibilityKey.
func isCompatAccount(auth *coreauth.Auth) bool {
	if auth == nil || auth.Provider != OpenAICompatibilityKey {
		return false
	}

	name, _ := auth.Metadata[compatMetaName].(string)

	return name != ""
}

// applyCompatAttributes sets the routing attributes, label and prefix of an
// OpenAI-compatible provider's auth from its metadata. The token store
// persists metadata only, so a loaded account gets them here.
func applyCompatAttributes(auth *coreauth.Auth) {
	name, _ := auth.Metadata[compatMetaName].(string)
	baseURL, _ := auth.Metadata[compatMetaBaseURL].(string)
	apiKey, _ := auth.Metadata[compatMetaAPIKey].(string)
	prefix, _ := auth.Metadata[compatMetaPrefix].(string)

	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string, 4)
	}

	auth.Attributes[compatAttrName] = name
	auth.Attributes[compatAttrProviderKey] = compatProviderKey(name)
	auth.Attributes[compatAttrBaseURL] = baseURL

	if apiKey != "" {
		auth.Attributes[compatAttrAPIKey] = apiKey
	} else {
		delete(auth.Attributes, compatAttrAPIKey)
	}

	auth.Label = name
	auth.Prefix = prefix
}

// compatMetadata is the credential of the OpenAI-compatible provider p.
func compatMetadata(provider app.CompatProvider) map[string]any {
	models := make([]any, 0, len(provider.Models))
	for _, m := range provider.Models {
		entry := map[string]any{"name": m.Name}
		if m.Alias != "" {
			entry["alias"] = m.Alias
		}

		models = append(models, entry)
	}

	meta := map[string]any{
		metadataType:      OpenAICompatibilityKey,
		compatMetaLabel:   provider.Name,
		compatMetaName:    provider.Name,
		compatMetaBaseURL: provider.BaseURL,
		compatMetaModels:  models,
	}
	if provider.APIKey != "" {
		meta[compatMetaAPIKey] = provider.APIKey
	}

	if provider.Prefix != "" {
		meta[compatMetaPrefix] = provider.Prefix
	}

	return meta
}

// compatModels reads the models an OpenAI-compatible provider's metadata
// lists. The metadata went through JSON, so the list is []any of objects.
func compatModels(meta map[string]any) []app.CompatModel {
	raw, _ := meta[compatMetaModels].([]any)

	out := make([]app.CompatModel, 0, len(raw))
	for _, item := range raw {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}

		name, _ := entry["name"].(string)
		alias, _ := entry["alias"].(string)

		if name != "" {
			out = append(out, app.CompatModel{Name: name, Alias: alias})
		}
	}

	return out
}

// compatDetails is the admin view of an OpenAI-compatible provider's auth.
func compatDetails(auth *coreauth.Auth) *app.CompatDetails {
	name, _ := auth.Metadata[compatMetaName].(string)
	baseURL, _ := auth.Metadata[compatMetaBaseURL].(string)
	apiKey, _ := auth.Metadata[compatMetaAPIKey].(string)
	prefix, _ := auth.Metadata[compatMetaPrefix].(string)

	return &app.CompatDetails{
		Name: name, BaseURL: baseURL, Prefix: prefix, HasAPIKey: apiKey != "",
		Models: compatModels(auth.Metadata),
	}
}

// compatEntry is the configuration entry upstream registers an
// OpenAI-compatible provider's models from. It carries no key and no prefix:
// both are on the auth.
func compatEntry(auth *coreauth.Auth) cliproxyconfig.OpenAICompatibility {
	name, _ := auth.Metadata[compatMetaName].(string)
	baseURL, _ := auth.Metadata[compatMetaBaseURL].(string)

	models := compatModels(auth.Metadata)
	entry := cliproxyconfig.OpenAICompatibility{
		Name:    name,
		BaseURL: baseURL,
		Models:  make([]cliproxyconfig.OpenAICompatibilityModel, 0, len(models)),
	}

	for _, m := range models {
		entry.Models = append(entry.Models, cliproxyconfig.OpenAICompatibilityModel{Name: m.Name, Alias: m.Alias})
	}

	return entry
}

// compatEntries derives the configuration entries of the OpenAI-compatible
// providers among auths, ordered by name.
func compatEntries(auths []*coreauth.Auth) []cliproxyconfig.OpenAICompatibility {
	var out []cliproxyconfig.OpenAICompatibility

	for _, auth := range auths {
		if isCompatAccount(auth) {
			out = append(out, compatEntry(auth))
		}
	}

	slices.SortFunc(out, func(a, b cliproxyconfig.OpenAICompatibility) int { return cmp.Compare(a.Name, b.Name) })

	return out
}

// withCompat returns cfg's openai-compatibility list as the gateway runs it:
// the boot entries (Params.Config's own, g.static) followed by one entry per
// OpenAI-compatible provider the manager holds. Whatever cfg carried is
// replaced, so a configuration built from the running one (settings'
// overlayOwned) cannot keep a removed provider's entry alive.
func (g *Gateway) withCompat(held []*coreauth.Auth) []cliproxyconfig.OpenAICompatibility {
	out := slices.Clone(g.static)

	return append(out, compatEntries(held)...)
}

// bootCompat adds the entry of every OpenAI-compatible provider in stored to
// cfg's own openai-compatibility entries (the boot entries), and returns the
// boot entries and the stored providers' names, lower-cased.
func bootCompat(cfg *cliproxyconfig.Config, stored []*coreauth.Auth) ([]cliproxyconfig.OpenAICompatibility, map[string]struct{}) {
	static := slices.Clone(cfg.OpenAICompatibility)
	entries := compatEntries(stored)
	cfg.OpenAICompatibility = append(slices.Clone(static), entries...)

	names := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		names[strings.ToLower(entry.Name)] = struct{}{}
	}

	return static, names
}

// heldAuths is what the manager holds; nil without a manager.
func (g *Gateway) heldAuths() []*coreauth.Auth {
	if g.coreAuth == nil {
		return nil
	}

	return g.coreAuth.List()
}

// dropSynthesizedCompat removes the auths upstream synthesised on Run from the
// derived entries of stored providers (service_lifecycle.go
// registerConfigAPIKeyAuths): keyless copies of the providers the store
// already holds with their keys, which would otherwise be routed to as well.
// Their model registrations go with them. It runs in OnBeforeStart, before
// the server serves and before upstream registers the held accounts' models.
func (g *Gateway) dropSynthesizedCompat(ctx context.Context) {
	if g.coreAuth == nil || len(g.derived) == 0 {
		return
	}

	for _, auth := range g.coreAuth.List() {
		if !coreauth.IsConfigAPIKeyAuth(auth) {
			continue
		}

		if _, derived := g.derived[strings.ToLower(auth.Attributes[compatAttrName])]; derived {
			g.coreAuth.Remove(ctx, auth.ID)
			cliproxy.GlobalModelRegistry().UnregisterClient(auth.ID)
		}
	}
}

// AddCompatProvider adds the OpenAI-compatible provider p as an account and
// serves its models at once. The name must be free — no held account and no
// boot entry goes by it (app.ErrConflict) — and not reserved for a built-in
// provider (*app.InvalidInputError on "name").
func (g *Gateway) AddCompatProvider(ctx context.Context, provider app.CompatProvider) (app.VendorAccount, error) {
	if compatNameRefused(provider.Name) {
		return app.VendorAccount{}, &app.InvalidInputError{Field: "name"}
	}

	id := CompatAccountID(provider.Name)

	g.pushMu.Lock()
	defer g.pushMu.Unlock()

	if g.coreAuth != nil {
		if _, held := g.coreAuth.GetByID(id); held {
			return app.VendorAccount{}, fmt.Errorf("gateway: provider %q: %w", provider.Name, app.ErrConflict)
		}
	}

	for _, entry := range g.static {
		if strings.EqualFold(strings.TrimSpace(entry.Name), provider.Name) {
			return app.VendorAccount{}, fmt.Errorf("gateway: provider %q: %w", provider.Name, app.ErrConflict)
		}
	}

	auth := &coreauth.Auth{
		ID:       id,
		FileName: id,
		Provider: OpenAICompatibilityKey,
		Status:   coreauth.StatusActive,
		Metadata: compatMetadata(provider),
	}
	applyCompatAttributes(auth)

	stored, err := g.addLocked(ctx, auth)
	if err != nil {
		return app.VendorAccount{}, err
	}

	return VendorAccount(stored), nil
}

// UpdateCompatProvider replaces the definition of the OpenAI-compatible
// provider id and serves it at once. The credential is saved first, so a
// failed save changes nothing; the name and the disabled state are kept.
// A stored key stays bound to its base URL: moving the provider to another
// base URL while keeping the key is an *app.InvalidInputError on "apiKey"
// (type the key again, or remove it), so the key never follows a URL the
// administrator merely typed.
func (g *Gateway) UpdateCompatProvider(ctx context.Context, id string, update app.CompatProviderUpdate) (app.VendorAccount, error) {
	g.pushMu.Lock()
	defer g.pushMu.Unlock()

	if g.store == nil {
		return app.VendorAccount{}, ErrNoTokenStore
	}

	reload, held, err := g.accountLocked(id)
	if err != nil {
		return app.VendorAccount{}, err
	}

	if !isCompatAccount(held) {
		return app.VendorAccount{}, fmt.Errorf("%w: %q", errCompatNotHeld, id)
	}

	name, _ := held.Metadata[compatMetaName].(string)
	apiKey, _ := held.Metadata[compatMetaAPIKey].(string)
	storedURL, _ := held.Metadata[compatMetaBaseURL].(string)

	switch {
	case update.APIKey != nil:
		apiKey = *update.APIKey
	case apiKey != "" && strings.TrimRight(storedURL, "/") != strings.TrimRight(update.BaseURL, "/"):
		return app.VendorAccount{}, &app.InvalidInputError{Field: "apiKey"}
	}

	next := held.Clone()
	next.Metadata = compatMetadata(app.CompatProvider{
		Name: name, BaseURL: update.BaseURL, APIKey: apiKey, Prefix: update.Prefix, Models: update.Models,
	})
	next.Metadata[metadataDisabled] = held.Disabled
	applyCompatAttributes(next)

	if _, err := g.store.Save(ctx, next); err != nil {
		return app.VendorAccount{}, fmt.Errorf("gateway: provider %q was not saved: %w", name, err)
	}

	updated, err := g.coreAuth.Update(ctx, next)
	if err != nil {
		return app.VendorAccount{}, fmt.Errorf("gateway: provider %q was saved but not applied (retry): %w", name, err)
	}

	if updated == nil {
		return app.VendorAccount{}, fmt.Errorf("%w: %q", ErrUnknownAccount, id)
	}

	g.reapplyLocked(reload)

	return VendorAccount(updated), nil
}

// DiscoverModels asks the vendor at baseURL which models it serves (GET
// {baseURL}/models, the OpenAI model list) and returns their ids, sorted.
// With no apiKey and accountID naming an OpenAI-compatible provider, that
// provider's stored key is sent, and only to its stored base URL: for any
// other baseURL it is an *app.InvalidInputError on "apiKey", so no request
// can carry a stored key to a host the administrator merely typed. The
// request goes through the running configuration's proxy-url, as the
// provider's traffic does, follows redirects only within the same scheme and
// host, and gives up after discoverTimeout or discoverMaxBytes. Errors name
// neither the URL nor the vendor's answer: app.ErrProviderAuthFailed for 401
// and 403, else app.ErrProviderUnreachable.
func (g *Gateway) DiscoverModels(ctx context.Context, baseURL, apiKey, accountID string) ([]string, error) {
	if apiKey == "" && accountID != "" && g.coreAuth != nil {
		if held, ok := g.coreAuth.GetByID(accountID); ok && isCompatAccount(held) {
			stored, _ := held.Metadata[compatMetaBaseURL].(string)
			if strings.TrimRight(stored, "/") != strings.TrimRight(baseURL, "/") {
				return nil, &app.InvalidInputError{Field: "apiKey"}
			}

			apiKey, _ = held.Metadata[compatMetaAPIKey].(string)
		}
	}

	endpoint, err := url.Parse(strings.TrimRight(baseURL, "/") + "/models")
	if err != nil {
		return nil, &app.InvalidInputError{Field: fieldBaseURL}
	}

	// The target itself, resolved here: behind a proxy the dialer below only
	// ever sees the proxy's address.
	if err := refuseLinkLocalHost(ctx, endpoint.Hostname()); err != nil {
		return nil, err
	}

	client, err := g.discoveryClient(endpoint)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, g.discoveryTimeout())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, &app.InvalidInputError{Field: fieldBaseURL}
	}

	req.Header.Set("Accept", "application/json")

	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed", app.ErrProviderUnreachable)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("%w: status %d", app.ErrProviderAuthFailed, resp.StatusCode)
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, fmt.Errorf("%w: status %d", app.ErrProviderUnreachable, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, discoverMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading the answer failed", app.ErrProviderUnreachable)
	}

	if len(body) > discoverMaxBytes {
		return nil, fmt.Errorf("%w: the answer is too large", app.ErrProviderUnreachable)
	}

	return modelIDs(body)
}

// discoveryClient is the client DiscoverModels asks endpoint with.
func (g *Gateway) discoveryClient(endpoint *url.URL) (*http.Client, error) {
	var proxyURL string
	if cfg := g.CurrentConfig(); cfg != nil {
		proxyURL = cfg.ProxyURL
	}

	transport, mode, err := proxyutil.BuildHTTPTransport(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("%w: the proxy-url is not usable", app.ErrProviderUnreachable)
	}

	if transport == nil {
		// No proxy-url: the default transport, environment proxy included,
		// as the rest of the vendor traffic goes out.
		base, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			base = &http.Transport{Proxy: http.ProxyFromEnvironment}
		}

		transport = base.Clone()
	}

	if mode != proxyutil.ModeProxy {
		// The dialer checks the address it actually connects to, so a name
		// that resolves differently after refuseLinkLocalHost is caught. Behind
		// an environment proxy it sees the proxy, and refuseLinkLocalHost has
		// covered the target. A proxy-url's own dialer (SOCKS) is left alone.
		dialer := &net.Dialer{Timeout: g.discoveryTimeout(), Control: refuseLinkLocalDial}
		transport.DialContext = dialer.DialContext
	}

	return &http.Client{
		Timeout:   g.discoveryTimeout(),
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != endpoint.Scheme || req.URL.Host != endpoint.Host || len(via) >= 5 {
				return errCrossHostRedirect
			}

			return nil
		},
	}, nil
}

// discoveryTimeout is how long DiscoverModels waits: discoverTimeout unless a
// test shortened it.
func (g *Gateway) discoveryTimeout() time.Duration {
	if g.discoverWait > 0 {
		return g.discoverWait
	}

	return discoverTimeout
}

// errLinkLocal refuses a discovery target on a link-local, multicast or
// unspecified address: where cloud metadata services answer, never a vendor.
// Loopback and private addresses stay allowed; a vendor on the same machine
// or network is a real case.
var errLinkLocal = errors.New("gateway: link-local discovery target")

// linkLocal reports whether ip is an address discovery must not reach.
func linkLocal(ip net.IP) bool {
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified()
}

// refuseLinkLocalHost resolves host and refuses it (*app.InvalidInputError on
// "baseURL") when any address it names is link-local. A name that does not
// resolve is left to the request, which then fails as unreachable.
func refuseLinkLocalHost(ctx context.Context, host string) error {
	var ips []net.IP

	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else if addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host); err == nil {
		for _, addr := range addrs {
			ips = append(ips, addr.IP)
		}
	}

	if slices.ContainsFunc(ips, linkLocal) {
		return &app.InvalidInputError{Field: fieldBaseURL}
	}

	return nil
}

// refuseLinkLocalDial is the direct dialer's Control hook: it refuses to
// connect to a link-local address, whatever name led there.
func refuseLinkLocalDial(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("gateway: discovery dial address %q: %w", address, err)
	}

	if ip := net.ParseIP(host); ip != nil && linkLocal(ip) {
		return errLinkLocal
	}

	return nil
}

// errCrossHostRedirect stops a discovery redirect that leaves the base URL's
// scheme and host: the key would follow it.
var errCrossHostRedirect = errors.New("gateway: redirect to another host")

// modelIDs reads an OpenAI model list ({"data":[{"id":…}]}) and returns its
// ids, sorted and without duplicates.
func modelIDs(body []byte) ([]string, error) {
	var list struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &list); err != nil || list.Data == nil {
		return nil, fmt.Errorf("%w: the answer is not a model list", app.ErrProviderUnreachable)
	}

	ids := make([]string, 0, len(list.Data))
	for _, m := range list.Data {
		if id := strings.TrimSpace(m.ID); id != "" {
			ids = append(ids, id)
		}
	}

	slices.Sort(ids)

	return slices.Compact(ids), nil
}
