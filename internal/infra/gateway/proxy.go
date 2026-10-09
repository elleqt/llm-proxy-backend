package gateway

import (
	"context"
	"fmt"
	"net/url"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/proxyutil"
)

// An account's proxy lives where upstream reads it: Auth.ProxyURL, which the
// executors prefer to the global proxy-url on every request
// (internal/runtime/executor/helps proxy_helpers.go effectiveProxyURL), and
// its credential's "proxy_url" metadata, which the token store keeps and
// restores into Auth.ProxyURL (authFromRow). "" inherits the global
// proxy-url, "direct" bypasses it, anything else is the account's own proxy
// (sdk/proxyutil Parse).

// metadataProxy is the credential metadata key an account's proxy is kept under.
const metadataProxy = "proxy_url"

// proxyDirect is the stored form of app.ProxyDirect.
const proxyDirect = "direct"

// proxyValue is the stored form of choice. It re-checks a custom URL with
// upstream's own parser, so a value upstream would read as invalid is never
// stored; the error names the field, never the URL.
func proxyValue(choice app.ProxyChoice) (string, error) {
	switch choice.Mode {
	case app.ProxyInherit:
		return "", nil
	case app.ProxyDirect:
		return proxyDirect, nil
	case app.ProxyCustom:
		setting, err := proxyutil.Parse(choice.URL)
		if err != nil || setting.Mode != proxyutil.ModeProxy || !proxyutil.ValidRequestProxy(choice.URL) {
			return "", &app.InvalidInputError{Field: app.FieldProxyURL}
		}

		return setting.Raw, nil
	default:
		return "", &app.InvalidInputError{Field: app.FieldProxyMode}
	}
}

// accountProxy is raw, an account's stored proxy, as the admin API shows it:
// a proxy URL reduced to scheme and host, its userinfo reported only as
// HasCredentials. A stored value upstream cannot read is shown as a custom
// proxy without a URL: the administrator sees something is set and can
// replace it.
func accountProxy(raw string) app.AccountProxy {
	setting, err := proxyutil.Parse(raw)

	switch {
	case err != nil:
		return app.AccountProxy{Mode: app.ProxyCustom}
	case setting.Mode == proxyutil.ModeInherit:
		return app.AccountProxy{Mode: app.ProxyInherit}
	case setting.Mode == proxyutil.ModeDirect:
		return app.AccountProxy{Mode: app.ProxyDirect}
	default:
		shown := url.URL{Scheme: setting.URL.Scheme, Host: setting.URL.Host}

		return app.AccountProxy{Mode: app.ProxyCustom, URL: shown.String(), HasCredentials: setting.URL.User != nil}
	}
}

// setProxy puts value, a stored proxy, on auth where the executors read it
// and where the token store keeps it.
func setProxy(auth *coreauth.Auth, value string) {
	auth.ProxyURL = value

	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}

	if value == "" {
		delete(auth.Metadata, metadataProxy)

		return
	}

	auth.Metadata[metadataProxy] = value
}

// SetAccountProxy sets how account id's traffic leaves the gateway. The
// manager's copy changes first, so the next request goes the new way:
// executors read the proxy from the account on every request and nothing has
// to be re-registered. Then the credential is saved, so the choice survives a
// restart. Accounts the store never holds — config-derived API keys,
// runtime-only and plugin-virtual accounts — have nothing to save and come
// back from configuration. A failed save is reported like
// SetAccountDisabled's: the account keeps the new proxy in memory and a retry
// converges.
func (g *Gateway) SetAccountProxy(ctx context.Context, id string, p app.ProxyChoice) error {
	value, err := proxyValue(p)
	if err != nil {
		return err
	}

	g.pushMu.Lock()
	defer g.pushMu.Unlock()

	if g.coreAuth != nil && g.store == nil {
		return ErrNoTokenStore
	}

	_, auth, err := g.accountLocked(id)
	if err != nil {
		return err
	}

	setProxy(auth, value)

	updated, err := g.coreAuth.Update(ctx, auth)
	if err != nil {
		return fmt.Errorf("gateway: update account %q: %w", id, err)
	}

	if updated == nil {
		return fmt.Errorf("%w: %q", ErrUnknownAccount, id)
	}

	if err := g.saveLocked(ctx, updated); err != nil {
		return fmt.Errorf("gateway: account %q has its new proxy in memory, but its credential was not saved, "+
			"so a restart would restore the previous one (retry SetAccountProxy): %w", id, err)
	}

	return nil
}
