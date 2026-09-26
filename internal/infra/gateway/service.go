// Package gateway embeds the upstream CLIProxyAPI service as a library.
//
// Configuration is pushed in as a struct rather than read from a file: the
// watcher factory installed here captures the upstream reload callback and
// returns a nil watcher, so no file is ever watched or parsed. The management
// API is never enabled — no secret key, no local password, no environment
// secret is supplied, which is the condition upstream registers those routes on;
// a configuration carrying a secret key is refused, and New and Run refuse to
// proceed while an environment variable that would enable it is set. The
// management control panel (/management.html) is forced off on every
// configuration, so no request can make the server download it.
//
// Accounts change through the Gateway, never the core auth manager directly:
// the hollow watcher means upstream registers an account's models only when a
// configuration is applied, so every change is followed by re-applying the
// current configuration.
//
// Access is by user API token only, and only to classified routes. The policy
// gate (policyGate), first in the server's middleware, answers 404 for every
// route the routes table does not list, and applies the owner's policy, over
// the model catalogue (Catalog), to every model route. Behind it, the
// gateway's AccessProvider, backed by Params.Resolver, is the one provider
// upstream's access manager holds (see claimAccess). A configuration carrying
// api-keys or enabling plugins is refused, and websocket authentication is
// forced on.
package gateway

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/gate"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v7/sdk/access"
	sdkapi "github.com/router-for-me/CLIProxyAPI/v7/sdk/api"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyusage "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	sdklogging "github.com/router-for-me/CLIProxyAPI/v7/sdk/logging"
)

// Params configures a Gateway.
type Params struct {
	// Config is the initial configuration. Required.
	Config *cliproxyconfig.Config
	// ConfigPath is required by the upstream builder. It is never read as
	// configuration, because the watcher installed here owns config updates,
	// and nothing is written beside it: upstream resolved its request-log
	// directory from it, and New installs no request logger (noRequestLogger).
	ConfigPath string
	// Middleware is prepended to the embedded server's Gin stack.
	Middleware []gin.HandlerFunc
	// UsagePlugin receives upstream usage records.
	UsagePlugin cliproxyusage.Plugin
	// Cooldown is what NewCoreAuthManager returned alongside the manager.
	Cooldown coreauth.CooldownStateStore
	// CoreAuth is required in production too: Service exposes no getter, and
	// the account methods (AddAccount, SetAccountDisabled, RemoveAccount) act on
	// this manager. Without it they return ErrNoCoreAuth.
	CoreAuth *coreauth.Manager
	// Store is the token store CoreAuth persists to, the one NewCoreAuthManager
	// was given. AddAccount saves the account through it and loads it back
	// from it, SetAccountDisabled saves through it and RemoveAccount deletes
	// the account's credential from it; without it they return
	// ErrNoTokenStore.
	Store coreauth.Store
	// Resolver authenticates the API tokens proxied requests present, and
	// returns their owners' policies. Required: it backs the only access
	// provider that can admit a request, and the policy gate.
	Resolver Resolver
	// Observer is told what the policy gate refuses. Nil observes nothing.
	Observer gate.Observer
	// Log receives the policy gate's own failures. Nil discards them.
	Log *slog.Logger
}

// Gateway owns the embedded upstream service and the configuration pushed into it.
type Gateway struct {
	svc      *cliproxy.Service
	coreAuth *coreauth.Manager
	store    coreauth.Store
	// access is the upstream access manager the server authenticates with, and
	// provider the one provider it may hold (see claimAccess).
	access   *sdkaccess.Manager
	provider *AccessProvider
	// catalog is where the policy gate learns which providers serve a model.
	catalog *Catalog
	// engine is the embedded server's gin engine, set when Run builds the
	// server; tests walk its routes against the routes table.
	engine atomic.Pointer[gin.Engine]
	// authDir is the boot configuration's AuthDir made absolute: gateway/login
	// hands upstream's login handler a subdirectory of it for its callback files
	// (AuthDir). Credentials are wherever Store keeps them; the gateway never
	// resolves a path for one.
	authDir string

	// pushMu serialises configuration pushes and account changes, so current
	// always matches the last configuration upstream committed and an account
	// change cannot interleave with a push.
	pushMu sync.Mutex

	mu      sync.RWMutex
	current *cliproxyconfig.Config
	reload  func(*cliproxyconfig.Config)

	// ready is closed once the watcher factory has captured reload.
	ready     chan struct{}
	readyOnce sync.Once
	// done is closed when Run returns; runErr is its result.
	done   chan struct{}
	runErr error
	// drain lets Shutdown finish the requests in flight, which upstream's stop
	// cuts.
	drain requestDrain
}

// ErrNotRunning reports that the gateway cannot accept configuration: Run has
// not yet installed the watcher, or it has already returned.
var ErrNotRunning = errors.New("gateway: not running")

// ErrManagementSecret reports a configuration that would enable upstream's
// management API, which this service never exposes.
var ErrManagementSecret = errors.New("gateway: remote-management secret key must be empty")

// ErrManagementEnv reports that the process environment would enable
// upstream's management API regardless of configuration.
var ErrManagementEnv = errors.New("gateway: environment would enable the management API")

// ErrNoCoreAuth reports an account change on a gateway built without
// Params.CoreAuth.
var ErrNoCoreAuth = errors.New("gateway: no core auth manager was supplied")

// ErrUnknownAccount reports an account id the core auth manager does not hold.
// It is an app.ErrNotFound.
var ErrUnknownAccount = fmt.Errorf("gateway: unknown account: %w", app.ErrNotFound)

// ErrNoTokenStore reports an account change on a gateway built without
// Params.Store: the change could not be made durable, so the account would
// come back as it was on the next start.
var ErrNoTokenStore = errors.New("gateway: no token store was supplied")

// ErrNoResolver reports Params without a Resolver: no request could be
// authenticated, and upstream admits every request when it has no provider.
var ErrNoResolver = errors.New("gateway: no token resolver was supplied")

// ErrConfigAPIKeys reports a configuration carrying api-keys. A config key
// belongs to no user, so no per-user policy could apply to it: it would be a
// master key. Access is by user token only.
var ErrConfigAPIKeys = errors.New("gateway: config api-keys are refused; access is by user token only")

// ErrPlugins reports a configuration enabling upstream plugins. A plugin can
// register an access provider — even claim it exclusive — and models, so it
// could admit a request no user token authenticates.
var ErrPlugins = errors.New("gateway: plugins are refused")

// ErrHomeMode reports a configuration enabling upstream's home mode, which
// routes every request to an external dispatcher (provider "home") without
// consulting the model registry the policy gate decides by.
var ErrHomeMode = errors.New("gateway: home mode is refused")

// ErrCompatName reports an openai-compatibility entry going by the name of a
// built-in provider, whose grants would all cover it, or by no name a policy
// could grant.
var ErrCompatName = errors.New("gateway: openai-compatibility name is reserved for a built-in provider")

// errNilConfig reports a nil configuration handed to New or PushConfig.
var errNilConfig = errors.New("gateway: nil configuration")

// errNilAccount reports a nil account handed to AddAccount.
var errNilAccount = errors.New("gateway: nil account")

// errCredentialNotLoaded reports a saved credential the token store's List
// does not read back. AddAccount wraps it with the account it was adding.
var errCredentialNotLoaded = errors.New("the token store does not load the saved credential")

// managementEnv lists every environment variable the embedded upstream code
// reads to enable /v0/management. Upstream v7.3.18 reads exactly one:
// MANAGEMENT_PASSWORD, in internal/api/server.go NewServer (route registration
// on a non-blank value) and internal/api/handlers/management/handler.go
// NewHandler (accepted as the management secret). Both trim whitespace, so a
// blank value enables nothing.
var managementEnv = []string{"MANAGEMENT_PASSWORD"}

// checkManagementEnv refuses an environment that would enable management.
func checkManagementEnv() error {
	for _, name := range managementEnv {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			return fmt.Errorf("%w: %s is set; unset it", ErrManagementEnv, name)
		}
	}

	return nil
}

// admit rejects what upstream would silently drop, what would enable the
// management surface, what would authenticate a request as no user — config
// api-keys, and plugins, the only other way a provider enters upstream's
// access registry — and what would route a request past the policy gate's
// model check: home mode, and an openai-compatibility entry whose policy name
// is a built-in provider's or empty (compatNameRefused). It then forces the
// control panel off, websocket authentication on, and cooldown files and
// request logging off. Upstream refuses a config update whose credential
// weights are invalid (sdk/cliproxy/service_config.go commitConfigUpdate)
// without reporting it to the reload caller, so that check has to happen here.
//
// With DisableControlPanel unset, upstream serves GET /management.html and, on
// the first request, downloads the panel from GitHub
// (internal/api/server_management.go serveManagementControlPanel →
// managementasset.EnsureLatestManagementHTML): an outbound call any anonymous
// client can trigger. The flag makes that handler answer 404 before it looks
// for or fetches the asset.
//
// With WebsocketAuth unset, upstream serves GET /v1/ws with no authentication
// at all (internal/api/server_routes.go AttachWebsocketRoute): it is the
// websocket relay through which a connecting client registers itself as an
// "aistudio" provider account (sdk/cliproxy/service_auth.go wsOnConnected).
// Forced on, the route goes through the access provider like every other —
// behind the policy gate, which refuses it outright (see routes).
//
// With SaveCooldownStatus set, upstream persists cooldown state through the
// token store's cooldown store and, for a store that provides none — the
// credential store does not — through a file store it creates in the auth
// directory (sdk/cliproxy/service_auth.go:566-581 resolveCooldownStateStore).
// Forced off, cooldown lives in memory only.
//
// With RequestLog set, upstream's handlers buffer failed requests' error
// details and websocket timelines in memory for the request logger
// (sdk/api/handlers/handlers_errors.go LoggingAPIResponseError,
// openai/openai_responses_websocket.go); New installs none (noRequestLogger),
// so nothing would ever consume them.
//
// Every forced flag is set on cfg itself, as upstream's own home mode does
// (service_config.go forceHomeRuntimeConfig), because upstream keeps the
// pointer; each is written only when it differs from the forced value, so
// re-pushing the running configuration writes nothing upstream is reading.
func admit(cfg *cliproxyconfig.Config) error {
	if cfg == nil {
		return errNilConfig
	}

	if cfg.RemoteManagement.SecretKey != "" {
		return ErrManagementSecret
	}

	if len(cfg.APIKeys) > 0 {
		return ErrConfigAPIKeys
	}

	if cfg.Plugins.Enabled {
		return ErrPlugins
	}

	if cfg.Home.Enabled {
		return ErrHomeMode
	}

	for _, compat := range cfg.OpenAICompatibility {
		if compatNameRefused(compat.Name) {
			return fmt.Errorf("%w: %q", ErrCompatName, compat.Name)
		}
	}

	if err := cfg.ValidateCredentialWeights(); err != nil {
		return fmt.Errorf("gateway: invalid configuration: %w", err)
	}

	if !cfg.RemoteManagement.DisableControlPanel {
		cfg.RemoteManagement.DisableControlPanel = true
	}

	if !cfg.WebsocketAuth {
		cfg.WebsocketAuth = true
	}

	if cfg.SaveCooldownStatus {
		cfg.SaveCooldownStatus = false
	}

	if cfg.RequestLog {
		cfg.RequestLog = false
	}

	return nil
}

// New builds the embedded service. It does not start it; call Run. It refuses
// to build while an environment variable that enables upstream's management
// API is set (ErrManagementEnv), on a configuration admit refuses, without a
// Resolver (ErrNoResolver), and when upstream's
// model registry cannot say which providers serve a model (ErrModelRegistry).
// It installs the policy gate as the server's first middleware. Access is
// claimed for the built gateway's provider (see claimAccess) — again just
// before the server starts serving — and the provider is registered here,
// never in init.
func New(params Params) (*Gateway, error) {
	if err := checkManagementEnv(); err != nil {
		return nil, err
	}

	if err := admit(params.Config); err != nil {
		return nil, err
	}

	if params.Resolver == nil {
		return nil, ErrNoResolver
	}

	catalog, err := newCatalog(cliproxy.GlobalModelRegistry())
	if err != nil {
		return nil, err
	}

	gw := &Gateway{
		current:  params.Config,
		coreAuth: params.CoreAuth,
		store:    params.Store,
		access:   sdkaccess.NewManager(),
		provider: NewAccessProvider(params.Resolver),
		catalog:  catalog,
		ready:    make(chan struct{}),
		done:     make(chan struct{}),
	}
	if dir := strings.TrimSpace(params.Config.AuthDir); dir != "" {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return nil, fmt.Errorf("gateway: resolve auth directory: %w", err)
		}

		gw.authDir = abs
	}

	builder := cliproxy.NewBuilder().
		WithConfig(params.Config).
		WithConfigPath(params.ConfigPath).
		WithRequestAccessManager(gw.access).
		WithWatcherFactory(func(_, _ string, reload func(*cliproxyconfig.Config)) (*cliproxy.WatcherWrapper, error) {
			// OnBeforeStart already took the access manager back from Run's
			// refresh (service_plugins.go syncPluginRuntimeConfig); claim again
			// as the reload callback is handed over, before any push.
			accessMu.Lock()
			gw.claimAccess()
			accessMu.Unlock()
			gw.mu.Lock()
			gw.reload = reload
			gw.mu.Unlock()
			gw.readyOnce.Do(func() { close(gw.ready) })
			// Hollow watcher: no file, no fsnotify. Every upstream call site
			// guards against a nil wrapper, and every WatcherWrapper method
			// returns early on a nil receiver.
			//nolint:nilnil // The hollow watcher is deliberately a nil wrapper: every upstream call site guards against it.
			return nil, nil
		}).
		WithHooks(cliproxy.Hooks{
			// Run refreshes the access manager from the registry after
			// building the server (service_plugins.go syncPluginRuntimeConfig)
			// and serves before it creates the watcher; take it back first.
			OnBeforeStart: func(*cliproxyconfig.Config) {
				accessMu.Lock()
				gw.claimAccess()
				accessMu.Unlock()
			},
		}).
		WithServerOptions(
			sdkapi.WithEngineConfigurator(gw.configureEngine),
			sdkapi.WithMiddleware(policyGate(params.Resolver, catalog, params.Observer, params.Log)),
			sdkapi.WithRequestLoggerFactory(noRequestLogger),
		)
	if len(params.Middleware) > 0 {
		builder = builder.WithServerOptions(sdkapi.WithMiddleware(params.Middleware...))
	}

	if params.CoreAuth != nil {
		builder = builder.WithCoreAuthManager(params.CoreAuth)
		if params.Cooldown != nil {
			builder = builder.WithCooldownStateStore(params.Cooldown)
		}
	}

	accessMu.Lock()
	gw.claimAccess()

	svc, err := builder.Build()
	if err == nil {
		gw.claimAccess()
	}
	accessMu.Unlock()

	if err != nil {
		return nil, fmt.Errorf("gateway: build the service: %w", err)
	}

	if params.UsagePlugin != nil {
		svc.RegisterUsagePlugin(params.UsagePlugin)
	}

	gw.svc = svc

	return gw, nil
}

// noRequestLogger is the request logger factory New installs. It returns no
// logger, so upstream installs no request-logging middleware
// (internal/api/server.go NewServer). Upstream's own logger writes every
// request's URL, headers, body and vendor answer to files in its log
// directory — every failed one even with request-log off
// (internal/api/middleware/response_writer.go Finalize) — and no state of
// this process lives in files. No logger of this package could replace it:
// sdk/logging.RequestLogger aliases internal/logging's, whose LogRequest takes
// a type only upstream's internal packages name. Vendor errors are seen
// through the metrics, the usage ledger and the process log instead.
func noRequestLogger(*cliproxyconfig.Config, string) sdklogging.RequestLogger { return nil }

// NewCoreAuthManager builds the core auth manager for the boot configuration
// cfg over store, the way the upstream builder builds its own
// (sdk/cliproxy/builder.go:253-266): when store provides a cooldown store
// (coreauth.CooldownStateStoreProvider) it is returned, nil otherwise. The
// caller points store at its backend; the manager only persists to it. Pass
// store as Params.Store, the cooldown store as Params.Cooldown and cfg as
// Params.Config.
//
// The manager routes by cfg's routing settings from the start. Upstream's
// builder picks the selector from the configuration only for a manager it builds
// itself; for a supplied one it records no routing state, so without this the
// stored strategy would be inert until the first configuration push.
func NewCoreAuthManager(cfg *cliproxyconfig.Config, store coreauth.Store) (*coreauth.Manager, coreauth.CooldownStateStore) {
	var cooldown coreauth.CooldownStateStore
	if provider, ok := store.(coreauth.CooldownStateStoreProvider); ok {
		cooldown = provider.CooldownStateStore()
	}

	return coreauth.NewManager(store, routingSelector(cfg), nil), cooldown
}

// routingSelector is the selector upstream builds for cfg's routing settings
// (sdk/cliproxy/service_config.go normalizedRoutingRuntimeState and
// newRoutingSelector, both unexported in v7.3.18): the strategy by its accepted
// spellings, round-robin otherwise, wrapped in session affinity when that is on.
// Upstream replaces it with its own on the first configuration it applies.
func routingSelector(cfg *cliproxyconfig.Config) coreauth.Selector {
	routing := cfg.Routing

	var selector coreauth.Selector

	switch strings.ToLower(strings.TrimSpace(routing.Strategy)) {
	case "weighted-round-robin", "weightedroundrobin", "wrr":
		selector = &coreauth.WeightedRoundRobinSelector{}
	case "fill-first", "fillfirst", "ff":
		selector = &coreauth.FillFirstSelector{}
	default:
		selector = &coreauth.RoundRobinSelector{}
	}

	if !routing.SessionAffinity {
		return selector
	}

	ttl := time.Hour

	if raw := strings.TrimSpace(routing.SessionAffinityTTL); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			ttl = max(parsed, time.Second)
		}
	}

	subagents := true
	if routing.SessionAffinitySubagents != nil {
		subagents = *routing.SessionAffinitySubagents
	}

	return coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{
		Fallback:         selector,
		TTL:              ttl,
		SubagentAffinity: &subagents,
	})
}

// Run starts the service and blocks until ctx is cancelled or the server stops.
// It shuts the embedded service down before returning. Call it once. To drain
// in-flight requests, stop it with Shutdown rather than by cancelling ctx.
//
// It repeats New's environment check: upstream reads MANAGEMENT_PASSWORD when
// Run builds the HTTP server, not when New builds the service.
func (g *Gateway) Run(ctx context.Context) error {
	err := checkManagementEnv()
	if err == nil {
		if err = g.svc.Run(ctx); err != nil {
			err = fmt.Errorf("gateway: run the service: %w", err)
		}
	}

	g.runErr = err
	close(g.done)

	return err
}

// Shutdown stops the proxied listener: from the call on it refuses new
// requests (503), waits until ctx ends for the requests in flight to finish
// (requestDrain), and stops the service, which closes the listener and every
// connection; Run then returns nil. Upstream's own stop, which cancelling
// Run's ctx runs instead, closes every connection at once (v7.3.17 on,
// internal/api/server.go Stop), so it drains nothing. When ctx ends first,
// the service is stopped all the same and the error says so.
//
// Upstream's Shutdown runs once (shutdownOnce) and Run's deferred call waits
// for this one to finish. Shutdown first waits for Run to have built the server
// (WaitReload): before that there is nothing to drain, and upstream would read
// the server while Run writes it. If Run has already returned, it has shut the
// service down itself and Shutdown returns nil.
func (g *Gateway) Shutdown(ctx context.Context) error {
	if err := g.WaitReload(ctx); err != nil {
		select {
		case <-g.done:
			return nil
		default:
			return err
		}
	}

	drained := g.drain.wait(ctx)
	if err := g.svc.Shutdown(ctx); err != nil {
		//nolint:wrapcheck // joins the drain's error and the stop's, each already wrapped
		return errors.Join(drained, fmt.Errorf("gateway: shut the service down: %w", err))
	}

	return drained
}

// PushConfig applies a configuration built from the database. It returns
// ErrNotRunning unless Run has installed the watcher and not yet returned (see
// WaitReload), and refuses a configuration upstream would reject, one that
// would enable the management API and one carrying api-keys. On error the
// running configuration and CurrentConfig are unchanged. An accepted cfg has
// its control panel forced off, websocket authentication forced on, and
// cooldown files and request logging forced off (admit).
func (g *Gateway) PushConfig(cfg *cliproxyconfig.Config) error {
	if err := admit(cfg); err != nil {
		return err
	}

	g.pushMu.Lock()
	defer g.pushMu.Unlock()

	reload, err := g.reloadLocked()
	if err != nil {
		return err
	}

	g.apply(reload, cfg)
	g.mu.Lock()
	g.current = cfg
	g.mu.Unlock()

	return nil
}

// AddAccount saves auth through the token store, loads it back from what was
// saved, registers that with the core auth manager and re-applies the current
// configuration, so its models become routable. It returns what the manager
// stored. Like PushConfig it needs a running service (ErrNotRunning), and like
// the other account changes a token store (ErrNoTokenStore).
//
// The account held is the one a restart would load: the store's List reads
// the saved credential the way boot does, so its id is the credential's key,
// Metadata carries everything the credential holds, and Label, Status,
// Disabled and the source attributes are set as on load. A login record keeps
// its tokens only in Storage, which Save serializes into the credential
// (upstream/internal/api/handlers/management/auth_files_fields.go
// saveTokenRecord does the same); the executors read them from Metadata, so
// registering the record itself would send requests without a credential.
// Accounts the store never holds — config-derived API keys, runtime-only and
// plugin-virtual accounts — are registered as given.
//
// The credential's key is the account's file name, else its id
// (credentialKey), so a re-login of the same account overwrites its
// credential. An account with neither gets a UUID id, as Register would give
// it.
//
// The save carries creation intent (coreauth.WithAuthCreationIntent): a token
// store creates no credential for a save without it — the credential store
// none at all (CredentialStore.Save), upstream's file store none for a
// disabled account (sdk/auth/filestore.go Save) — so the account would vanish
// on restart.
//
// An account is either added and durable or not routable. If the save fails,
// nothing is registered and the manager is left as it was. If the saved
// account cannot be loaded back or registered, the credential is withdrawn
// again — deleted, and an account the manager already held under that key
// withdrawn with it (RemoveAccount's steps), since its credential is the one
// just overwritten — and the error returned. If the withdrawal fails as well,
// the error says so.
func (g *Gateway) AddAccount(ctx context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	if auth == nil {
		return nil, errNilAccount
	}

	g.pushMu.Lock()
	defer g.pushMu.Unlock()

	if g.coreAuth == nil {
		return nil, ErrNoCoreAuth
	}

	if g.store == nil {
		return nil, ErrNoTokenStore
	}

	reload, err := g.reloadLocked()
	if err != nil {
		return nil, err
	}

	if auth.Storage != nil && auth.Metadata == nil {
		auth.Metadata = make(map[string]any) // as Save does
	}

	if !storeHolds(auth) {
		stored, err := g.coreAuth.Register(ctx, auth)
		if err != nil {
			return nil, fmt.Errorf("gateway: register account: %w", err)
		}

		g.reapplyLocked(reload)

		return stored, nil
	}

	key := credentialKey(auth)
	if key == "" {
		auth.ID = uuid.NewString()
		key = auth.ID
	}

	if _, err := g.store.Save(coreauth.WithAuthCreationIntent(ctx), auth); err != nil {
		return nil, fmt.Errorf("gateway: account %q was not saved: %w", auth.ID, err)
	}

	stored, err := g.loadLocked(ctx, key)
	if err == nil {
		stored, err = g.coreAuth.Register(ctx, stored)
	}

	if err != nil {
		if errWithdraw := g.withdrawLocked(ctx, reload, key); errWithdraw != nil {
			return nil, fmt.Errorf("gateway: account %q was saved but not added, "+
				"and its credential %q could not be withdrawn (retry RemoveAccount): %w",
				auth.ID, key, errors.Join(err, errWithdraw))
		}

		return nil, fmt.Errorf("gateway: account %q was saved but not added, so its credential was withdrawn: %w", auth.ID, err)
	}

	g.reapplyLocked(reload)

	return stored, nil
}

// SetAccountDisabled disables or re-enables account id and re-applies the
// current configuration, which unregisters or restores its models. The state is
// recorded the way upstream's own management API records it (Disabled, Status
// and the persisted "disabled" metadata) and saved through the token store, so
// it survives a restart; the manager's own save ignores errors
// (conductor_lifecycle.go updateInternal). Accounts the store never holds —
// config-derived API keys, runtime-only and plugin-virtual accounts — have
// nothing to save and come back from configuration.
//
// If the save fails, the error says so and the account keeps the requested
// state in memory: a failed write may have left the stored credential in
// either state, so rolling back could not restore agreement with the store,
// and rolling back a disable would put a credential the caller is withdrawing
// back into rotation. A retry converges.
func (g *Gateway) SetAccountDisabled(ctx context.Context, id string, disabled bool) error {
	g.pushMu.Lock()
	defer g.pushMu.Unlock()

	if g.coreAuth != nil && g.store == nil {
		return ErrNoTokenStore
	}

	reload, auth, err := g.accountLocked(id)
	if err != nil {
		return err
	}

	updated, err := g.setDisabledLocked(ctx, auth, disabled)
	if err != nil {
		return err
	}

	g.reapplyLocked(reload)

	if err := g.saveLocked(ctx, updated); err != nil {
		return fmt.Errorf("gateway: account %q is disabled=%t in memory, but its credential was not saved, "+
			"so a restart would restore the previous state (retry SetAccountDisabled): %w", id, disabled, err)
	}

	return nil
}

// RemoveAccount removes account id and deletes its stored credential, so it
// does not come back on the next start. A bare Remove leaves its models
// registered — upstream only unregisters an account it still holds as disabled
// — so the account is disabled and the configuration re-applied first.
//
// Order: disable, re-apply, delete from the store, then remove from memory.
// Upstream's own management API deletes the credential before removing the
// account (internal/api/handlers/management/auth_files_crud.go
// DeleteAuthFile). Remove cannot fail once the account is held, so the only
// partial failure is the store delete: the account is then left disabled,
// unroutable and still held, and a RemoveAccount retry can finish the job.
// The credential is then saved marked disabled; if that save fails too, the
// error reports both, because the stored credential may still say enabled.
// Removing from memory first would instead strand the credential where no
// gateway call can reach it until a restart revives it. A deleted credential
// is not written back by the manager's own saves (a refresh, a cooldown):
// they carry no creation intent, and the token store creates nothing without
// it (CredentialStore.Save).
func (g *Gateway) RemoveAccount(ctx context.Context, id string) error {
	g.pushMu.Lock()
	defer g.pushMu.Unlock()

	if g.coreAuth != nil && g.store == nil {
		return ErrNoTokenStore
	}

	reload, auth, err := g.accountLocked(id)
	if err != nil {
		return err
	}

	return g.removeLocked(ctx, reload, auth)
}

// Accounts lists the accounts the core auth manager holds, ordered by
// provider and id, as the admin API shows them: under policy provider names,
// with no credential material. Nil without a manager.
func (g *Gateway) Accounts() []app.VendorAccount {
	if g.coreAuth == nil {
		return nil
	}

	held := g.coreAuth.List()

	out := make([]app.VendorAccount, 0, len(held))
	for _, auth := range held {
		out = append(out, VendorAccount(auth))
	}

	slices.SortFunc(out, func(a, b app.VendorAccount) int {
		return cmp.Or(cmp.Compare(a.Provider, b.Provider), cmp.Compare(a.ID, b.ID))
	})

	return out
}

// VendorAccount is auth as the admin API shows it, for Accounts and
// gateway/login. Email is the one metadata field read; tokens, attributes and
// storage never leave the gateway.
func VendorAccount(auth *coreauth.Auth) app.VendorAccount {
	account := app.VendorAccount{
		ID:              auth.ID,
		Provider:        PolicyProvider(auth.Provider),
		Label:           auth.Label,
		Status:          string(auth.Status),
		Disabled:        auth.Disabled,
		LastRefreshedAt: lastRefreshed(auth),
	}
	if email, ok := auth.Metadata["email"].(string); ok {
		account.Email = email
	}

	if auth.LastError != nil {
		account.LastError = auth.LastError.Message
	}

	return account
}

// lastRefreshed is when the account's credential was last refreshed. The
// manager sets LastRefreshedAt only when it refreshes the credential in this
// process (sdk/cliproxy/auth/conductor_refresh.go), so an account loaded from
// the token store at boot shows zero until its next refresh, while the stored
// credential records the last refresh as metadata "last_refresh" — the key
// upstream itself reads first (conductor_refresh.go authLastRefreshTimestamp).
// A value that is not an RFC 3339 time is treated as absent.
func lastRefreshed(auth *coreauth.Auth) time.Time {
	if !auth.LastRefreshedAt.IsZero() {
		return auth.LastRefreshedAt
	}

	raw, ok := auth.Metadata["last_refresh"].(string)
	if !ok {
		return time.Time{}
	}

	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(raw))
	if err != nil {
		return time.Time{}
	}

	return t
}

// storeHolds reports whether the token store holds auth: upstream's
// Manager.persist skips the rest (conductor_lifecycle.go persist).
func storeHolds(auth *coreauth.Auth) bool {
	return !coreauth.IsConfigAPIKeyAuth(auth) && !coreauth.IsPluginVirtualAuth(auth) && auth.Metadata != nil &&
		!strings.EqualFold(strings.TrimSpace(auth.Attributes["runtime_only"]), "true")
}

// Catalog is the model catalogue the policy gate decides by, for the admin
// screens (app.ModelCatalog) to read the same source.
func (g *Gateway) Catalog() *Catalog { return g.catalog }

// AuthDir is the boot configuration's auth directory made absolute;
// gateway/login gives upstream's login handler a subdirectory of it.
func (g *Gateway) AuthDir() string { return g.authDir }

// CoreAuthManager is the manager account changes act on; gateway/login hands
// it to upstream's login handler. Accounts still change only through Gateway.
func (g *Gateway) CoreAuthManager() *coreauth.Manager { return g.coreAuth }

// CurrentConfig returns the most recently pushed configuration.
func (g *Gateway) CurrentConfig() *cliproxyconfig.Config {
	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.current
}

// WaitReload blocks until the service has created its watcher and the reload
// callback has been captured, so PushConfig and the account methods stop
// returning ErrNotRunning. If Run returns first — upstream bails out before the
// watcher on an unusable auth directory or a provider load error — WaitReload
// returns Run's error instead of waiting for ctx.
//
// It does not make a push race-free. Upstream creates the watcher
// (sdk/cliproxy/service_lifecycle.go:187) before Run finishes booting: it then
// registers models for every account it holds (syncPluginModelRuntime, :205),
// and those registration workers read the service configuration without its
// lock, while a push writes it under the lock. Nothing on the SDK surface
// reports that boot has finished. The contract is therefore: production builds
// the boot configuration before New, and neither pushes nor changes accounts
// immediately after boot.
func (g *Gateway) WaitReload(ctx context.Context) error {
	select {
	case <-g.ready:
		return nil
	case <-g.done:
		select {
		case <-g.ready:
			return nil
		default:
		}

		if g.runErr != nil {
			return fmt.Errorf("gateway: stopped before the watcher was installed: %w", g.runErr)
		}

		return fmt.Errorf("gateway: stopped before the watcher was installed: %w", ErrNotRunning)
	case <-ctx.Done():
		return fmt.Errorf("gateway: wait for the watcher: %w", ctx.Err())
	}
}

// claimAccess makes g's provider the only one g's access manager holds.
//
// Upstream's access manager admits every request when it holds no provider
// (sdk/access/manager.go Authenticate), and whenever upstream refreshes it —
// in Build, in Run, and on every configuration application — it copies
// upstream's process-global registry (sdkaccess.RegisteredProviders). Each of
// those refreshes first calls the plugin host's RegisterFrontendAuthProviders
// (internal/pluginhost/adapters_auth.go), which clears the registry's
// exclusive provider unless a plugin claims it, so a SetExclusiveProvider made
// once does not last. claimAccess therefore re-registers g's provider, makes
// it exclusive and reloads g's manager from the registry, and g calls it
// before Build, after Build, just before Run starts the server (OnBeforeStart),
// when Run hands over the reload callback, and before and after every
// configuration it applies. Anything else registered —
// a plugin's provider, upstream's config-api-key provider — is then never in
// the manager g's server authenticates with outside those upstream steps.
//
// The registry is process-global. Registering under a fixed key replaces the
// previous instance, so the gateway built last owns the registry until
// another gateway claims it again; each gateway only reloads its own manager,
// and claims before and after each upstream step that reads the registry for
// it, so repeated New calls in one process each authenticate with their own
// resolver. The caller holds accessMu.
func (g *Gateway) claimAccess() {
	sdkaccess.RegisterProvider(accessProviderType, g.provider)
	sdkaccess.SetExclusiveProvider(accessProviderType)
	g.access.SetProviders(sdkaccess.RegisteredProviders())
}

// apply runs reload(cfg) with g's access claimed on both sides of it.
func (g *Gateway) apply(reload func(*cliproxyconfig.Config), cfg *cliproxyconfig.Config) {
	accessMu.Lock()
	defer accessMu.Unlock()

	g.claimAccess()
	reload(cfg)
	g.claimAccess()
}

// configureEngine is applied to the embedded server's gin engine before
// upstream adds its middleware and routes. It turns off gin's trailing-slash
// and fixed-path redirects, which answer a path that is a slash or a letter
// case away from a registered route with a redirect to it before any
// middleware runs: every route would be told apart from an unrouted path, the
// ones the policy gate refuses included. Unmatched, such a path now reaches
// the gate and gets its 404. It installs the drain (requestDrain) ahead of
// everything, so it counts each request whole, and readDeadlineControl ahead
// of upstream's middleware, which wraps the response writer.
func (g *Gateway) configureEngine(e *gin.Engine) {
	e.RedirectTrailingSlash = false
	e.RedirectFixedPath = false
	e.Use(g.drain.track(), readDeadlineControl())
	g.engine.Store(e)
}

// reloadLocked returns upstream's reload callback, or ErrNotRunning unless Run
// has installed the watcher and not yet returned. The caller holds pushMu.
func (g *Gateway) reloadLocked() (func(*cliproxyconfig.Config), error) {
	select {
	case <-g.done:
		return nil, ErrNotRunning
	default:
	}

	g.mu.RLock()
	reload := g.reload
	g.mu.RUnlock()

	if reload == nil {
		return nil, ErrNotRunning
	}

	return reload, nil
}

// accountLocked checks what every account change needs: a manager, a running
// service, and — for an existing account — that the manager holds id. The
// caller holds pushMu. Checking before mutating keeps a refused change from
// leaving the manager and the model registry out of step.
func (g *Gateway) accountLocked(id string) (func(*cliproxyconfig.Config), *coreauth.Auth, error) {
	if g.coreAuth == nil {
		return nil, nil, ErrNoCoreAuth
	}

	reload, err := g.reloadLocked()
	if err != nil {
		return nil, nil, err
	}

	auth, ok := g.coreAuth.GetByID(id)
	if !ok {
		return nil, nil, fmt.Errorf("%w: %q", ErrUnknownAccount, id)
	}

	return reload, auth, nil
}

// reapplyLocked re-applies the current configuration. Upstream's config
// application re-registers executors and models for every account the manager
// holds (sdk/cliproxy/service_config.go applyConfigRuntime →
// service_plugins.go syncPluginModelRuntime) and unregisters the models of a
// disabled one; nothing else does so under the hollow watcher, which drops the
// account update queue upstream would otherwise use. The caller holds pushMu.
func (g *Gateway) reapplyLocked(reload func(*cliproxyconfig.Config)) {
	g.apply(reload, g.CurrentConfig())
}

// loadLocked returns the account the token store loads under key, as boot
// loads it: the first listed record whose id is key. The caller holds pushMu.
func (g *Gateway) loadLocked(ctx context.Context, key string) (*coreauth.Auth, error) {
	listed, err := g.store.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list the token store: %w", err)
	}

	for _, auth := range listed {
		if auth.ID == key {
			return auth, nil
		}
	}

	return nil, fmt.Errorf("%w %q", errCredentialNotLoaded, key)
}

// withdrawLocked undoes a save AddAccount could not complete: an account the
// manager holds under key is removed with RemoveAccount's steps, since the
// save overwrote its credential; otherwise the credential is deleted. The
// caller holds pushMu.
func (g *Gateway) withdrawLocked(ctx context.Context, reload func(*cliproxyconfig.Config), key string) error {
	for _, held := range g.coreAuth.List() {
		if credentialKey(held) == key {
			return g.removeLocked(ctx, reload, held)
		}
	}

	if err := g.store.Delete(ctx, key); err != nil {
		return fmt.Errorf("gateway: delete credential %q: %w", key, err)
	}

	return nil
}

// removeLocked is RemoveAccount on an account the manager holds. The caller
// holds pushMu.
func (g *Gateway) removeLocked(ctx context.Context, reload func(*cliproxyconfig.Config), auth *coreauth.Auth) error {
	id := auth.ID
	key := credentialKey(auth)

	updated, err := g.setDisabledLocked(ctx, auth, true)
	if err != nil {
		return err
	}

	g.reapplyLocked(reload)

	if err := g.store.Delete(ctx, key); err != nil {
		if errSave := g.saveLocked(ctx, updated); errSave != nil {
			return fmt.Errorf("gateway: account %q is disabled but still held, its credential %q was not deleted "+
				"and may not be marked disabled in the store (retry RemoveAccount): %w", id, key, errors.Join(err, errSave))
		}

		return fmt.Errorf("gateway: account %q is disabled but still held, "+
			"and its credential %q was not deleted (retry RemoveAccount): %w", id, key, err)
	}

	g.coreAuth.Remove(ctx, id)

	return nil
}

// saveLocked writes auth through the token store and returns the error the
// manager's own save discards. It skips accounts the store never holds
// (storeHolds). The caller holds pushMu.
func (g *Gateway) saveLocked(ctx context.Context, auth *coreauth.Auth) error {
	if !storeHolds(auth) {
		return nil
	}

	if _, err := g.store.Save(ctx, auth); err != nil {
		return fmt.Errorf("gateway: save account %q: %w", auth.ID, err)
	}

	return nil
}

// setDisabledLocked mirrors upstream's management applyAuthDisabledState
// (internal/api/handlers/management/auth_files_fields.go) and returns what the
// manager stored. The caller holds pushMu.
func (g *Gateway) setDisabledLocked(ctx context.Context, auth *coreauth.Auth, disabled bool) (*coreauth.Auth, error) {
	auth.Disabled = disabled
	if disabled {
		auth.Status = coreauth.StatusDisabled
		auth.StatusMessage = "disabled via gateway"
	} else {
		auth.Status = coreauth.StatusActive
		auth.StatusMessage = ""
	}

	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}

	auth.Metadata["disabled"] = disabled

	updated, err := g.coreAuth.Update(ctx, auth)
	if err != nil {
		return nil, fmt.Errorf("gateway: update account %q: %w", auth.ID, err)
	}

	if updated == nil {
		// Update reports an id it does not hold with (nil, nil); pushMu keeps
		// the gateway's own changes out, so only a direct manager caller can
		// have removed it since accountLocked.
		return nil, fmt.Errorf("%w: %q", ErrUnknownAccount, auth.ID)
	}

	return updated, nil
}
