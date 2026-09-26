// Package boot is the composition root: it turns the environment, the database and
// every service into one process serving three listeners, and stops it in order.
// cmd/gateway calls Run to serve, and the end-to-end test calls the same Run; its
// reset-password subcommand calls ResetPassword, which builds only what it needs.
package boot

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/adminusers"
	"github.com/elleqt/llm-proxy-backend/internal/app/auth"
	"github.com/elleqt/llm-proxy-backend/internal/app/models"
	appprices "github.com/elleqt/llm-proxy-backend/internal/app/prices"
	"github.com/elleqt/llm-proxy-backend/internal/app/providers"
	appsettings "github.com/elleqt/llm-proxy-backend/internal/app/settings"
	apptokens "github.com/elleqt/llm-proxy-backend/internal/app/tokens"
	appusage "github.com/elleqt/llm-proxy-backend/internal/app/usage"
	"github.com/elleqt/llm-proxy-backend/internal/config"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	webapi "github.com/elleqt/llm-proxy-backend/internal/iface/http"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/login"
	gwusage "github.com/elleqt/llm-proxy-backend/internal/infra/gateway/usage"
	"github.com/elleqt/llm-proxy-backend/internal/infra/metrics"
	"github.com/elleqt/llm-proxy-backend/internal/infra/oidc"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
	pgactivity "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/activity"
	pgaudit "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/audit"
	pgidentities "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/identities"
	pgloginattempts "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/loginattempts"
	pgpasswords "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/passwords"
	pgprices "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/prices"
	pgsessions "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/sessions"
	pgsettings "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/settings"
	pgtokens "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/tokens"
	pgusage "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/usage"
	pgusers "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/users"
	pgvendorcreds "github.com/elleqt/llm-proxy-backend/internal/infra/postgres/vendorcreds"
	"github.com/elleqt/llm-proxy-backend/internal/infra/pricecatalog"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

// Options is what the process takes from outside its environment variables.
type Options struct {
	// Output receives the process log, upstream's logrus records included, and the
	// bootstrap administrator's one-time password banner, which bypasses the
	// logger. The command passes os.Stderr. Required.
	Output io.Writer
	// Version labels every log record and llmproxy_build_info; empty takes it from
	// the binary's build information (resolveVersion).
	Version string
	// Compatibility declares openai-compatibility vendors in the boot
	// configuration: boot-only credentials, which a configuration push cannot add
	// and no environment variable sets, so the command passes none. The end-to-end
	// test declares its wire-level fake vendors here.
	Compatibility []cliproxyconfig.OpenAICompatibility
}

// Sign-in throttling: this many failed attempts per address within the window
// lock the address for the window.
const (
	signInFailures = 5
	signInLockout  = 15 * time.Minute
)

// Shutdown deadlines, each counted from the signal; the container's stop grace
// period must cover the longest plus sinkGrace.
const (
	// drainGrace bounds in-flight proxied requests, streams included.
	drainGrace = 30 * time.Second
	// listenerGrace bounds in-flight requests on the web and metrics listeners.
	listenerGrace = 10 * time.Second
	// sinkGrace bounds writing the usage records still queued to the ledger.
	sinkGrace = 5 * time.Second
)

// Run boots the process and serves until SIGTERM, SIGINT or the end of ctx, then
// stops it in order and returns nil. A failure to start is returned at once; a
// listener failing while serving is returned after the same orderly stop. Once
// the stop has begun, a second SIGTERM or SIGINT is no longer caught: it ends the
// process at once, as the signal does by default.
//
// Boot order: configuration and the process log, migrations, the pool,
// repositories and the one password hasher, the bootstrap administrator, the
// upstream boot configuration from the database, metrics, the price list and the
// usage sink, the vendor credential store, the gateway, then the three listeners
// and the price catalog's checks, and once the gateway runs, the model catalogue
// updaters unless LLMPROXY_MODEL_CATALOG_UPDATES is off.
// Nothing pushes a configuration or changes an account after boot: the first
// change is an administrator's.
func Run(ctx context.Context, opts Options) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, os.Interrupt)
	defer stop()
	// A configuration error is returned, not logged: the log format is part of
	// the configuration.
	cfg, err := config.Load()
	if err != nil {
		return err //nolint:wrapcheck // config errors name their package, and CI pins the startup message's text
	}

	version := resolveVersion(opts.Version)
	h := newLogHandler(opts.Output, cfg.LogFormat, version)
	logger := slog.New(h.WithAttrs([]slog.Attr{slog.String("component", componentOwn)}))
	routeLogrus(h)

	// Neither error carries the DSN (see postgres.report).
	if err := postgres.Migrate(ctx, cfg.DatabaseURL); err != nil {
		return fmt.Errorf("database migration: %w", err)
	}

	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer pool.Close()

	logger.Info("database migrated and connected")

	proc, err := build(ctx, cfg, opts, version, pool, logger)
	if err != nil {
		return err
	}

	return proc.serve(ctx, stop)
}

// process is the built service, ready to serve.
type process struct {
	log     *slog.Logger
	gateway *gateway.Gateway
	// apiAddr is where the gateway serves the proxied API.
	apiAddr string
	// catalogUpdates starts upstream's model catalogue updaters once the gateway
	// runs (LLMPROXY_MODEL_CATALOG_UPDATES).
	catalogUpdates bool
	sink           *gwusage.Sink
	// prices checks the price catalog every catalogInterval while serving.
	prices          *appprices.Service
	catalogInterval time.Duration
	// web is nil when LLMPROXY_WEB_ADDR is off.
	web     *http.Server
	metrics *http.Server
}

// build wires the services. version is the resolved build version, and logger
// the process's own (component llmproxy).
//
//nolint:funlen // one linear wiring sequence in boot order; splitting it would only scatter that order
func build(ctx context.Context, cfg config.Config, opts Options, version string, pool *pgxpool.Pool,
	logger *slog.Logger,
) (*process, error) {
	users, passwords := pgusers.New(pool), pgpasswords.New(pool)
	tokens, sessions := pgtokens.New(pool), pgsessions.New(pool)
	audit, usage := pgaudit.New(pool), pgusage.New(pool)
	settings := pgsettings.New(pool)
	clock, logs := systemClock{}, processLog{logger}
	// One hasher, so LLMPROXY_PASSWORD_HASH_CONCURRENCY bounds every derivation in
	// the process: sign-in, bootstrap and administrators' resets alike.
	hasher := app.NewPasswordHasher(cfg.PasswordHashConcurrency, identity.HashPassword, identity.VerifyPassword)

	if err := bootstrapAdmin(ctx, cfg, opts.Output, users, passwords, hasher, logs); err != nil {
		return nil, err
	}

	bootCfg, err := appsettings.LoadBootConfig(ctx, settings, ownedConfig(cfg, opts.Compatibility), logs)
	if err != nil {
		return nil, fmt.Errorf("boot configuration: %w", err)
	}

	registry := prometheus.NewRegistry()
	prices := &app.PriceTable{}

	var gw *gateway.Gateway

	meters := metrics.New(registry,
		metrics.WithClock(clock),
		metrics.WithVersion(version),
		// gw is set below, before anything is served.
		metrics.WithKnownModel(func(model string) (string, bool) { return gw.Catalog().KnownModel(model) }),
	)
	//nolint:contextcheck // the sink's goroutine lives until Drain, not for a boot context
	sink := gwusage.New(usage, tokens, users, prices, meters, clock, logs)

	registerSinkCounters(registry, sink)
	// A nil source (LLMPROXY_PRICES_CATALOG_URL=off) leaves the manual prices alone
	// in force; the catalog's first check runs as serving starts.
	var catalogSource app.PriceCatalogSource
	if cfg.PriceCatalog.Enabled() {
		catalogSource = pricecatalog.New(cfg.PriceCatalog.URL, version)
	}

	priceList := appprices.New(pgprices.New(pool), pgprices.NewCatalogRepo(pool), catalogSource,
		prices, meters, audit, clock, logs)
	if err := priceList.Load(ctx); err != nil {
		return nil, fmt.Errorf("prices: %w", err)
	}

	// The vendor accounts' credentials live in the database, sealed under
	// LLMPROXY_CREDENTIALS_KEY. The store is registered process-wide before the
	// gateway exists, so upstream code that asks sdkauth.GetTokenStore gets it,
	// never a file store it would create on the spot. It provides no cooldown
	// store: cooldown stays in memory.
	sealer, err := credentials.NewSealer([]byte(cfg.CredentialsKey))
	if err != nil {
		return nil, fmt.Errorf("vendor credentials: %w", err)
	}

	// The shipped compose files start as downloaded, placeholder key included. That
	// key is public, so say so on every start until it is replaced.
	if cfg.CredentialsKeyIsPlaceholder() {
		//nolint:contextcheck // the process log is not request-scoped and logs under no context
		logs.Warn("LLMPROXY_CREDENTIALS_KEY is the compose files' public placeholder: anyone with a copy of the " +
			"database can read the vendor accounts' credentials. Set a random key (openssl rand -hex 32), " +
			"best before adding vendor accounts: those added under the placeholder must be signed in again")
	}

	vendorCredentials := pgvendorcreds.New(pool)

	store, err := gateway.NewCredentialStore(vendorCredentials, sealer, clock, "")
	if err != nil {
		return nil, fmt.Errorf("vendor credentials: %w", err)
	}

	// COMPAT(credentials-import): the one-shot import of the previous release's credential files; remove next release (RELEASING.md).
	if err := gateway.ImportFileCredentials(ctx, bootCfg.AuthDir, vendorCredentials, sealer, clock, logs); err != nil {
		return nil, fmt.Errorf("vendor credentials: %w", err)
	}

	sdkauth.RegisterTokenStore(store)

	// Upstream loads the store itself but only warns when that fails, so a wrong
	// LLMPROXY_CREDENTIALS_KEY would serve with no vendor accounts. One List here
	// stops the boot instead, naming the account the key cannot open.
	if _, err := store.List(ctx); err != nil {
		return nil, fmt.Errorf("vendor credentials: %w", err)
	}

	manager, cooldown := gateway.NewCoreAuthManager(bootCfg, store)

	//nolint:contextcheck // handlers take each request's context; construction serves nothing yet
	gw, err = gateway.New(gateway.Params{
		Config: bootCfg,
		// Required by upstream; no file is created or read there, and no log
		// directory is resolved from it: the gateway installs no request logger.
		ConfigPath:  filepath.Join(cfg.RuntimeDir, "config.yaml"),
		UsagePlugin: sink,
		CoreAuth:    manager,
		Store:       store,
		Cooldown:    cooldown,
		Resolver:    app.NewTokenResolver(users, tokens),
		// The gate's 401s and refusals are counted, a denial under its owner.
		Observer: gateMetrics{meters},
		Log:      logger,
	})
	if err != nil {
		return nil, fmt.Errorf("gateway: %w", err)
	}

	proc := &process{
		log:             logger,
		gateway:         gw,
		apiAddr:         cfg.ListenAddr,
		catalogUpdates:  cfg.ModelCatalogUpdates,
		sink:            sink,
		prices:          priceList,
		catalogInterval: cfg.PriceCatalog.Interval,
		metrics:         metricsServer(cfg.MetricsAddr, meters.Handler()),
	}
	if !cfg.Web.Enabled() {
		return proc, nil
	}

	idents := pgidentities.New(pool)

	oidcService, err := newOIDCService(ctx, cfg.OIDC, users, idents, sessions, audit, clock)
	if err != nil {
		return nil, err
	}

	tokenService := apptokens.New(users, tokens, audit, clock, logs)

	logins, err := login.New(gw)
	if err != nil {
		return nil, fmt.Errorf("vendor logins: %w", err)
	}

	router, err := webapi.NewRouter(webapi.Deps{
		Auth: auth.New(users, passwords,
			auth.NewThrottle(pgloginattempts.New(pool), signInFailures, signInLockout, clock),
			hasher, sessions, audit, clock),
		Tokens:          tokenService,
		OIDC:            oidcService,
		OIDCDisplayName: cfg.OIDC.DisplayName,
		LocalLogin:      cfg.Web.LocalLogin,
		Usage:           appusage.New(usage),
		Models:          models.New(gw.Catalog()),
		AdminUsers: adminusers.New(users, passwords, idents, sessions, pgactivity.New(pool),
			tokenService, hasher, audit, clock, gw.Catalog(), adminusers.Config{
				OIDCIssuer:             cfg.OIDC.Issuer,
				GroupMappingConfigured: len(cfg.OIDC.GroupPolicy) > 0,
			}),
		Settings: appsettings.New(settings, gw, audit, clock),
		Prices:   priceList,
		// Removing an account forgets its quota snapshot in the sink and its
		// series in these metrics (providers.Service.Remove).
		Providers:    providers.New(gw, logins, sink, meters, audit, clock, logs),
		Clock:        clock,
		Log:          logs,
		PublicAPIURL: cfg.Web.PublicAPIURL,
		CookieSecure: cfg.Web.CookieSecure,
		SessionKey:   cfg.Web.SessionKey,
	})
	if err != nil {
		return nil, fmt.Errorf("web API: %w", err)
	}

	proc.web = webapi.NewServer(cfg.Web.Addr, router)

	return proc, nil
}

// registerSinkCounters exposes the usage sink's dropped records and recovered
// panics as counters on registry.
func registerSinkCounters(registry *prometheus.Registry, sink *gwusage.Sink) {
	registry.MustRegister(
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Namespace: "llmproxy", Name: "usage_dropped_total",
			Help: "Usage records dropped before reaching the ledger: the sink's queue was full, or the process was stopping.",
		}, func() float64 { return float64(sink.Dropped()) }),
		prometheus.NewCounterFunc(prometheus.CounterOpts{
			Namespace: "llmproxy", Name: "usage_panics_total",
			Help: "Panics the usage sink recovered from while recording usage.",
		}, func() float64 { return float64(sink.Panics()) }),
	)
}

// bootstrapAdmin creates the bootstrap administrator when no administrator
// exists (app.Bootstrap), and then shows its temporary password on out.
func bootstrapAdmin(ctx context.Context, cfg config.Config, out io.Writer, users app.UserRepo,
	passwords app.PasswordRepo, hasher *app.PasswordHasher, logs processLog,
) error {
	password, err := app.Bootstrap(ctx, users, passwords, hasher, cfg.BootstrapAdminEmail)
	if err != nil {
		return fmt.Errorf("bootstrap administrator: %w", err)
	}

	if password == "" {
		return nil
	}

	printBootstrapPassword(out, cfg.BootstrapAdminEmail, password)

	if cfg.Web.Enabled() && !cfg.Web.LocalLogin {
		//nolint:contextcheck // the process log is not request-scoped and logs under no context
		logs.Warn("the bootstrap administrator signs in with a password, but LLMPROXY_LOCAL_LOGIN is false: "+
			"set it to true until the administrator can sign in another way", slog.String("admin", cfg.BootstrapAdminEmail))
	}

	return nil
}

// newOIDCService connects to the OpenID Connect identity provider and builds
// the federated sign-in on it; it returns nil while OIDC is off.
func newOIDCService(ctx context.Context, cfg config.OIDC, users app.UserRepo, idents app.IdentityRepo,
	sessions app.SessionRepo, audit app.AuditSink, clock app.Clock,
) (*auth.OIDC, error) {
	if !cfg.Enabled() {
		return nil, nil //nolint:nilnil // OIDC off is no service and no error
	}

	idp, err := oidc.New(ctx, oidc.Config{
		Issuer:       cfg.Issuer,
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		GroupsClaim:  cfg.GroupsClaim,
	})
	if err != nil {
		return nil, fmt.Errorf("identity provider: %w", err)
	}

	service, err := auth.NewOIDC(users, idents, sessions, idp, audit, clock, auth.OIDCConfig{
		RequiredGroup: cfg.RequiredGroup,
		AllowSignUp:   cfg.AllowSignUp,
		DefaultPolicy: cfg.DefaultPolicy,
		GroupPolicy:   cfg.GroupPolicy,
	})
	if err != nil {
		return nil, fmt.Errorf("oidc sign-in: %w", err)
	}

	return service, nil
}

// ownedConfig is the gateway-owned part of the boot configuration, which the
// stored settings document cannot set (appsettings.LoadBootConfig): the proxied
// listener, the auth directory, the control panel off and websocket
// authentication on, the boot-only vendors, and nothing else — no api-keys, no
// management secret, plugins, home mode, pprof or discovery.
func ownedConfig(cfg config.Config, compat []cliproxyconfig.OpenAICompatibility) *cliproxyconfig.Config {
	host, port := cfg.ListenHostPort()
	owned := &cliproxyconfig.Config{
		Host:                host,
		Port:                port,
		AuthDir:             cfg.AuthDir,
		WebsocketAuth:       true,
		OpenAICompatibility: compat,
	}
	owned.RemoteManagement.DisableControlPanel = true

	return owned
}

// metricsServer serves /metrics and nothing else on addr.
func metricsServer(addr string, h http.Handler) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", h)

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

// server is one of the process's own listeners (the gateway serves the third).
type server struct {
	name string
	srv  *http.Server
}

// serve runs the listeners until ctx ends or one of them fails, then stops.
// releaseSignals is called as the stop begins, so a second signal is no longer
// caught. Every stage's deadline starts at that moment:
//
//   - the web and metrics listeners stop accepting, and their requests in flight
//     get listenerGrace;
//   - meanwhile the gateway stops accepting, and its requests in flight get
//     drainGrace (Gateway.Shutdown, not the cancellation of Run's context,
//     which makes upstream close every connection at once);
//   - once all have returned, the usage sink gets sinkGrace to write what it
//     still holds, and Run closes the pool.
//
// The price catalog's checks run from the start and stop with the listeners: a
// check in flight is cancelled and waited for, so none outlives the pool.
//
// Upstream's usage dispatch stops for good with the gateway, so the process
// exits rather than restarting it.
//
//nolint:funlen // one linear start-and-stop sequence whose stage order and goroutine ownership are the contract
func (p *process) serve(ctx context.Context, releaseSignals func()) error {
	servers := []server{{"metrics", p.metrics}}
	if p.web != nil {
		servers = append(servers, server{"web API", p.web})
	}
	// Bind before serving anything, so an address in use fails the start.
	listeners := make([]net.Listener, 0, len(servers))
	for _, entry := range servers {
		// A signal during the bind must not fail it: the listener binds, then the
		// ctx.Done() branch below stops cleanly. So the bind ignores cancellation.
		listener, err := (&net.ListenConfig{}).Listen(context.WithoutCancel(ctx), "tcp", entry.srv.Addr)
		if err != nil {
			for _, bound := range listeners {
				_ = bound.Close()
			}

			return fmt.Errorf("%s listener: %w", entry.name, err)
		}

		listeners = append(listeners, listener)
	}

	// The gateway is stopped by Shutdown below, not when ctx ends; its context
	// only backs that up.
	gatewayCtx, stopGateway := context.WithCancel(context.WithoutCancel(ctx))
	defer stopGateway()

	gatewayDone := make(chan error, 1)
	go func() { gatewayDone <- p.gateway.Run(gatewayCtx) }()
	go func() {
		if p.gateway.WaitReload(gatewayCtx) != nil {
			return
		}

		p.log.Info("serving the proxied API", slog.String("addr", p.apiAddr))
		// Upstream's binary starts the model catalogue updaters before its
		// service; here they start once the service runs, under its context,
		// which ends their periodic refresh at shutdown. A change found before
		// upstream registers its refresh callback is held and delivered on
		// registration. They log their own start and every refresh.
		if p.catalogUpdates {
			gateway.StartModelCatalogUpdaters(gatewayCtx)
		}
	}()

	catalogCtx, stopCatalog := context.WithCancel(context.WithoutCancel(ctx))
	defer stopCatalog()

	catalogDone := make(chan struct{})
	go func() {
		defer close(catalogDone)

		p.prices.RunCatalog(catalogCtx, p.catalogInterval)
	}()

	failed := make(chan error, len(servers))
	for i, entry := range servers {
		p.log.Info("serving listener", slog.String("listener", entry.name), slog.String("addr", listeners[i].Addr().String()))
		go func() {
			if err := entry.srv.Serve(listeners[i]); !errors.Is(err, http.ErrServerClosed) {
				failed <- fmt.Errorf("%s listener: %w", entry.name, err)
			}
		}()
	}

	var cause error

	gatewayReturned := false

	select {
	case <-ctx.Done():
	case cause = <-failed:
	case err := <-gatewayDone:
		gatewayReturned = true
		cause = fmt.Errorf("proxied listener stopped: %w", cmp.Or(err, errNoErrorReported))
	}

	releaseSignals()

	if cause != nil {
		p.log.Info("stopping", slog.Any("cause", cause))
	} else {
		p.log.Info("stopping")
	}

	stopCatalog()

	// Each stage's deadline counts from now, detached from ctx's cancellation:
	// ctx may have ended, and the stop must run its course regardless.
	var stopped sync.WaitGroup
	for _, entry := range servers {
		stopped.Go(func() {
			sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), listenerGrace)
			defer cancel()

			if err := entry.srv.Shutdown(sctx); err != nil {
				p.log.Warn("listener shutdown incomplete; closing its remaining connections",
					slog.String("listener", entry.name), slog.Any("err", err))
				_ = entry.srv.Close()
			}
		})
	}

	if !gatewayReturned {
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), drainGrace)
		if err := p.gateway.Shutdown(dctx); err != nil {
			cause = errors.Join(cause, fmt.Errorf("proxied listener: requests in flight were cut: %w", err))
		}

		cancel()
		stopGateway()

		if err := <-gatewayDone; err != nil && !errors.Is(err, context.Canceled) {
			cause = errors.Join(cause, fmt.Errorf("proxied listener: %w", err))
		}
	}

	stopped.Wait()
	<-catalogDone

	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sinkGrace)
	defer cancel()

	if err := p.sink.Drain(dctx); err != nil {
		p.log.Warn("usage records still queued were not all written", slog.Any("err", err))
	}

	p.log.Info("stopped")

	return cause //nolint:wrapcheck // cause joins errors each already wrapped with its stage
}

// errNoErrorReported stands in for the error of a gateway that returned without one.
var errNoErrorReported = errors.New("no error reported")

// printBootstrapPassword shows the bootstrap administrator's temporary password
// once, on the process's output and never through the logger: no log adapter,
// level or hook ever handles it.
func printBootstrapPassword(w io.Writer, email, password string) {
	_, _ = fmt.Fprintf(w, "\n"+
		"=================== llm-proxy: bootstrap administrator ===================\n"+
		"  account:            %s\n"+
		"  temporary password: %s\n"+
		"  Shown this once. Sign in on the web interface and choose a new password.\n"+
		"===========================================================================\n\n",
		email, password)
}

type systemClock struct{}

func (systemClock) Now() time.Time { return time.Now().UTC() }
