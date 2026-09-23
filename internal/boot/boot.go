// Package boot is the composition root: it turns the environment, the database and
// every service into one process serving three listeners, and stops it in order.
// cmd/gateway calls Run and nothing else, and the end-to-end test calls the same Run.
package boot

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/sirupsen/logrus"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/config"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	webapi "github.com/elleqt/llm-proxy-backend/internal/iface/http"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway"
	"github.com/elleqt/llm-proxy-backend/internal/infra/metrics"
	"github.com/elleqt/llm-proxy-backend/internal/infra/oidc"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres"
)

// Options is what the process takes from outside its environment variables.
type Options struct {
	// Output receives the process log and the bootstrap administrator's one-time
	// password banner. The command passes os.Stderr. Required.
	Output io.Writer
	// Version labels llmproxy_build_info; empty takes it from the binary's build
	// information.
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
// Boot order: configuration, migrations, the pool, repositories and the one
// password hasher, the bootstrap administrator, the upstream boot configuration
// from the database, metrics and the usage sink, the gateway, then the three
// listeners, and once the gateway runs, the model catalogue updaters unless
// LLMPROXY_MODEL_CATALOG_UPDATES is off. Nothing pushes a configuration or
// changes an account after boot: the first change is an administrator's.
func Run(ctx context.Context, opts Options) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM, os.Interrupt)
	defer stop()
	plog := log.New(opts.Output, "", log.LstdFlags|log.LUTC)
	// Upstream logs through logrus. Debug level would log request details; keep it
	// at info whatever the environment set before.
	logrus.SetLevel(logrus.InfoLevel)

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	// Neither error carries the DSN (see postgres.report).
	if err := postgres.Migrate(ctx, cfg.DatabaseURL); err != nil {
		return fmt.Errorf("database migration: %w", err)
	}
	pool, err := postgres.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	defer pool.Close()
	plog.Printf("database migrated and connected")

	p, err := build(ctx, cfg, opts, pool, plog)
	if err != nil {
		return err
	}
	return p.serve(ctx, stop)
}

// process is the built service, ready to serve.
type process struct {
	log     *log.Logger
	gateway *gateway.Gateway
	// apiAddr is where the gateway serves the proxied API.
	apiAddr string
	// catalogUpdates starts upstream's model catalogue updaters once the gateway
	// runs (LLMPROXY_MODEL_CATALOG_UPDATES).
	catalogUpdates bool
	sink           *gateway.UsageSink
	// web is nil when LLMPROXY_WEB_ADDR is off.
	web     *http.Server
	metrics *http.Server
}

func build(ctx context.Context, cfg config.Config, opts Options, pool *pgxpool.Pool, plog *log.Logger) (*process, error) {
	users, passwords := postgres.NewUserRepo(pool), postgres.NewPasswordRepo(pool)
	tokens, sessions := postgres.NewTokenRepo(pool), postgres.NewSessionRepo(pool)
	audit, usage := postgres.NewAuditSink(pool), postgres.NewUsageRepo(pool)
	settings := postgres.NewSettingsRepo(pool)
	clock, logs := systemClock{}, processLog{plog}
	// One hasher, so LLMPROXY_PASSWORD_HASH_CONCURRENCY bounds every derivation in
	// the process: sign-in, bootstrap and administrators' resets alike.
	hasher := app.NewPasswordHasher(cfg.PasswordHashConcurrency, identity.HashPassword, identity.VerifyPassword)

	password, err := app.Bootstrap(ctx, users, passwords, hasher, cfg.BootstrapAdminEmail)
	if err != nil {
		return nil, err
	}
	if password != "" {
		printBootstrapPassword(opts.Output, cfg.BootstrapAdminEmail, password)
		if cfg.Web.Enabled() && !cfg.Web.LocalLogin {
			logs.Warnf("the bootstrap administrator %s signs in with a password, but LLMPROXY_LOCAL_LOGIN is false: "+
				"set it to true until the administrator can sign in another way", cfg.BootstrapAdminEmail)
		}
	}

	bootCfg, err := app.LoadBootConfig(ctx, settings, ownedConfig(cfg, opts.Compatibility))
	if err != nil {
		return nil, err
	}

	registry := prometheus.NewRegistry()
	prices := &metrics.PriceTable{}
	var g *gateway.Gateway
	meters := metrics.New(registry,
		metrics.WithClock(clock),
		metrics.WithVersion(opts.Version),
		metrics.WithPrices(prices),
		// g is set below, before anything is served.
		metrics.WithKnownModel(func(model string) (string, bool) { return g.Catalog().KnownModel(model) }),
	)
	sink := gateway.NewUsageSink(usage, tokens, users, meters, clock, logs)
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
	priceList := app.NewPrices(postgres.NewPriceRepo(pool), prices, audit, clock)
	if err := priceList.Load(ctx); err != nil {
		return nil, err
	}

	// The store's base directory and the gateway's auth directory are both
	// bootCfg.AuthDir.
	manager, store, cooldown := gateway.NewCoreAuthManager(bootCfg)
	g, err = gateway.New(gateway.Params{
		Config: bootCfg,
		// Required by upstream, which resolves its log directory from it; no
		// file is created or read there.
		ConfigPath:  filepath.Join(cfg.RuntimeDir, "config.yaml"),
		UsagePlugin: sink,
		CoreAuth:    manager,
		Store:       store,
		Cooldown:    cooldown,
		Resolver:    app.NewTokenResolver(users, tokens),
		// The gate's 401s and refusals are counted, a denial under its owner.
		Observer: gateMetrics{meters},
	})
	if err != nil {
		return nil, fmt.Errorf("gateway: %w", err)
	}

	p := &process{
		log:            plog,
		gateway:        g,
		apiAddr:        cfg.ListenAddr,
		catalogUpdates: cfg.ModelCatalogUpdates,
		sink:           sink,
		metrics:        metricsServer(cfg.MetricsAddr, meters.Handler()),
	}
	if !cfg.Web.Enabled() {
		return p, nil
	}

	var oidcService *app.OIDCService
	idents := postgres.NewIdentityRepo(pool)
	if cfg.OIDC.Enabled() {
		idp, err := oidc.New(ctx, oidc.Config{
			Issuer:       cfg.OIDC.Issuer,
			ClientID:     cfg.OIDC.ClientID,
			ClientSecret: cfg.OIDC.ClientSecret,
			RedirectURL:  cfg.OIDC.RedirectURL,
			GroupsClaim:  cfg.OIDC.GroupsClaim,
		})
		if err != nil {
			return nil, err
		}
		oidcService, err = app.NewOIDCService(users, idents, sessions, idp, audit, clock, app.OIDCConfig{
			RequiredGroup: cfg.OIDC.RequiredGroup,
			AllowSignUp:   cfg.OIDC.AllowSignUp,
			DefaultPolicy: cfg.OIDC.DefaultPolicy,
			GroupPolicy:   cfg.OIDC.GroupPolicy,
		})
		if err != nil {
			return nil, err
		}
	}
	tokenService := app.NewTokenService(users, tokens, audit, clock, logs)
	router, err := webapi.NewRouter(webapi.Deps{
		Auth: app.NewAuthService(users, passwords,
			app.NewThrottle(postgres.NewLoginAttemptRepo(pool), signInFailures, signInLockout, clock),
			hasher, sessions, audit, clock),
		Tokens:          tokenService,
		OIDC:            oidcService,
		OIDCDisplayName: cfg.OIDC.DisplayName,
		LocalLogin:      cfg.Web.LocalLogin,
		Usage:           app.NewUsageService(usage),
		AdminUsers: app.NewAdminUsers(users, passwords, idents, sessions, postgres.NewActivityRepo(pool),
			tokenService, hasher, audit, clock, g.Catalog(), app.AdminUsersConfig{
				OIDCIssuer:             cfg.OIDC.Issuer,
				GroupMappingConfigured: len(cfg.OIDC.GroupPolicy) > 0,
			}),
		Settings: app.NewSettings(settings, g, audit, clock),
		Prices:   priceList,
		// Removing an account forgets its quota snapshot in the sink and its
		// series in these metrics (Providers.Remove).
		Providers:    app.NewProviders(g, gateway.NewLogin(g), sink, meters, audit, clock, logs),
		Clock:        clock,
		Log:          logs,
		PublicAPIURL: cfg.Web.PublicAPIURL,
		CookieSecure: cfg.Web.CookieSecure,
		SessionKey:   cfg.Web.SessionKey,
	})
	if err != nil {
		return nil, err
	}
	p.web = webapi.NewServer(cfg.Web.Addr, router)
	return p, nil
}

// ownedConfig is the gateway-owned part of the boot configuration, which the
// stored settings document cannot set (app.LoadBootConfig): the proxied
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
//     drainGrace (Gateway.Shutdown, not the cancellation of Run's context, whose
//     deadline upstream counts from boot);
//   - once all have returned, the usage sink gets sinkGrace to write what it
//     still holds, and Run closes the pool.
//
// Upstream's usage dispatch stops for good with the gateway, so the process
// exits rather than restarting it.
func (p *process) serve(ctx context.Context, releaseSignals func()) error {
	servers := []server{{"metrics", p.metrics}}
	if p.web != nil {
		servers = append(servers, server{"web API", p.web})
	}
	// Bind before serving anything, so an address in use fails the start.
	listeners := make([]net.Listener, 0, len(servers))
	for _, s := range servers {
		l, err := net.Listen("tcp", s.srv.Addr)
		if err != nil {
			for _, bound := range listeners {
				_ = bound.Close()
			}
			return fmt.Errorf("%s listener: %w", s.name, err)
		}
		listeners = append(listeners, l)
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
		p.log.Printf("serving the proxied API on %s", p.apiAddr)
		// Upstream's binary starts the model catalogue updaters before its
		// service; here they start once the service runs, under its context,
		// which ends their periodic refresh at shutdown. A change found before
		// upstream registers its refresh callback is held and delivered on
		// registration. They log their own start and every refresh.
		if p.catalogUpdates {
			gateway.StartModelCatalogUpdaters(gatewayCtx)
		}
	}()

	failed := make(chan error, len(servers))
	for i, s := range servers {
		p.log.Printf("serving %s on %s", s.name, listeners[i].Addr())
		go func() {
			if err := s.srv.Serve(listeners[i]); !errors.Is(err, http.ErrServerClosed) {
				failed <- fmt.Errorf("%s listener: %w", s.name, err)
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
		cause = fmt.Errorf("proxied listener stopped: %w", cmp.Or(err, errors.New("no error reported")))
	}
	releaseSignals()
	if cause != nil {
		p.log.Printf("stopping: %v", cause)
	} else {
		p.log.Printf("stopping")
	}

	var stopped sync.WaitGroup
	for _, s := range servers {
		stopped.Go(func() {
			sctx, cancel := context.WithTimeout(context.Background(), listenerGrace)
			defer cancel()
			if err := s.srv.Shutdown(sctx); err != nil {
				p.log.Printf("%s listener: %v; closing its remaining connections", s.name, err)
				_ = s.srv.Close()
			}
		})
	}
	if !gatewayReturned {
		dctx, cancel := context.WithTimeout(context.Background(), drainGrace)
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

	dctx, cancel := context.WithTimeout(context.Background(), sinkGrace)
	defer cancel()
	if err := p.sink.Drain(dctx); err != nil {
		p.log.Printf("usage records still queued were not all written: %v", err)
	}
	p.log.Printf("stopped")
	return cause
}

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

// processLog is app.Logger over the process log.
type processLog struct{ l *log.Logger }

func (p processLog) Warnf(format string, args ...any) { p.l.Printf("warning: "+format, args...) }
