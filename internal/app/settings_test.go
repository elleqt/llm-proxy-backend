package app_test

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/stretchr/testify/mock"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

var settingsNow = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

type settingsFixture struct {
	repo    *mocks.SettingsRepo
	gateway *mocks.ConfigPusher
	audit   *mocks.AuditSink
	svc     *app.Settings
	running *sdkconfig.Config
}

// ownedDefaults is what a composition root supplies: the gateway-owned part of the
// configuration, including a boot-only credential family.
func ownedDefaults() *sdkconfig.Config {
	return &sdkconfig.Config{
		Host:    "127.0.0.1",
		Port:    8317,
		AuthDir: "/var/lib/llmproxy/auths",
		OpenAICompatibility: []sdkconfig.OpenAICompatibility{{
			Name: "vendor-a", BaseURL: "http://vendor-a.test/v1",
		}},
	}
}

// newSettingsFixture boots a running configuration from runningDoc the way the
// composition root does, and hands it to the service as the gateway's current one.
func newSettingsFixture(t *testing.T, runningDoc string) *settingsFixture {
	t.Helper()
	boot := mocks.NewSettingsRepo(t)
	boot.EXPECT().UpstreamDocument(mock.Anything).Return(runningDoc, nil).Once()
	running, err := app.LoadBootConfig(context.Background(), boot, ownedDefaults())
	if err != nil {
		t.Fatalf("LoadBootConfig: %v", err)
	}
	f := &settingsFixture{
		repo:    mocks.NewSettingsRepo(t),
		gateway: mocks.NewConfigPusher(t),
		audit:   mocks.NewAuditSink(t),
		running: running,
	}
	f.svc = app.NewSettings(f.repo, f.gateway, f.audit, fixedClock{now: settingsNow})
	return f
}

func yamlUpdate(doc string, dryRun bool) app.SettingsUpdate {
	return app.SettingsUpdate{YAML: &doc, DryRun: dryRun}
}

func wantSettingError(t *testing.T, err, kind error, field string) {
	t.Helper()
	var se *app.SettingError
	if !errors.Is(err, kind) || !errors.As(err, &se) {
		t.Fatalf("err = %v, want a *SettingError wrapping %v", err, kind)
	}
	if se.Field != field {
		t.Fatalf("field = %q, want %q (err %v)", se.Field, field, err)
	}
}

func TestSettingsRefusesGatewayOwnedFields(t *testing.T) {
	cases := map[string]string{
		"host":                 "host: 0.0.0.0",
		"port":                 "port: 9999",
		"tls":                  "tls:\n  enable: true",
		"trusted-proxies":      "trusted-proxies: [0.0.0.0/0]",
		"pprof":                "pprof:\n  enable: true\n  addr: 0.0.0.0:6060",
		"discovery":            "discovery:\n  enabled: true",
		"debug":                "debug: true",
		"auth-dir":             "auth-dir: /tmp/elsewhere",
		"remote-management":    "remote-management:\n  secret-key: hunter2",
		"api-keys":             "api-keys: [master]",
		"plugins":              "plugins:\n  enabled: true",
		"ws-auth":              "ws-auth: false",
		"home":                 "home:\n  enabled: true",
		"claude-api-key":       "claude-api-key:\n  - api-key: sk-test",
		"openai-compatibility": "openai-compatibility:\n  - name: extra\n    base-url: http://x.test",
		"future-api-key":       "future-api-key: []",
	}
	// Every credential family upstream declares is boot-only, not just the ones
	// spelled out above: a new "*-api-key" field must be refused too.
	ct := reflect.TypeFor[sdkconfig.Config]()
	for i := range ct.NumField() {
		tag, _, _ := strings.Cut(ct.Field(i).Tag.Get("yaml"), ",")
		if strings.HasSuffix(tag, "-api-key") {
			cases[tag] = tag + ": []"
		}
	}
	for field, line := range cases {
		t.Run(field, func(t *testing.T) {
			f := newSettingsFixture(t, "")
			// No expectation on gateway, repo or audit: touching any fails the test.
			_, err := f.svc.Update(context.Background(), newAdmin(), yamlUpdate("request-retry: 2\n"+line+"\n", false))
			wantSettingError(t, err, app.ErrForbiddenSetting, field)
		})
	}

	t.Run("stored document at boot", func(t *testing.T) {
		repo := mocks.NewSettingsRepo(t)
		repo.EXPECT().UpstreamDocument(mock.Anything).Return("api-keys: [master]\n", nil)
		_, err := app.LoadBootConfig(context.Background(), repo, ownedDefaults())
		wantSettingError(t, err, app.ErrForbiddenSetting, "api-keys")
	})
}

// TestSettingsRefusesSmuggledOwnedFields covers owned fields set by a route other
// than a literal top-level key.
func TestSettingsRefusesSmuggledOwnedFields(t *testing.T) {
	for name, c := range map[string]struct{ doc, field string }{
		"merge of api-keys":            {"<<: {api-keys: [master]}\n", "<<"},
		"merge list of a secret":       {"<<: [{remote-management: {secret-key: hunter2}}]\n", "<<"},
		"merge of listener fields":     {"<<: {auth-dir: /tmp/evil, host: 0.0.0.0}\n", "<<"},
		"nested merge":                 {"streaming:\n  <<: {keepalive-seconds: 5}\n", "<<"},
		"second document":              {"request-retry: 1\n---\napi-keys: [master]\n", "document"},
		"alias used as a key":          {"video-result-auth-cache-ttl: &k api-keys\n*k : [master]\n", "api-keys"},
		"alias used as a listener key": {"video-result-auth-cache-ttl: &k pprof\n*k : {enable: true, addr: 0.0.0.0:6060}\n", "pprof"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newSettingsFixture(t, "")
			_, err := f.svc.Update(context.Background(), newAdmin(), yamlUpdate(c.doc, true))
			wantSettingError(t, err, app.ErrForbiddenSetting, c.field)
		})
	}
}

func TestSettingsRefusesUnknownAndMalformedDocuments(t *testing.T) {
	for name, doc := range map[string]string{
		"misspelt top-level key": "request-retries: 3\n",
		"misspelt nested key":    "streaming:\n  keepalive-second: 5\n",
		"not a mapping":          "- a\n- b\n",
		"wrong type":             "request-retry: many\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := newSettingsFixture(t, "")
			_, err := f.svc.Update(context.Background(), newAdmin(), yamlUpdate(doc, true))
			if !errors.Is(err, app.ErrInvalidSettings) {
				t.Fatalf("err = %v, want ErrInvalidSettings", err)
			}
		})
	}
	t.Run("proxy URL upstream would not use", func(t *testing.T) {
		f := newSettingsFixture(t, "")
		_, err := f.svc.Update(context.Background(), newAdmin(), yamlUpdate("proxy-url: ftp://proxy.test:21\n", true))
		wantSettingError(t, err, app.ErrInvalidSettings, "proxy-url")
	})
}

func TestSettingsYAMLAndFieldsAreMutuallyExclusive(t *testing.T) {
	f := newSettingsFixture(t, "")
	doc, retry := "request-retry: 1\n", 2

	_, err := f.svc.Update(context.Background(), newAdmin(), app.SettingsUpdate{YAML: &doc, Fields: &app.SettingsPatch{RequestRetry: &retry}})
	wantSettingError(t, err, app.ErrInvalidSettings, "fields")

	_, err = f.svc.Update(context.Background(), newAdmin(), app.SettingsUpdate{DryRun: true})
	wantSettingError(t, err, app.ErrInvalidSettings, "yaml")
}

func TestSettingsDryRunAppliesAndPersistsNothing(t *testing.T) {
	f := newSettingsFixture(t, "request-retry: 1\n")
	f.gateway.EXPECT().CurrentConfig().Return(f.running)
	// No PushConfig, SetUpstreamDocument or Record expectation: a call fails the test.

	res, err := f.svc.Update(context.Background(), newAdmin(), yamlUpdate("request-retry: 3\n", true))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if res.Applied {
		t.Fatal("dry run reported applied")
	}
	if !strings.Contains(res.Diff, "-request-retry: 1\n") || !strings.Contains(res.Diff, "+request-retry: 3\n") {
		t.Fatalf("diff does not show the change:\n%s", res.Diff)
	}
	if res.Settings.Fields.RequestRetry != 3 {
		t.Fatalf("proposed requestRetry = %d, want 3", res.Settings.Fields.RequestRetry)
	}
	if f.running.RequestRetry != 1 {
		t.Fatalf("running configuration was modified: request-retry = %d", f.running.RequestRetry)
	}
}

func TestSettingsApplyPushesThenPersists(t *testing.T) {
	f := newSettingsFixture(t, "request-retry: 1\n")
	admin := newAdmin()
	doc := "# retries\nrequest-retry: 3\nmax-retry-interval: 30\n"
	var steps []string
	var pushed *sdkconfig.Config

	f.gateway.EXPECT().CurrentConfig().Return(f.running)
	f.gateway.EXPECT().PushConfig(mock.Anything).RunAndReturn(func(c *sdkconfig.Config) error {
		steps, pushed = append(steps, "push"), c
		return nil
	}).Once()
	f.repo.EXPECT().SetUpstreamDocument(mock.Anything, doc, admin.ID, settingsNow).RunAndReturn(
		func(context.Context, string, uuid.UUID, time.Time) error {
			steps = append(steps, "persist")
			return nil
		}).Once()
	f.audit.EXPECT().Record(mock.Anything, mock.MatchedBy(func(e app.AuditEvent) bool {
		return e.Action == "settings.update" && e.ActorID == admin.ID &&
			strings.Contains(e.Detail["diff"].(string), "+request-retry: 3")
	})).Return(nil).Once()

	res, err := f.svc.Update(context.Background(), admin, yamlUpdate(doc, false))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !res.Applied {
		t.Fatal("not reported applied")
	}
	if strings.Join(steps, ",") != "push,persist" {
		t.Fatalf("steps = %v, want push then persist", steps)
	}
	if pushed == f.running {
		t.Fatal("pushed the running configuration object itself; want a new one")
	}
	if pushed.RequestRetry != 3 || pushed.MaxRetryInterval != 30 {
		t.Fatalf("pushed request-retry/max-retry-interval = %d/%d, want 3/30", pushed.RequestRetry, pushed.MaxRetryInterval)
	}
	// Gateway-owned fields come from the running configuration, untouched.
	if pushed.Host != "127.0.0.1" || pushed.Port != 8317 || pushed.AuthDir != f.running.AuthDir ||
		len(pushed.OpenAICompatibility) != 1 || pushed.OpenAICompatibility[0].Name != "vendor-a" {
		t.Fatalf("gateway-owned fields not carried over: host=%q port=%d auth-dir=%q compat=%v",
			pushed.Host, pushed.Port, pushed.AuthDir, pushed.OpenAICompatibility)
	}
	if strings.Contains(res.Diff, "auth-dir") || strings.Contains(res.Diff, "openai-compatibility") {
		t.Fatalf("diff shows gateway-owned fields:\n%s", res.Diff)
	}
}

func TestSettingsPushFailurePersistsNothing(t *testing.T) {
	f := newSettingsFixture(t, "")
	refused := errors.New("gateway: not running")
	f.gateway.EXPECT().CurrentConfig().Return(f.running)
	f.gateway.EXPECT().PushConfig(mock.Anything).Return(refused).Once()
	// No SetUpstreamDocument and no Record expectation.

	_, err := f.svc.Update(context.Background(), newAdmin(), yamlUpdate("request-retry: 3\n", false))
	if !errors.Is(err, refused) {
		t.Fatalf("err = %v, want the push error", err)
	}
}

func TestSettingsPersistFailureRestoresRunningConfiguration(t *testing.T) {
	f := newSettingsFixture(t, "request-retry: 1\n")
	dbDown := errors.New("connection refused")
	var pushes []*sdkconfig.Config
	f.gateway.EXPECT().CurrentConfig().Return(f.running)
	f.gateway.EXPECT().PushConfig(mock.Anything).RunAndReturn(func(c *sdkconfig.Config) error {
		pushes = append(pushes, c)
		return nil
	}).Twice()
	f.repo.EXPECT().SetUpstreamDocument(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(dbDown).Once()

	_, err := f.svc.Update(context.Background(), newAdmin(), yamlUpdate("request-retry: 3\n", false))
	if !errors.Is(err, dbDown) {
		t.Fatalf("err = %v, want the persistence error", err)
	}
	if len(pushes) != 2 || pushes[1] != f.running {
		t.Fatalf("pushes = %d, want the new configuration then the previous one back", len(pushes))
	}
}

func TestSettingsDiffAndAuditRedactProxyCredentials(t *testing.T) {
	f := newSettingsFixture(t, "proxy-url: http://olduser:oldpass@proxy.old.test:3128/?token=OLDQUERY\n")
	f.gateway.EXPECT().CurrentConfig().Return(f.running)
	f.gateway.EXPECT().PushConfig(mock.Anything).Return(nil)
	f.repo.EXPECT().SetUpstreamDocument(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	var detail map[string]any
	f.audit.EXPECT().Record(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, e app.AuditEvent) error {
		detail = e.Detail
		return nil
	})

	// A nested credential upstream keeps out of JSON: the TURN server of the Codex
	// live media relay.
	doc := "proxy-url: socks5://alice:s3cret@proxy.new.test:1080/p4thsecret?token=QS3CRET\n" +
		"codex:\n  live-media-relay:\n    ice-servers:\n" +
		"      - urls: [turn:turn.test:3478]\n        username: turnuser\n        credential: TURNs3cret\n"
	res, err := f.svc.Update(context.Background(), newAdmin(), yamlUpdate(doc, false))
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !strings.Contains(res.Diff, "-proxy-url: http://redacted@proxy.old.test:3128\n") ||
		!strings.Contains(res.Diff, "+proxy-url: socks5://redacted@proxy.new.test:1080\n") ||
		!strings.Contains(res.Diff, "+          - turn:turn.test:3478") ||
		!strings.Contains(res.Diff, "+        username: REDACTED") ||
		!strings.Contains(res.Diff, "+        credential: REDACTED") {
		t.Fatalf("diff does not show the redacted change:\n%s", res.Diff)
	}
	audited, _ := detail["diff"].(string)
	for _, secret := range []string{"olduser", "oldpass", "OLDQUERY", "alice", "s3cret", "p4thsecret", "QS3CRET", "turnuser", "TURNs3cret"} {
		if strings.Contains(res.Diff, secret) || strings.Contains(audited, secret) {
			t.Fatalf("credential %q leaked:\ndiff:\n%s\naudit:\n%s", secret, res.Diff, audited)
		}
	}
	// The administrator's own view keeps the value, or a round-trip would erase it.
	if res.Settings.Fields.ProxyURL != "socks5://alice:s3cret@proxy.new.test:1080/p4thsecret?token=QS3CRET" {
		t.Fatalf("settings proxyURL = %q", res.Settings.Fields.ProxyURL)
	}
}

func TestSettingsFieldPatchKeepsTheRestOfTheDocument(t *testing.T) {
	stored := "# operator notes\nrequest-log: true # keep\nproxy-url: http://proxy.test:3128\nrequest-retry: 1\n"
	f := newSettingsFixture(t, stored)
	admin := newAdmin()
	retry, interval := 5, 20
	var persisted string
	f.repo.EXPECT().UpstreamDocument(mock.Anything).Return(stored, nil)
	f.gateway.EXPECT().CurrentConfig().Return(f.running)
	f.gateway.EXPECT().PushConfig(mock.Anything).Return(nil)
	f.repo.EXPECT().SetUpstreamDocument(mock.Anything, mock.Anything, admin.ID, settingsNow).RunAndReturn(
		func(_ context.Context, doc string, _ uuid.UUID, _ time.Time) error { persisted = doc; return nil })
	f.audit.EXPECT().Record(mock.Anything, mock.Anything).Return(nil)

	res, err := f.svc.Update(context.Background(), admin, app.SettingsUpdate{
		Fields: &app.SettingsPatch{RequestRetry: &retry, MaxRetryInterval: &interval},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	for _, want := range []string{"# operator notes", "request-log: true # keep", "proxy-url: http://proxy.test:3128", "request-retry: 5", "max-retry-interval: 20"} {
		if !strings.Contains(persisted, want) {
			t.Errorf("persisted document lacks %q:\n%s", want, persisted)
		}
	}
	if got := res.Settings.Fields; got != (app.SettingsFields{ProxyURL: "http://proxy.test:3128", RequestRetry: 5, MaxRetryInterval: 20}) {
		t.Fatalf("fields = %+v", got)
	}
	if strings.Contains(res.Diff, "request-log") {
		t.Fatalf("diff shows an untouched key:\n%s", res.Diff)
	}
}

func TestSettingsFieldPatchValidation(t *testing.T) {
	neg, badURL := -1, "gopher://proxy.test"
	for field, patch := range map[string]app.SettingsPatch{
		"requestRetry":     {RequestRetry: &neg},
		"maxRetryInterval": {MaxRetryInterval: &neg},
		"proxyURL":         {ProxyURL: &badURL},
	} {
		t.Run(field, func(t *testing.T) {
			f := newSettingsFixture(t, "")
			_, err := f.svc.Update(context.Background(), newAdmin(), app.SettingsUpdate{Fields: &patch})
			wantSettingError(t, err, app.ErrInvalidSettings, field)
		})
	}
}

func TestSettingsGet(t *testing.T) {
	f := newSettingsFixture(t, "")
	stored := "proxy-url: http://proxy.test:3128\nrequest-retry: 4 # tuned\n"
	f.repo.EXPECT().UpstreamDocument(mock.Anything).Return(stored, nil).Once()

	got, err := f.svc.Get(context.Background(), newAdmin())
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.YAML != stored || got.Fields != (app.SettingsFields{ProxyURL: "http://proxy.test:3128", RequestRetry: 4}) {
		t.Fatalf("Get = %+v", got)
	}

	if _, err := f.svc.Get(context.Background(), identity.User{}); !errors.Is(err, app.ErrForbidden) {
		t.Fatalf("Get by nobody: err = %v, want ErrForbidden", err)
	}
}

func TestLoadBootConfigWithoutStoredDocument(t *testing.T) {
	repo := mocks.NewSettingsRepo(t)
	repo.EXPECT().UpstreamDocument(mock.Anything).Return("", app.ErrNotFound)

	cfg, err := app.LoadBootConfig(context.Background(), repo, ownedDefaults())
	if err != nil {
		t.Fatalf("LoadBootConfig: %v", err)
	}
	if cfg.Port != 8317 || len(cfg.OpenAICompatibility) != 1 || cfg.RequestRetry != 0 {
		t.Fatalf("boot config = port %d, compat %d, request-retry %d", cfg.Port, len(cfg.OpenAICompatibility), cfg.RequestRetry)
	}
}
