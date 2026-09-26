package settings_test

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/app/settings"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/google/uuid"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

var settingsNow = time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)

type settingsFixture struct {
	repo    *mocks.SettingsRepo
	gateway *mocks.ConfigPusher
	audit   *mocks.AuditSink
	svc     *settings.Service
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
// The boot warnings about inert keys are TestLoadBootConfigWarnsAboutInertKeys's
// concern, so the fixture's boot tolerates them.
func newSettingsFixture(t *testing.T, runningDoc string) *settingsFixture {
	t.Helper()
	boot := mocks.NewSettingsRepo(t)
	boot.EXPECT().UpstreamDocument(mock.Anything).Return(runningDoc, nil).Once()

	bootLog := mocks.NewLogger(t)
	bootLog.EXPECT().Warn(mock.Anything, mock.Anything).Maybe()

	running, err := settings.LoadBootConfig(context.Background(), boot, ownedDefaults(), bootLog)
	require.NoError(t, err, "LoadBootConfig")
	// gateway.admit forces both off on every boot and push, so the gateway's
	// current configuration never reports them set, whatever runningDoc says.
	running.RequestLog, running.SaveCooldownStatus = false, false

	fixture := &settingsFixture{
		repo:    mocks.NewSettingsRepo(t),
		gateway: mocks.NewConfigPusher(t),
		audit:   mocks.NewAuditSink(t),
		running: running,
	}
	fixture.svc = settings.New(fixture.repo, fixture.gateway, fixture.audit, fixedClock{now: settingsNow})

	return fixture
}

func yamlUpdate(doc string, dryRun bool) settings.Update {
	return settings.Update{YAML: &doc, DryRun: dryRun}
}

func wantSettingError(t *testing.T, err, kind error, field string) {
	t.Helper()

	var se *app.SettingError

	require.ErrorIs(t, err, kind)
	require.ErrorAs(t, err, &se, "want a *SettingError")
	require.Equal(t, field, se.Field, "field of %v", err)
}

// inertKeyWarning is the boot warning about an inert key, as an operator reads it.
const inertKeyWarning = "settings: key has no effect and is ignored; remove it from the settings document"

// keyAttr matches the attributes of a warning about key: exactly key=<key>.
func keyAttr(key string) any {
	want := slog.String("key", key)

	return mock.MatchedBy(func(attrs []slog.Attr) bool {
		return len(attrs) == 1 && attrs[0].Equal(want)
	})
}

func TestSettingsRefusesGatewayOwnedFields(t *testing.T) {
	cases := map[string]string{
		"host":                   "host: 0.0.0.0",
		"port":                   "port: 9999",
		"tls":                    "tls:\n  enable: true",
		"trusted-proxies":        "trusted-proxies: [0.0.0.0/0]",
		"pprof":                  "pprof:\n  enable: true\n  addr: 0.0.0.0:6060",
		"discovery":              "discovery:\n  enabled: true",
		"debug":                  "debug: true",
		"logging-to-file":        "logging-to-file: true",
		"logs-max-total-size-mb": "logs-max-total-size-mb: 100",
		"auth-dir":               "auth-dir: /tmp/elsewhere",
		"remote-management":      "remote-management:\n  secret-key: hunter2",
		"api-keys":               "api-keys: [master]",
		"plugins":                "plugins:\n  enabled: true",
		"ws-auth":                "ws-auth: false",
		"home":                   "home:\n  enabled: true",
		"claude-api-key":         "claude-api-key:\n  - api-key: sk-test",
		"openai-compatibility":   "openai-compatibility:\n  - name: extra\n    base-url: http://x.test",
		"future-api-key":         "future-api-key: []",
	}
	// Every credential family upstream declares is boot-only, not just the ones
	// spelled out above: a new "*-api-key" field must be refused too.
	ct := reflect.TypeFor[sdkconfig.Config]()
	for field := range ct.Fields() {
		tag, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
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
		_, err := settings.LoadBootConfig(context.Background(), repo, ownedDefaults(), mocks.NewLogger(t))
		wantSettingError(t, err, app.ErrForbiddenSetting, "api-keys")
	})
}

// TestSettingsRefusesSmuggledOwnedFields covers owned fields set by a route other
// than a literal top-level key.
func TestSettingsRefusesSmuggledOwnedFields(t *testing.T) {
	for name, tc := range map[string]struct{ doc, field string }{
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
			_, err := f.svc.Update(context.Background(), newAdmin(), yamlUpdate(tc.doc, true))
			wantSettingError(t, err, app.ErrForbiddenSetting, tc.field)
		})
	}
}

// TestSettingsRefusesAddingOrChangingInertKeys: a whole document may not add an
// inert key or change its value; the refusal is the one an owned key gets.
func TestSettingsRefusesAddingOrChangingInertKeys(t *testing.T) {
	for key, values := range map[string][2]string{
		"save-cooldown-status": {"true", "false"},
		"request-log":          {"true", "false"},
		"error-logs-max-files": {"5", "20"},
	} {
		t.Run(key+" added", func(t *testing.T) {
			f := newSettingsFixture(t, "request-retry: 1\n")
			f.repo.EXPECT().UpstreamDocument(mock.Anything).Return("request-retry: 1\n", nil).Once()
			// No gateway, persist or audit expectation: touching any fails the test.
			_, err := f.svc.Update(context.Background(), newAdmin(),
				yamlUpdate("request-retry: 2\n"+key+": "+values[0]+"\n", false))
			wantSettingError(t, err, app.ErrForbiddenSetting, key)
		})

		t.Run(key+" changed", func(t *testing.T) {
			stored := key + ": " + values[0] + "\nrequest-retry: 1\n"
			f := newSettingsFixture(t, stored)
			f.repo.EXPECT().UpstreamDocument(mock.Anything).Return(stored, nil).Once()
			_, err := f.svc.Update(context.Background(), newAdmin(),
				yamlUpdate(key+": "+values[1]+"\nrequest-retry: 1\n", false))
			wantSettingError(t, err, app.ErrForbiddenSetting, key)
		})
	}

	t.Run("added to the default document", func(t *testing.T) {
		f := newSettingsFixture(t, "")
		f.repo.EXPECT().UpstreamDocument(mock.Anything).Return("", app.ErrNotFound).Once()
		_, err := f.svc.Update(context.Background(), newAdmin(), yamlUpdate("request-log: false\n", true))
		wantSettingError(t, err, app.ErrForbiddenSetting, "request-log")
	})
}

// TestSettingsAcceptsInertKeysKeptOrRemoved: a legacy inert key carried over
// unchanged does not block other edits, and removing one is accepted.
func TestSettingsAcceptsInertKeysKeptOrRemoved(t *testing.T) {
	stored := "save-cooldown-status: true\nrequest-log: true\nerror-logs-max-files: 5\nrequest-retry: 1\n"

	for name, doc := range map[string]string{
		"kept unchanged": "save-cooldown-status: true\nrequest-log: true # legacy\nerror-logs-max-files: 5\nrequest-retry: 3\n",
		"one removed":    "save-cooldown-status: true\nerror-logs-max-files: 5\nrequest-retry: 3\n",
		"all removed":    "request-retry: 3\n",
	} {
		t.Run(name, func(t *testing.T) {
			f := newSettingsFixture(t, stored)
			f.repo.EXPECT().UpstreamDocument(mock.Anything).Return(stored, nil)
			f.gateway.EXPECT().CurrentConfig().Return(f.running)

			res, err := f.svc.Update(context.Background(), newAdmin(), yamlUpdate(doc, true))
			require.NoError(t, err, "Update")
			require.Equal(t, 3, res.Settings.Fields.RequestRetry, "proposed requestRetry")
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
			require.ErrorIs(t, err, app.ErrInvalidSettings)
		})
	}

	t.Run("proxy URL upstream would not use", func(t *testing.T) {
		f := newSettingsFixture(t, "")
		_, err := f.svc.Update(context.Background(), newAdmin(), yamlUpdate("proxy-url: ftp://proxy.test:21\n", true))
		wantSettingError(t, err, app.ErrInvalidSettings, "proxy-url")
	})
}

func TestSettingsYAMLAndFieldsAreMutuallyExclusive(t *testing.T) {
	fixture := newSettingsFixture(t, "")
	doc, retry := "request-retry: 1\n", 2

	_, err := fixture.svc.Update(context.Background(), newAdmin(), settings.Update{YAML: &doc, Fields: &settings.Patch{RequestRetry: &retry}})
	wantSettingError(t, err, app.ErrInvalidSettings, "fields")

	_, err = fixture.svc.Update(context.Background(), newAdmin(), settings.Update{DryRun: true})
	wantSettingError(t, err, app.ErrInvalidSettings, "yaml")
}

func TestSettingsDryRunAppliesAndPersistsNothing(t *testing.T) {
	fixture := newSettingsFixture(t, "request-retry: 1\n")
	fixture.repo.EXPECT().UpstreamDocument(mock.Anything).Return("request-retry: 1\n", nil).Once()
	fixture.gateway.EXPECT().CurrentConfig().Return(fixture.running)
	// No PushConfig, SetUpstreamDocument or Record expectation: a call fails the test.

	res, err := fixture.svc.Update(context.Background(), newAdmin(), yamlUpdate("request-retry: 3\n", true))
	require.NoError(t, err, "Update")
	require.False(t, res.Applied, "dry run reported applied")
	require.Contains(t, res.Diff, "-request-retry: 1\n", "diff does not show the change")
	require.Contains(t, res.Diff, "+request-retry: 3\n", "diff does not show the change")
	require.Equal(t, 3, res.Settings.Fields.RequestRetry, "proposed requestRetry")
	require.Equal(t, 1, fixture.running.RequestRetry, "running configuration was modified")
}

func TestSettingsApplyPushesThenPersists(t *testing.T) {
	fixture := newSettingsFixture(t, "request-retry: 1\n")
	admin := newAdmin()
	doc := "# retries\nrequest-retry: 3\nmax-retry-interval: 30\n"

	var (
		steps  []string
		pushed *sdkconfig.Config
	)

	fixture.repo.EXPECT().UpstreamDocument(mock.Anything).Return("request-retry: 1\n", nil).Once()
	fixture.gateway.EXPECT().CurrentConfig().Return(fixture.running)
	fixture.gateway.EXPECT().PushConfig(mock.Anything).RunAndReturn(func(c *sdkconfig.Config) error {
		steps, pushed = append(steps, "push"), c

		return nil
	}).Once()
	fixture.repo.EXPECT().SetUpstreamDocument(mock.Anything, doc, admin.ID, settingsNow).RunAndReturn(
		func(context.Context, string, uuid.UUID, time.Time) error {
			steps = append(steps, "persist")

			return nil
		}).Once()
	fixture.audit.EXPECT().Record(mock.Anything, mock.MatchedBy(func(event app.AuditEvent) bool {
		diff, isString := event.Detail["diff"].(string)

		return event.Action == "settings.update" && event.ActorID == admin.ID &&
			isString && strings.Contains(diff, "+request-retry: 3")
	})).Return(nil).Once()

	res, err := fixture.svc.Update(context.Background(), admin, yamlUpdate(doc, false))
	require.NoError(t, err, "Update")
	require.True(t, res.Applied, "not reported applied")
	require.Equal(t, []string{"push", "persist"}, steps, "want push then persist")
	require.NotNil(t, pushed, "nothing pushed")
	require.NotSame(t, fixture.running, pushed, "pushed the running configuration object itself; want a new one")
	require.Equal(t, 3, pushed.RequestRetry, "pushed request-retry")
	require.Equal(t, 30, pushed.MaxRetryInterval, "pushed max-retry-interval")
	// Gateway-owned fields come from the running configuration, untouched.
	require.Equal(t, "127.0.0.1", pushed.Host, "gateway-owned host not carried over")
	require.Equal(t, 8317, pushed.Port, "gateway-owned port not carried over")
	require.Equal(t, fixture.running.AuthDir, pushed.AuthDir, "gateway-owned auth-dir not carried over")
	require.Len(t, pushed.OpenAICompatibility, 1, "gateway-owned openai-compatibility not carried over")
	require.Equal(t, "vendor-a", pushed.OpenAICompatibility[0].Name, "gateway-owned openai-compatibility not carried over")
	require.NotContains(t, res.Diff, "auth-dir", "diff shows gateway-owned fields")
	require.NotContains(t, res.Diff, "openai-compatibility", "diff shows gateway-owned fields")
}

func TestSettingsPushFailurePersistsNothing(t *testing.T) {
	fixture := newSettingsFixture(t, "")
	refused := errors.New("gateway: not running")

	fixture.repo.EXPECT().UpstreamDocument(mock.Anything).Return("", nil).Once()
	fixture.gateway.EXPECT().CurrentConfig().Return(fixture.running)
	fixture.gateway.EXPECT().PushConfig(mock.Anything).Return(refused).Once()
	// No SetUpstreamDocument and no Record expectation.

	_, err := fixture.svc.Update(context.Background(), newAdmin(), yamlUpdate("request-retry: 3\n", false))
	require.ErrorIs(t, err, refused, "want the push error")
}

func TestSettingsPersistFailureRestoresRunningConfiguration(t *testing.T) {
	fixture := newSettingsFixture(t, "request-retry: 1\n")
	dbDown := errors.New("connection refused")

	var pushes []*sdkconfig.Config

	fixture.repo.EXPECT().UpstreamDocument(mock.Anything).Return("request-retry: 1\n", nil).Once()
	fixture.gateway.EXPECT().CurrentConfig().Return(fixture.running)
	fixture.gateway.EXPECT().PushConfig(mock.Anything).RunAndReturn(func(c *sdkconfig.Config) error {
		pushes = append(pushes, c)

		return nil
	}).Twice()
	fixture.repo.EXPECT().SetUpstreamDocument(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(dbDown).Once()

	_, err := fixture.svc.Update(context.Background(), newAdmin(), yamlUpdate("request-retry: 3\n", false))
	require.ErrorIs(t, err, dbDown, "want the persistence error")
	require.Len(t, pushes, 2, "want the new configuration then the previous one back")
	require.Same(t, fixture.running, pushes[1], "want the previous configuration pushed back")
}

func TestSettingsDiffAndAuditRedactProxyCredentials(t *testing.T) {
	stored := "proxy-url: http://olduser:oldpass@proxy.old.test:3128/?token=OLDQUERY\n"
	fixture := newSettingsFixture(t, stored)
	fixture.repo.EXPECT().UpstreamDocument(mock.Anything).Return(stored, nil).Once()
	fixture.gateway.EXPECT().CurrentConfig().Return(fixture.running)
	fixture.gateway.EXPECT().PushConfig(mock.Anything).Return(nil)
	fixture.repo.EXPECT().SetUpstreamDocument(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	var detail map[string]any

	fixture.audit.EXPECT().Record(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, e app.AuditEvent) error {
		detail = e.Detail

		return nil
	})

	// A nested credential upstream keeps out of JSON: the TURN server of the Codex
	// live media relay.
	doc := "proxy-url: socks5://alice:s3cret@proxy.new.test:1080/p4thsecret?token=QS3CRET\n" +
		"codex:\n  live-media-relay:\n    ice-servers:\n" +
		"      - urls: [turn:turn.test:3478]\n        username: turnuser\n        credential: TURNs3cret\n"

	res, err := fixture.svc.Update(context.Background(), newAdmin(), yamlUpdate(doc, false))
	require.NoError(t, err, "Update")

	for _, want := range []string{
		"-proxy-url: http://redacted@proxy.old.test:3128\n",
		"+proxy-url: socks5://redacted@proxy.new.test:1080\n",
		"+          - turn:turn.test:3478",
		"+        username: REDACTED",
		"+        credential: REDACTED",
	} {
		require.Contains(t, res.Diff, want, "diff does not show the redacted change")
	}

	audited, _ := detail["diff"].(string)

	for _, secret := range []string{"olduser", "oldpass", "OLDQUERY", "alice", "s3cret", "p4thsecret", "QS3CRET", "turnuser", "TURNs3cret"} {
		require.NotContains(t, res.Diff, secret, "credential leaked into the diff")
		require.NotContains(t, audited, secret, "credential leaked into the audit record")
	}
	// The administrator's own view keeps the value, or a round-trip would erase it.
	require.Equal(t, "socks5://alice:s3cret@proxy.new.test:1080/p4thsecret?token=QS3CRET", res.Settings.Fields.ProxyURL, "settings proxyURL")
}

// TestSettingsFieldPatchKeepsTheRestOfTheDocument: a field patch keeps every other
// key and its comments, including inert keys a document saved by an earlier
// release still sets.
func TestSettingsFieldPatchKeepsTheRestOfTheDocument(t *testing.T) {
	stored := "# operator notes\nrequest-log: true # keep\nsave-cooldown-status: true\nerror-logs-max-files: 5\n" +
		"proxy-url: http://proxy.test:3128\nrequest-retry: 1\n"
	fixture := newSettingsFixture(t, stored)
	admin := newAdmin()
	retry, interval := 5, 20

	var persisted string

	fixture.repo.EXPECT().UpstreamDocument(mock.Anything).Return(stored, nil)
	fixture.gateway.EXPECT().CurrentConfig().Return(fixture.running)
	fixture.gateway.EXPECT().PushConfig(mock.Anything).Return(nil)
	fixture.repo.EXPECT().SetUpstreamDocument(mock.Anything, mock.Anything, admin.ID, settingsNow).RunAndReturn(
		func(_ context.Context, doc string, _ uuid.UUID, _ time.Time) error {
			persisted = doc

			return nil
		})
	fixture.audit.EXPECT().Record(mock.Anything, mock.Anything).Return(nil)

	res, err := fixture.svc.Update(context.Background(), admin, settings.Update{
		Fields: &settings.Patch{RequestRetry: &retry, MaxRetryInterval: &interval},
	})
	require.NoError(t, err, "Update")

	for _, want := range []string{
		"# operator notes", "request-log: true # keep", "save-cooldown-status: true", "error-logs-max-files: 5",
		"proxy-url: http://proxy.test:3128", "request-retry: 5", "max-retry-interval: 20",
	} {
		assert.Contains(t, persisted, want, "persisted document")
	}

	require.Equal(t, settings.Fields{ProxyURL: "http://proxy.test:3128", RequestRetry: 5, MaxRetryInterval: 20}, res.Settings.Fields)
	require.NotContains(t, res.Diff, "request-log", "diff shows an untouched key")
}

// TestSettingsDiffOmitsUnchangedInertKeys: the running configuration reports
// request-log and save-cooldown-status off (gateway.admit) even when the stored
// document sets them. An update that keeps them unchanged — a field patch, or a
// whole document carrying them over — shows no change to either in its diff or
// audit record (a key may still appear as an unchanged context line).
func TestSettingsDiffOmitsUnchangedInertKeys(t *testing.T) {
	stored := "request-log: true\nsave-cooldown-status: true\nrequest-retry: 1\n"
	retry := 4

	for name, req := range map[string]settings.Update{
		"field patch":    {Fields: &settings.Patch{RequestRetry: &retry}},
		"whole document": yamlUpdate("request-log: true\nsave-cooldown-status: true\nrequest-retry: 4\n", false),
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newSettingsFixture(t, stored)
			fixture.repo.EXPECT().UpstreamDocument(mock.Anything).Return(stored, nil)
			fixture.gateway.EXPECT().CurrentConfig().Return(fixture.running)
			fixture.gateway.EXPECT().PushConfig(mock.Anything).Return(nil)
			fixture.repo.EXPECT().SetUpstreamDocument(mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

			var detail map[string]any

			fixture.audit.EXPECT().Record(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, e app.AuditEvent) error {
				detail = e.Detail

				return nil
			})

			res, err := fixture.svc.Update(context.Background(), newAdmin(), req)
			require.NoError(t, err, "Update")
			require.Contains(t, res.Diff, "+request-retry: 4\n", "diff does not show the patched field")

			audited, _ := detail["diff"].(string)

			for _, key := range []string{"request-log", "save-cooldown-status"} {
				for _, change := range []string{"-" + key + ":", "+" + key + ":"} {
					require.NotContains(t, res.Diff, change, "diff shows an unchanged inert key as changed")
					require.NotContains(t, audited, change, "audit record shows an unchanged inert key as changed")
				}
			}
		})
	}
}

// TestSettingsRemovingAnInertKeyIsAChange: a whole document whose only change is
// dropping a legacy inert key shows that as a change, so the admin panel can
// apply it, and it is applied and audited: the stored document no longer sets it.
func TestSettingsRemovingAnInertKeyIsAChange(t *testing.T) {
	for key, tc := range map[string]struct{ stored, removed, added string }{
		"request-log":          {"request-log: true\n", "-request-log: true\n", "+request-log: false\n"},
		"save-cooldown-status": {"save-cooldown-status: true\n", "-save-cooldown-status: true\n", "+save-cooldown-status: false\n"},
		"error-logs-max-files": {"error-logs-max-files: 5\n", "-error-logs-max-files: 5\n", "+error-logs-max-files: 10\n"},
	} {
		t.Run(key, func(t *testing.T) {
			stored := tc.stored + "request-retry: 1\n"
			fixture := newSettingsFixture(t, stored)

			var persisted string

			fixture.repo.EXPECT().UpstreamDocument(mock.Anything).Return(stored, nil)
			fixture.gateway.EXPECT().CurrentConfig().Return(fixture.running)
			fixture.gateway.EXPECT().PushConfig(mock.Anything).Return(nil)
			fixture.repo.EXPECT().SetUpstreamDocument(mock.Anything, mock.Anything, mock.Anything, mock.Anything).RunAndReturn(
				func(_ context.Context, doc string, _ uuid.UUID, _ time.Time) error {
					persisted = doc

					return nil
				})

			var detail map[string]any

			fixture.audit.EXPECT().Record(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, e app.AuditEvent) error {
				detail = e.Detail

				return nil
			})

			res, err := fixture.svc.Update(context.Background(), newAdmin(), yamlUpdate("request-retry: 1\n", false))
			require.NoError(t, err, "Update")
			require.True(t, res.Applied, "removal not applied")
			require.NotContains(t, persisted, key, "persisted document still sets the key")

			audited, _ := detail["diff"].(string)

			for _, line := range []string{tc.removed, tc.added} {
				require.Contains(t, res.Diff, line, "diff does not show the removal")
				require.Contains(t, audited, line, "audit record does not show the removal")
			}
		})
	}
}

func TestSettingsFieldPatchValidation(t *testing.T) {
	neg, badURL := -1, "gopher://proxy.test"
	for field, patch := range map[string]settings.Patch{
		"requestRetry":     {RequestRetry: &neg},
		"maxRetryInterval": {MaxRetryInterval: &neg},
		"proxyURL":         {ProxyURL: &badURL},
	} {
		t.Run(field, func(t *testing.T) {
			f := newSettingsFixture(t, "")
			_, err := f.svc.Update(context.Background(), newAdmin(), settings.Update{Fields: &patch})
			wantSettingError(t, err, app.ErrInvalidSettings, field)
		})
	}
}

func TestSettingsGet(t *testing.T) {
	fixture := newSettingsFixture(t, "")
	stored := "proxy-url: http://proxy.test:3128\nrequest-retry: 4 # tuned\n"
	fixture.repo.EXPECT().UpstreamDocument(mock.Anything).Return(stored, nil).Once()

	got, err := fixture.svc.Get(context.Background(), newAdmin())
	require.NoError(t, err, "Get")
	require.Equal(t, stored, got.YAML, "Get YAML")
	require.Equal(t, settings.Fields{ProxyURL: "http://proxy.test:3128", RequestRetry: 4}, got.Fields, "Get fields")

	_, err = fixture.svc.Get(context.Background(), identity.User{})
	require.ErrorIs(t, err, app.ErrForbidden, "Get by nobody")
}

func TestLoadBootConfigWithoutStoredDocument(t *testing.T) {
	repo := mocks.NewSettingsRepo(t)
	repo.EXPECT().UpstreamDocument(mock.Anything).Return("", app.ErrNotFound)

	cfg, err := settings.LoadBootConfig(context.Background(), repo, ownedDefaults(), mocks.NewLogger(t))
	require.NoError(t, err, "LoadBootConfig")
	require.Equal(t, 8317, cfg.Port, "boot config port")
	require.Len(t, cfg.OpenAICompatibility, 1, "boot config openai-compatibility")
	require.Zero(t, cfg.RequestRetry, "boot config request-retry")

	aliases := cfg.OAuthModelAlias["claude"]
	require.Len(t, aliases, 3, "default aliases")
	require.Equal(t, "claude-sonnet-4-5-20250929", aliases[1].Name, "default alias name")
	require.Equal(t, "claude-sonnet-4-5", aliases[1].Alias, "default alias")
	require.True(t, aliases[1].Fork, "default alias fork")

	excluded := cfg.OAuthExcludedModels["claude"]
	require.Len(t, excluded, 5, "default exclusions")
	require.Equal(t, "claude-3-7-sonnet-20250219", excluded[3], "default exclusion")
}

// TestLoadBootConfigWarnsAboutInertKeys: a document saved by an earlier release
// that still sets an inert key boots, with exactly one warning per key present,
// whatever its value.
func TestLoadBootConfigWarnsAboutInertKeys(t *testing.T) {
	repo := mocks.NewSettingsRepo(t)
	repo.EXPECT().UpstreamDocument(mock.Anything).Return(
		"save-cooldown-status: false\nrequest-log: true\nerror-logs-max-files: 5\nrequest-retry: 2\n", nil)

	logs := mocks.NewLogger(t)
	for _, key := range []string{"save-cooldown-status", "request-log", "error-logs-max-files"} {
		logs.EXPECT().Warn(inertKeyWarning, keyAttr(key)).Once()
	}

	cfg, err := settings.LoadBootConfig(context.Background(), repo, ownedDefaults(), logs)
	require.NoError(t, err, "LoadBootConfig")
	require.Equal(t, 2, cfg.RequestRetry, "boot config request-retry")
	require.Equal(t, 8317, cfg.Port, "gateway-owned port not carried over")
}

func TestGetWithoutStoredDocumentShowsDefault(t *testing.T) {
	f := newSettingsFixture(t, "")
	f.repo.EXPECT().UpstreamDocument(mock.Anything).Return("", app.ErrNotFound)

	view, err := f.svc.Get(context.Background(), newAdmin())
	require.NoError(t, err, "Get")
	require.Contains(t, view.YAML, "oauth-model-alias:", "want the default document")
	require.Contains(t, view.YAML, "claude-opus-4-5", "want the default document")
}
