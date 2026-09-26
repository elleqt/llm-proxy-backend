package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/stretchr/testify/require"
)

// These tests pin upstream behaviour the account methods depend on, measured
// against v7.3.18: an upgrade that changes it must fail here.

// claudeGrant is a Claude OAuth account. Claude models come from upstream's
// static catalogue, so registering one needs no network; the token is valid
// for two days so nothing tries to refresh it.
func claudeGrant(t *testing.T) *coreauth.Auth {
	t.Helper()

	return claudeGrantNamed(t, t.Name())
}

// claudeGrantNamed is claudeGrant for a test that needs more than one account.
func claudeGrantNamed(t *testing.T, name string) *coreauth.Auth {
	t.Helper()

	id := "claude-" + strings.ToLower(name) + ".json"
	// The model registry is process-global; never leave this account's models
	// behind for a later test.
	t.Cleanup(func() { cliproxy.GlobalModelRegistry().UnregisterClient(id) })

	return &coreauth.Auth{
		ID:       id,
		FileName: id,
		Provider: "claude",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{
			"type":         "claude",
			"access_token": "fake-claude-access-token",
			"expired":      time.Now().Add(48 * time.Hour).Format(time.RFC3339),
		},
	}
}

// registeredModels is what upstream routes on: the models the global registry
// holds for account id.
func registeredModels(id string) int {
	return len(cliproxy.GlobalModelRegistry().GetModelsForClient(id))
}

// startProduction starts a gateway wired as production wires it and returns it
// with its core auth manager, once boot has finished (startBooted).
func startProduction(t *testing.T) (*running, *coreauth.Manager) {
	t.Helper()
	p := productionParams(t)

	return startBooted(t, p), p.CoreAuth
}

// startBooted is startWith for a test that changes accounts straight after
// the gateway starts. Upstream goes on booting after the watcher exists:
// it hands the watcher the configuration and then registers the models of
// every account the manager holds (service_lifecycle.go:196-205,
// syncPluginModelRuntime), reading the service configuration without its
// lock, and reports nowhere when it is done. An account change re-applies the
// configuration under the lock and would race it, and an account registered
// meanwhile would get its models from boot instead of from the change (see
// WaitReload). So the token store holds one credential before boot, which
// only that last step registers models for — the manager loads it without
// any, unlike a config-derived account — and startBooted returns once its
// models are in the registry. The credential is an account like any other,
// in the store, the manager and Accounts.
func startBooted(t *testing.T, params Params) *running {
	t.Helper()

	boot := claudeGrantNamed(t, "boot-"+strconv.FormatInt(wireSeq.Add(1), 10))
	_, err := params.Store.Save(context.Background(), boot)
	require.NoError(t, err, "save the boot credential")

	srv := startWith(t, params)

	for deadline := time.Now().Add(10 * time.Second); registeredModels(boot.ID) == 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			require.Fail(t, "boot never registered the models of the account it loaded")
		}
	}

	return srv
}

// TestBareRegisterLeavesAnAccountUnroutable is the reason the account methods
// exist: with the hollow watcher, registering an account straight into the
// manager registers none of its models. If this starts failing, upstream has
// fixed it and the re-apply in the account methods can go.
func TestBareRegisterLeavesAnAccountUnroutable(t *testing.T) {
	_, manager := startProduction(t)
	grant := claudeGrant(t)

	_, err := manager.Register(context.Background(), grant)
	require.NoError(t, err, "Register")

	_, ok := manager.GetByID(grant.ID)
	require.True(t, ok, "manager does not hold the registered account")
	require.Zero(t, registeredModels(grant.ID), "a bare Register registered models: upstream now reconciles on its own")
}

func TestAddAccountRegistersTheAccountsModels(t *testing.T) {
	r, manager := startProduction(t)
	grant := claudeGrant(t)

	stored, err := r.gateway.AddAccount(context.Background(), grant)
	require.NoError(t, err, "AddAccount")
	require.NotNil(t, stored, "AddAccount returned no stored account")
	require.Equal(t, grant.ID, stored.ID, "AddAccount returned another account")

	_, ok := manager.GetByID(grant.ID)
	require.True(t, ok, "manager does not hold the added account")
	require.NotZero(t, registeredModels(grant.ID), "the added Claude account has no registered models: it is not routable")
}

func TestSetAccountDisabledUnregistersAndRestoresModels(t *testing.T) {
	srv, manager := startProduction(t)

	grant := claudeGrant(t)
	_, err := srv.gateway.AddAccount(context.Background(), grant)
	require.NoError(t, err, "AddAccount")

	enabled := registeredModels(grant.ID)
	require.NotZero(t, enabled, "the added Claude account has no registered models")
	require.NoError(t, srv.gateway.SetAccountDisabled(context.Background(), grant.ID, true), "SetAccountDisabled(true)")
	require.Zero(t, registeredModels(grant.ID), "a disabled account still has registered models")

	got, _ := manager.GetByID(grant.ID)
	require.NotNil(t, got, "manager does not hold the account")
	require.True(t, got.Disabled, "manager holds %+v, want the account disabled", got)
	require.NoError(t, srv.gateway.SetAccountDisabled(context.Background(), grant.ID, false), "SetAccountDisabled(false)")
	require.Equal(t, enabled, registeredModels(grant.ID), "a re-enabled account must have the registered models it had")
}

func TestRemoveAccountUnregistersModels(t *testing.T) {
	srv, manager := startProduction(t)

	grant := claudeGrant(t)
	_, err := srv.gateway.AddAccount(context.Background(), grant)
	require.NoError(t, err, "AddAccount")
	require.NotZero(t, registeredModels(grant.ID), "the added Claude account has no registered models")
	require.NoError(t, srv.gateway.RemoveAccount(context.Background(), grant.ID), "RemoveAccount")

	_, ok := manager.GetByID(grant.ID)
	require.False(t, ok, "manager still holds the removed account")
	require.Zero(t, registeredModels(grant.ID), "the removed account still has registered models: they would be listed with no credential behind them")
}

// TestRemoveAccountDeletesTheCredentialAcrossARestart: a removed account must
// stay removed when a fresh gateway starts on the same token store. The kept
// account shows the fresh gateway does load what the store holds, so the
// removed one's absence is not an empty boot. The removed account's file name
// differs from the id it was added with; it is stored and held, as a restart
// loads it, under its file name.
func TestRemoveAccountDeletesTheCredentialAcrossARestart(t *testing.T) {
	params := productionParams(t)
	authDir := params.Config.AuthDir
	srv := startBooted(t, params)
	kept := claudeGrantNamed(t, t.Name()+"-kept")
	removed := claudeGrantNamed(t, t.Name()+"-removed")

	removed.FileName = "file-of-" + removed.ID
	for _, grant := range []*coreauth.Auth{kept, removed} {
		stored, err := srv.gateway.AddAccount(context.Background(), grant)
		require.NoError(t, err, "AddAccount(%s)", grant.ID)
		require.Equal(t, grant.FileName, stored.ID, "AddAccount(%s) must hold the id a restart gives it, its file name", grant.ID)
		require.True(t, storeLists(t, params.Store, grant.FileName), "the token store lists no credential for the added account %q", grant.FileName)
	}

	require.NoError(t, srv.gateway.RemoveAccount(context.Background(), removed.FileName), "RemoveAccount")
	require.False(t, storeLists(t, params.Store, removed.FileName), "the token store still lists the removed account's credential")
	require.ErrorIs(t, srv.stop(), context.Canceled, "stop: Run must return context.Canceled")

	fresh := productionParamsIn(authDir)
	startWith(t, fresh)

	_, ok := fresh.CoreAuth.GetByID(kept.ID)
	require.True(t, ok, "a fresh gateway did not load the kept account: the restart proves nothing")
	// A credential loaded from the store takes its key, the file name, as its id.
	for _, id := range []string{removed.ID, removed.FileName} {
		_, ok := fresh.CoreAuth.GetByID(id)
		require.False(t, ok, "a fresh gateway resurrected the removed account as %q", id)
	}
}

// faultyStore is the production token store with Save and Delete failing on
// demand. The manager keeps persisting to the real store it was built on; only
// the gateway's own calls go through this one.
type faultyStore struct {
	coreauth.Store

	refuseSave   atomic.Bool
	refuseDelete atomic.Bool
}

var (
	errSaveRefused   = errors.New("save refused by test")
	errDeleteRefused = errors.New("delete refused by test")
)

func (s *faultyStore) Save(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if s.refuseSave.Load() {
		return "", errSaveRefused
	}

	return s.Store.Save(ctx, auth)
}

func (s *faultyStore) Delete(ctx context.Context, id string) error {
	if s.refuseDelete.Load() {
		return errDeleteRefused
	}

	return s.Store.Delete(ctx, id)
}

// TestSetAccountDisabledReportsAnUnsavedFlag: the manager discards its save
// error, so without the gateway's own save a failed write would return nil and
// the account would come back enabled after a restart. On failure the account
// keeps the requested state in memory — disabled and unroutable — and a retry
// succeeds.
func TestSetAccountDisabledReportsAnUnsavedFlag(t *testing.T) {
	params := productionParams(t)
	store := &faultyStore{Store: params.Store}
	params.Store = store
	srv := startBooted(t, params)

	grant := claudeGrant(t)
	_, err := srv.gateway.AddAccount(context.Background(), grant)
	require.NoError(t, err, "AddAccount")

	store.refuseSave.Store(true)

	err = srv.gateway.SetAccountDisabled(context.Background(), grant.ID, true)
	require.ErrorIs(t, err, errSaveRefused, "SetAccountDisabled with a failing save must report the store's error")

	got, ok := params.CoreAuth.GetByID(grant.ID)
	require.True(t, ok, "the manager dropped the account after a failed save")
	require.True(t, got.Disabled, "after a failed save the account is enabled in memory, want it kept disabled as requested")
	require.Zero(t, registeredModels(grant.ID), "the account disabled in memory still has registered models")

	store.refuseSave.Store(false)

	require.NoError(t, srv.gateway.SetAccountDisabled(context.Background(), grant.ID, true), "retried SetAccountDisabled")
}

// TestRemoveAccountReportsAnUndeletedCredential pins the failure mode
// RemoveAccount allows: when the store delete fails, the account is left
// disabled, unroutable and still held, the error says so, and a retry finishes
// the removal. Removing from memory before deleting would leave nothing to retry.
func TestRemoveAccountReportsAnUndeletedCredential(t *testing.T) {
	params := productionParams(t)
	store := &faultyStore{Store: params.Store}
	params.Store = store
	srv := startBooted(t, params)

	grant := claudeGrant(t)
	_, err := srv.gateway.AddAccount(context.Background(), grant)
	require.NoError(t, err, "AddAccount")

	store.refuseDelete.Store(true)

	err = srv.gateway.RemoveAccount(context.Background(), grant.ID)
	require.ErrorIs(t, err, errDeleteRefused, "RemoveAccount with a failing store must report the store's error")
	require.ErrorContains(t, err, "disabled but still held", "RemoveAccount error does not name the partial state")

	got, ok := params.CoreAuth.GetByID(grant.ID)
	require.True(t, ok, "the account is gone from the manager although its credential was not deleted: a retry cannot reach it")
	require.True(t, got.Disabled, "the account whose credential could not be deleted is still enabled")
	require.Zero(t, registeredModels(grant.ID), "the half-removed account still has registered models")

	store.refuseDelete.Store(false)

	require.NoError(t, srv.gateway.RemoveAccount(context.Background(), grant.ID), "retried RemoveAccount")

	_, ok = params.CoreAuth.GetByID(grant.ID)
	require.False(t, ok, "manager still holds the account after the retry")

	require.False(t, storeLists(t, params.Store, grant.ID), "the token store still lists the credential after the retry")
}

// TestRemoveAccountReportsAnUnsavedDisable: when the delete fails, the
// credential left behind must say disabled; if that save fails too, the error
// reports it, because the file may still say enabled.
func TestRemoveAccountReportsAnUnsavedDisable(t *testing.T) {
	params := productionParams(t)
	store := &faultyStore{Store: params.Store}
	params.Store = store
	srv := startBooted(t, params)

	grant := claudeGrant(t)
	_, err := srv.gateway.AddAccount(context.Background(), grant)
	require.NoError(t, err, "AddAccount")

	store.refuseDelete.Store(true)
	store.refuseSave.Store(true)

	err = srv.gateway.RemoveAccount(context.Background(), grant.ID)
	require.ErrorIs(t, err, errDeleteRefused, "RemoveAccount with delete and save failing must report the delete error")
	require.ErrorIs(t, err, errSaveRefused, "RemoveAccount with delete and save failing must report the save error")

	_, ok := params.CoreAuth.GetByID(grant.ID)
	require.True(t, ok, "the account is gone from the manager although its credential was not deleted")
}

func TestAccountChangesRefuseAnUnknownAccount(t *testing.T) {
	p := productionParams(t)
	srv, manager := startWith(t, p), p.CoreAuth

	require.ErrorIs(t, srv.gateway.SetAccountDisabled(context.Background(), "no-such-account", true), ErrUnknownAccount, "SetAccountDisabled(unknown)")
	require.ErrorIs(t, srv.gateway.RemoveAccount(context.Background(), "no-such-account"), ErrUnknownAccount, "RemoveAccount(unknown)")
	require.Empty(t, manager.List(), "manager holds accounts after refused changes")
}

func TestAccountChangesWithoutCoreAuthReportIt(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	gw, err := New(Params{
		Config:     &cliproxyconfig.Config{AuthDir: t.TempDir()},
		ConfigPath: filepath.Join(t.TempDir(), "unused.yaml"),
		Resolver:   wireResolver,
	})
	require.NoError(t, err, "New")

	ctx := context.Background()
	_, err = gw.AddAccount(ctx, claudeGrant(t))
	require.ErrorIs(t, err, ErrNoCoreAuth, "AddAccount")
	require.ErrorIs(t, gw.SetAccountDisabled(ctx, "any", true), ErrNoCoreAuth, "SetAccountDisabled")
	require.ErrorIs(t, gw.RemoveAccount(ctx, "any"), ErrNoCoreAuth, "RemoveAccount")
}

// TestAccountChangesWithoutAStoreRefuse: without Params.Store a change cannot
// be made durable, so it is refused before anything changes. The account the
// disable and removal are tried on is registered straight into the manager,
// since AddAccount refuses too.
func TestAccountChangesWithoutAStoreRefuse(t *testing.T) {
	params := productionParams(t)
	params.Store = nil
	srv := startWith(t, params)

	grant := claudeGrant(t)
	_, err := srv.gateway.AddAccount(context.Background(), grant)
	require.ErrorIs(t, err, ErrNoTokenStore, "AddAccount without a store")

	_, ok := params.CoreAuth.GetByID(grant.ID)
	require.False(t, ok, "a refused AddAccount left the account held")

	_, err = params.CoreAuth.Register(context.Background(), grant)
	require.NoError(t, err, "Register")
	require.ErrorIs(t, srv.gateway.SetAccountDisabled(context.Background(), grant.ID, true), ErrNoTokenStore, "SetAccountDisabled without a store")
	require.ErrorIs(t, srv.gateway.RemoveAccount(context.Background(), grant.ID), ErrNoTokenStore, "RemoveAccount without a store")

	got, ok := params.CoreAuth.GetByID(grant.ID)
	require.True(t, ok, "a refused change dropped the account")
	require.False(t, got.Disabled, "a refused change disabled the account")
}

// TestAddAccountWithdrawsAnUnsavedCredential: Register discards its save
// error, so an add that registered first and saved second would return
// success on a failed write and the account would be gone after a restart.
// A failed save adds nothing — not held, not routable, no credential left —
// so nothing serves traffic on an account the caller was told failed; a retry
// adds it.
func TestAddAccountWithdrawsAnUnsavedCredential(t *testing.T) {
	params := productionParams(t)
	store := &faultyStore{Store: params.Store}
	params.Store = store
	srv := startBooted(t, params)

	store.refuseSave.Store(true)

	grant := claudeGrant(t)
	_, err := srv.gateway.AddAccount(context.Background(), grant)
	require.ErrorIs(t, err, errSaveRefused, "AddAccount with a failing save must report the store's error")

	_, ok := params.CoreAuth.GetByID(grant.ID)
	require.False(t, ok, "the unsaved account is still held")
	require.Zero(t, registeredModels(grant.ID), "the unsaved account still has registered models")

	require.False(t, storeLists(t, params.Store, grant.FileName), "the token store lists the unsaved account's credential")

	store.refuseSave.Store(false)

	_, err = srv.gateway.AddAccount(context.Background(), grant)
	require.NoError(t, err, "retried AddAccount")
}

// TestAddAccountKeepsADisabledAccountAcrossARestart: upstream's file store
// writes nothing for a disabled account whose file does not exist yet unless
// the save says it creates one, so an account added disabled would vanish on
// restart.
func TestAddAccountKeepsADisabledAccountAcrossARestart(t *testing.T) {
	p := productionParams(t)
	authDir := p.Config.AuthDir
	srv := startBooted(t, p)
	grant := claudeGrant(t)
	grant.Disabled = true

	grant.Status = coreauth.StatusDisabled
	_, err := srv.gateway.AddAccount(context.Background(), grant)
	require.NoError(t, err, "AddAccount(disabled)")
	require.ErrorIs(t, srv.stop(), context.Canceled, "stop: Run must return context.Canceled")

	fresh := productionParamsIn(authDir)
	startWith(t, fresh)

	got, ok := fresh.CoreAuth.GetByID(grant.ID)
	require.True(t, ok, "a fresh gateway does not hold the account added disabled: it was never written")
	require.True(t, got.Disabled, "the account added disabled came back enabled after a restart")
}

// TestAccountsListsUnderPolicyNames: the admin list names providers as
// policies do (codex is chatgpt), ordered by provider, with the email and
// never a token.
func TestAccountsListsUnderPolicyNames(t *testing.T) {
	p := productionParams(t)
	srv, manager := startWith(t, p), p.CoreAuth
	codex := &coreauth.Auth{
		ID:       "codex-" + strings.ToLower(t.Name()) + ".json",
		Provider: "codex",
		Metadata: map[string]any{
			"email":        "ops@example.com",
			"access_token": "fake-codex-access-token",
			"expired":      time.Now().Add(48 * time.Hour).Format(time.RFC3339),
		},
	}
	t.Cleanup(func() { cliproxy.GlobalModelRegistry().UnregisterClient(codex.ID) })

	_, err := manager.Register(context.Background(), codex)
	require.NoError(t, err, "Register")

	grant := claudeGrant(t)
	_, err = manager.Register(context.Background(), grant)
	require.NoError(t, err, "Register")

	got := srv.gateway.Accounts()
	require.Len(t, got, 2, "Accounts()")
	require.Equal(t, codex.ID, got[0].ID, "codex account listed as %+v", got[0])
	require.Equal(t, "chatgpt", got[0].Provider, "codex account listed as %+v", got[0])
	require.Equal(t, "ops@example.com", got[0].Email, "codex account listed as %+v", got[0])
	require.Equal(t, grant.ID, got[1].ID, "claude account listed as %+v", got[1])
	require.Equal(t, "claude", got[1].Provider, "claude account listed as %+v", got[1])
	require.NotContains(t, fmt.Sprintf("%+v", got), "fake-codex-access-token", "the account list carries a token")
}

// TestNewRefusesAManagementEnvironment: MANAGEMENT_PASSWORD enables every
// /v0/management route whatever the configuration says.
func TestNewRefusesAManagementEnvironment(t *testing.T) {
	// Every variable found in upstream v7.3.18 that enables management; listed
	// here rather than read from managementEnv, so dropping one from the guard
	// fails the test.
	for _, name := range []string{"MANAGEMENT_PASSWORD"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "operator-secret")

			_, err := New(Params{
				Config:     &cliproxyconfig.Config{AuthDir: t.TempDir()},
				ConfigPath: filepath.Join(t.TempDir(), "unused.yaml"),
			})
			require.ErrorIs(t, err, ErrManagementEnv, "New with %s set", name)
			require.ErrorContains(t, err, name, "New error does not name %s", name)
		})
	}
}

// TestRunRefusesAManagementEnvironment: upstream reads MANAGEMENT_PASSWORD when
// Run builds the HTTP server, so a variable set after New must still stop Run.
func TestRunRefusesAManagementEnvironment(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")

	gw, err := New(Params{
		Config:     &cliproxyconfig.Config{Port: freePort(t), AuthDir: t.TempDir()},
		ConfigPath: filepath.Join(t.TempDir(), "unused.yaml"),
		Resolver:   wireResolver,
	})
	require.NoError(t, err, "New")

	t.Setenv("MANAGEMENT_PASSWORD", "operator-secret")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.ErrorIs(t, gw.Run(ctx), ErrManagementEnv, "Run with MANAGEMENT_PASSWORD set")
	require.ErrorIs(t, gw.WaitReload(ctx), ErrManagementEnv, "WaitReload after the refused Run")
}

// claudeBaselineUserAgent is the Claude CLI identity upstream v7.3.18 presents
// for a Claude OAuth account when the client is not Claude Code itself
// (internal/runtime/executor/helps/claude_device_profile.go
// defaultClaudeFingerprintUserAgent). Before v7.3.15 the baseline was older
// than the vendor accepts, and only a claude-header-defaults user-agent in the
// configuration kept Claude accounts usable.
const claudeBaselineUserAgent = "claude-cli/2.1.280 (external, cli)"

// TestClaudeRequestCarriesTheCLIBaseline: with no claude-header-defaults in
// the configuration, a request a non-Claude-Code client sends through a Claude
// OAuth account reaches the vendor under upstream's CLI baseline User-Agent,
// not the client's own.
func TestClaudeRequestCarriesTheCLIBaseline(t *testing.T) {
	vendor := &faketest.Vendor{Payload: []byte(`{"id":"msg_1","type":"message","role":"assistant","model":"m",` +
		`"content":[{"type":"text","text":"hello from claude"}],"stop_reason":"end_turn",` +
		`"usage":{"input_tokens":1,"output_tokens":2}}`)}
	srv := faketest.Start(t, vendor)
	// productionParams: a configuration with no claude-header-defaults.
	params := productionParams(t)
	gw := startBooted(t, params)
	// A file-backed account loses its attributes on the store round trip and
	// would go to the vendor's real host; a runtime-only one is registered as
	// given, so base_url sends it to the fake. Upstream takes an account for a
	// Claude subscription, and gives it the CLI identity, by its token's shape;
	// the account id spares the profile lookup, which goes to the real host.
	const oauthToken = "sk-ant-oat01-fake"

	grant := claudeGrant(t)
	grant.Metadata["access_token"] = oauthToken
	grant.Metadata["account_uuid"] = "5f0c6a2e-1b7d-4e3a-9c84-0d2b3a4c5e6f"

	grant.Attributes = map[string]string{"base_url": srv.URL, coreauth.AttributeRuntimeOnly: "true"}
	_, err := gw.gateway.AddAccount(context.Background(), grant)
	require.NoError(t, err, "AddAccount")
	// Nothing else may serve the request: startBooted's account has no base_url.
	for _, a := range params.CoreAuth.List() {
		if a.ID != grant.ID {
			require.NoError(t, gw.gateway.SetAccountDisabled(context.Background(), a.ID, true), "disable %s", a.ID)
		}
	}

	models := cliproxy.GlobalModelRegistry().GetModelsForClient(grant.ID)
	require.NotEmpty(t, models, "the Claude account registered no models")

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, gw.baseURL+"/v1/messages", strings.NewReader(
		`{"model":"`+models[0].ID+`","max_tokens":64,"messages":[{"role":"user","content":"say hello"}]}`))
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+wireSecret)
	req.Header.Set("User-Agent", "some-client/1.0")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err, "POST /v1/messages")

	body, _ := io.ReadAll(resp.Body)

	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "POST /v1/messages (%s)", body)
	require.Contains(t, string(body), "hello from claude", "want the vendor's answer")

	reqs := vendor.Requests()
	require.Len(t, reqs, 1, "vendor requests")
	// The account's token, so the request went through upstream's Claude
	// executor for this account and not some other route to the vendor.
	require.Equal(t, "Bearer "+oauthToken, reqs[0].Header.Get("Authorization"), "vendor Authorization must be the Claude account's token")
	require.Equal(t, claudeBaselineUserAgent, reqs[0].Header.Get("User-Agent"), "vendor User-Agent must be upstream's baseline")
}
