package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

// These tests pin upstream behaviour the account methods depend on, measured
// against v7.3.12: an upgrade that changes it must fail here.

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
// WaitReload). So the auth directory holds one credential before boot, which
// only that last step registers models for — the manager loads it without
// any, unlike a config-derived account — and startBooted returns once its
// models are in the registry. The credential is an account like any other,
// in the directory, the manager and Accounts.
func startBooted(t *testing.T, p Params) *running {
	t.Helper()
	boot := claudeGrantNamed(t, "boot-"+strconv.FormatInt(wireSeq.Add(1), 10))
	if _, err := p.Store.Save(context.Background(), boot); err != nil {
		t.Fatalf("save the boot credential: %v", err)
	}
	r := startWith(t, p)
	for deadline := time.Now().Add(10 * time.Second); registeredModels(boot.ID) == 0; time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("boot never registered the models of the account it loaded")
		}
	}
	return r
}

// TestBareRegisterLeavesAnAccountUnroutable is the reason the account methods
// exist: with the hollow watcher, registering an account straight into the
// manager registers none of its models. If this starts failing, upstream has
// fixed it and the re-apply in the account methods can go.
func TestBareRegisterLeavesAnAccountUnroutable(t *testing.T) {
	_, manager := startProduction(t)
	grant := claudeGrant(t)

	if _, err := manager.Register(context.Background(), grant); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if _, ok := manager.GetByID(grant.ID); !ok {
		t.Fatal("manager does not hold the registered account")
	}
	if n := registeredModels(grant.ID); n != 0 {
		t.Fatalf("a bare Register registered %d models: upstream now reconciles on its own", n)
	}
}

func TestAddAccountRegistersTheAccountsModels(t *testing.T) {
	r, manager := startProduction(t)
	grant := claudeGrant(t)

	stored, err := r.gateway.AddAccount(context.Background(), grant)
	if err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	if stored == nil || stored.ID != grant.ID {
		t.Fatalf("AddAccount returned %+v, want the stored account %q", stored, grant.ID)
	}
	if _, ok := manager.GetByID(grant.ID); !ok {
		t.Fatal("manager does not hold the added account")
	}
	if n := registeredModels(grant.ID); n == 0 {
		t.Fatal("the added Claude account has no registered models: it is not routable")
	}
}

func TestSetAccountDisabledUnregistersAndRestoresModels(t *testing.T) {
	r, manager := startProduction(t)
	grant := claudeGrant(t)
	if _, err := r.gateway.AddAccount(context.Background(), grant); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	enabled := registeredModels(grant.ID)
	if enabled == 0 {
		t.Fatal("the added Claude account has no registered models")
	}

	if err := r.gateway.SetAccountDisabled(context.Background(), grant.ID, true); err != nil {
		t.Fatalf("SetAccountDisabled(true): %v", err)
	}
	if n := registeredModels(grant.ID); n != 0 {
		t.Fatalf("a disabled account still has %d registered models", n)
	}
	if got, _ := manager.GetByID(grant.ID); got == nil || !got.Disabled {
		t.Fatalf("manager holds %+v, want the account disabled", got)
	}

	if err := r.gateway.SetAccountDisabled(context.Background(), grant.ID, false); err != nil {
		t.Fatalf("SetAccountDisabled(false): %v", err)
	}
	if n := registeredModels(grant.ID); n != enabled {
		t.Fatalf("a re-enabled account has %d registered models, want the %d it had", n, enabled)
	}
}

func TestRemoveAccountUnregistersModels(t *testing.T) {
	r, manager := startProduction(t)
	grant := claudeGrant(t)
	if _, err := r.gateway.AddAccount(context.Background(), grant); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	if registeredModels(grant.ID) == 0 {
		t.Fatal("the added Claude account has no registered models")
	}

	if err := r.gateway.RemoveAccount(context.Background(), grant.ID); err != nil {
		t.Fatalf("RemoveAccount: %v", err)
	}
	if _, ok := manager.GetByID(grant.ID); ok {
		t.Fatal("manager still holds the removed account")
	}
	if n := registeredModels(grant.ID); n != 0 {
		t.Fatalf("the removed account still has %d registered models: they would be listed with no credential behind them", n)
	}
}

// TestRemoveAccountDeletesTheCredentialAcrossARestart: a removed account must
// stay removed when a fresh gateway starts on the same auth directory. The kept
// account shows the fresh gateway does load what the directory holds, so the
// removed one's absence is not an empty boot. The removed account's file name
// differs from its id, so deleting by id alone would miss the file.
func TestRemoveAccountDeletesTheCredentialAcrossARestart(t *testing.T) {
	p := productionParams(t)
	authDir := p.Config.AuthDir
	r := startBooted(t, p)
	kept := claudeGrantNamed(t, t.Name()+"-kept")
	removed := claudeGrantNamed(t, t.Name()+"-removed")
	removed.FileName = "file-of-" + removed.ID
	for _, grant := range []*coreauth.Auth{kept, removed} {
		if _, err := r.gateway.AddAccount(context.Background(), grant); err != nil {
			t.Fatalf("AddAccount(%s): %v", grant.ID, err)
		}
		if _, err := os.Stat(filepath.Join(authDir, grant.FileName)); err != nil {
			t.Fatalf("the added account's credential was not persisted: %v", err)
		}
	}

	if err := r.gateway.RemoveAccount(context.Background(), removed.ID); err != nil {
		t.Fatalf("RemoveAccount: %v", err)
	}
	if _, err := os.Stat(filepath.Join(authDir, removed.FileName)); !os.IsNotExist(err) {
		t.Fatalf("the removed account's credential is still in the auth directory (stat: %v)", err)
	}
	if err := r.stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("stop: Run returned %v, want context.Canceled", err)
	}

	fresh := productionParamsIn(authDir)
	startWith(t, fresh)
	if _, ok := fresh.CoreAuth.GetByID(kept.ID); !ok {
		t.Fatal("a fresh gateway did not load the kept account: the restart proves nothing")
	}
	// A credential loaded from the directory takes its file name as its id.
	for _, id := range []string{removed.ID, removed.FileName} {
		if got, ok := fresh.CoreAuth.GetByID(id); ok {
			t.Fatalf("a fresh gateway resurrected the removed account as %q (disabled=%t)", id, got.Disabled)
		}
	}
}

// TestRemoveAccountDeletesACredentialInASubdirectory: a file name with a
// separator — upstream puts the raw account email into Claude file names —
// is saved under the auth directory. The file store's Delete would resolve
// such a key against the working directory and report the missing file as
// success, and the store lists subdirectories, so a fresh gateway would load
// the account again. The name climbs with ".." but stays inside, so AddAccount
// must accept it: the containment check is on the resolved path, not the text.
func TestRemoveAccountDeletesACredentialInASubdirectory(t *testing.T) {
	p := productionParams(t)
	authDir := p.Config.AuthDir
	r := startBooted(t, p)
	grant := claudeGrant(t)
	grant.FileName = "team/sub/../" + grant.ID
	if _, err := r.gateway.AddAccount(context.Background(), grant); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	inTeam := filepath.Join("team", grant.ID)
	onDisk := filepath.Join(authDir, inTeam)
	if _, err := os.Stat(onDisk); err != nil {
		t.Fatalf("the added account's credential was not persisted under the auth directory: %v", err)
	}

	if err := r.gateway.RemoveAccount(context.Background(), grant.ID); err != nil {
		t.Fatalf("RemoveAccount: %v", err)
	}
	if _, err := os.Stat(onDisk); !os.IsNotExist(err) {
		t.Fatalf("the removed account's credential is still at %s (stat: %v)", onDisk, err)
	}
	if err := r.stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("stop: Run returned %v, want context.Canceled", err)
	}

	fresh := productionParamsIn(authDir)
	startWith(t, fresh)
	for _, id := range []string{grant.ID, inTeam} {
		if got, ok := fresh.CoreAuth.GetByID(id); ok {
			t.Fatalf("a fresh gateway resurrected the removed account as %q (disabled=%t)", id, got.Disabled)
		}
	}
}

// TestRemoveAccountRefusesACredentialOutsideTheAuthDirectory: a credential
// that lies outside the auth directory is refused before anything changes, and
// the file it names is not touched. AddAccount refuses such an account, so it
// is registered straight into the manager, which persists it where the name
// points.
func TestRemoveAccountRefusesACredentialOutsideTheAuthDirectory(t *testing.T) {
	parent := t.TempDir()
	p := productionParamsIn(filepath.Join(parent, "auths"))
	r := startWith(t, p)
	grant := claudeGrant(t)
	grant.FileName = filepath.Join("..", grant.ID)
	if _, err := p.CoreAuth.Register(context.Background(), grant); err != nil {
		t.Fatalf("Register: %v", err)
	}
	outside := filepath.Join(parent, grant.ID)
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("upstream did not write the escaping credential where the test expects it: %v", err)
	}

	err := r.gateway.RemoveAccount(context.Background(), grant.ID)
	if !errors.Is(err, ErrCredentialPath) {
		t.Fatalf("RemoveAccount of a credential outside the auth directory = %v, want ErrCredentialPath", err)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("the refused removal touched the file outside the auth directory: %v", err)
	}
	if got, ok := p.CoreAuth.GetByID(grant.ID); !ok || got.Disabled {
		t.Fatalf("a refused removal changed the account: held=%t %+v", ok, got)
	}
}

// TestAddAccountRefusesACredentialOutsideTheAuthDirectory: Save writes to the
// first of the path attribute, the file name and the id that is set, so each
// one that escapes is refused before Register — including one Save would not
// use now, which a later save without the path attribute would fall back to.
// Nothing is written and nothing is held.
func TestAddAccountRefusesACredentialOutsideTheAuthDirectory(t *testing.T) {
	for _, tc := range []struct {
		name   string
		escape func(grant *coreauth.Auth, parent string)
	}{
		{"file name", func(grant *coreauth.Auth, _ string) {
			grant.FileName = "team/../../" + grant.ID
		}},
		{"id", func(grant *coreauth.Auth, _ string) {
			grant.ID = "../" + grant.ID
		}},
		{"path attribute", func(grant *coreauth.Auth, parent string) {
			grant.Attributes = map[string]string{coreauth.AttributePath: filepath.Join(parent, grant.FileName)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			authDir := filepath.Join(parent, "auths")
			p := productionParamsIn(authDir)
			r := startWith(t, p)
			grant := claudeGrantNamed(t, strings.ReplaceAll(t.Name(), "/", "-"))
			tc.escape(grant, parent)

			_, err := r.gateway.AddAccount(context.Background(), grant)
			if !errors.Is(err, ErrCredentialPath) {
				t.Errorf("AddAccount of a credential outside the auth directory = %v, want ErrCredentialPath", err)
			}
			if n := len(p.CoreAuth.List()); n != 0 {
				t.Errorf("manager holds %d accounts after a refused AddAccount, want 0", n)
			}
			if n := registeredModels(grant.ID); n != 0 {
				t.Errorf("a refused account has %d registered models", n)
			}
			_ = filepath.WalkDir(parent, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					t.Fatalf("walk %s: %v", path, err)
				}
				if !d.IsDir() {
					t.Errorf("a refused AddAccount left %s on disk", path)
				}
				return nil
			})
		})
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
	p := productionParams(t)
	store := &faultyStore{Store: p.Store}
	p.Store = store
	r := startBooted(t, p)
	grant := claudeGrant(t)
	if _, err := r.gateway.AddAccount(context.Background(), grant); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}

	store.refuseSave.Store(true)
	err := r.gateway.SetAccountDisabled(context.Background(), grant.ID, true)
	if !errors.Is(err, errSaveRefused) {
		t.Fatalf("SetAccountDisabled with a failing save = %v, want the store's error", err)
	}
	got, ok := p.CoreAuth.GetByID(grant.ID)
	if !ok {
		t.Fatal("the manager dropped the account after a failed save")
	}
	if !got.Disabled {
		t.Fatal("after a failed save the account is enabled in memory, want it kept disabled as requested")
	}
	if n := registeredModels(grant.ID); n != 0 {
		t.Fatalf("the account disabled in memory still has %d registered models", n)
	}

	store.refuseSave.Store(false)
	if err := r.gateway.SetAccountDisabled(context.Background(), grant.ID, true); err != nil {
		t.Fatalf("retried SetAccountDisabled: %v", err)
	}
}

// TestRemoveAccountReportsAnUndeletedCredential pins the failure mode
// RemoveAccount allows: when the store delete fails, the account is left
// disabled, unroutable and still held, the error says so, and a retry finishes
// the removal. Removing from memory before deleting would leave nothing to retry.
func TestRemoveAccountReportsAnUndeletedCredential(t *testing.T) {
	p := productionParams(t)
	store := &faultyStore{Store: p.Store}
	p.Store = store
	r := startBooted(t, p)
	grant := claudeGrant(t)
	if _, err := r.gateway.AddAccount(context.Background(), grant); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}

	store.refuseDelete.Store(true)
	err := r.gateway.RemoveAccount(context.Background(), grant.ID)
	if !errors.Is(err, errDeleteRefused) {
		t.Fatalf("RemoveAccount with a failing store = %v, want the store's error", err)
	}
	if !strings.Contains(err.Error(), "disabled but still held") {
		t.Fatalf("RemoveAccount error %q does not name the partial state", err)
	}
	got, ok := p.CoreAuth.GetByID(grant.ID)
	if !ok {
		t.Fatal("the account is gone from the manager although its credential was not deleted: a retry cannot reach it")
	}
	if !got.Disabled {
		t.Fatal("the account whose credential could not be deleted is still enabled")
	}
	if n := registeredModels(grant.ID); n != 0 {
		t.Fatalf("the half-removed account still has %d registered models", n)
	}

	store.refuseDelete.Store(false)
	if err := r.gateway.RemoveAccount(context.Background(), grant.ID); err != nil {
		t.Fatalf("retried RemoveAccount: %v", err)
	}
	if _, ok := p.CoreAuth.GetByID(grant.ID); ok {
		t.Fatal("manager still holds the account after the retry")
	}
	if _, err := os.Stat(filepath.Join(p.Config.AuthDir, grant.ID)); !os.IsNotExist(err) {
		t.Fatalf("the credential survived the retry (stat: %v)", err)
	}
}

// TestRemoveAccountReportsAnUnsavedDisable: when the delete fails, the
// credential left behind must say disabled; if that save fails too, the error
// reports it, because the file may still say enabled.
func TestRemoveAccountReportsAnUnsavedDisable(t *testing.T) {
	p := productionParams(t)
	store := &faultyStore{Store: p.Store}
	p.Store = store
	r := startBooted(t, p)
	grant := claudeGrant(t)
	if _, err := r.gateway.AddAccount(context.Background(), grant); err != nil {
		t.Fatalf("AddAccount: %v", err)
	}

	store.refuseDelete.Store(true)
	store.refuseSave.Store(true)
	err := r.gateway.RemoveAccount(context.Background(), grant.ID)
	if !errors.Is(err, errDeleteRefused) || !errors.Is(err, errSaveRefused) {
		t.Fatalf("RemoveAccount with delete and save failing = %v, want both errors", err)
	}
	if _, ok := p.CoreAuth.GetByID(grant.ID); !ok {
		t.Fatal("the account is gone from the manager although its credential was not deleted")
	}
}

func TestAccountChangesRefuseAnUnknownAccount(t *testing.T) {
	p := productionParams(t)
	r, manager := startWith(t, p), p.CoreAuth

	if err := r.gateway.SetAccountDisabled(context.Background(), "no-such-account", true); !errors.Is(err, ErrUnknownAccount) {
		t.Fatalf("SetAccountDisabled(unknown) = %v, want ErrUnknownAccount", err)
	}
	if err := r.gateway.RemoveAccount(context.Background(), "no-such-account"); !errors.Is(err, ErrUnknownAccount) {
		t.Fatalf("RemoveAccount(unknown) = %v, want ErrUnknownAccount", err)
	}
	if n := len(manager.List()); n != 0 {
		t.Fatalf("manager holds %d accounts after refused changes, want 0", n)
	}
}

func TestAccountChangesWithoutCoreAuthReportIt(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	g, err := New(Params{
		Config:     &cliproxyconfig.Config{AuthDir: t.TempDir()},
		ConfigPath: filepath.Join(t.TempDir(), "unused.yaml"),
		Resolver:   wireResolver,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := g.AddAccount(ctx, claudeGrant(t)); !errors.Is(err, ErrNoCoreAuth) {
		t.Fatalf("AddAccount = %v, want ErrNoCoreAuth", err)
	}
	if err := g.SetAccountDisabled(ctx, "any", true); !errors.Is(err, ErrNoCoreAuth) {
		t.Fatalf("SetAccountDisabled = %v, want ErrNoCoreAuth", err)
	}
	if err := g.RemoveAccount(ctx, "any"); !errors.Is(err, ErrNoCoreAuth) {
		t.Fatalf("RemoveAccount = %v, want ErrNoCoreAuth", err)
	}
}

// TestAccountChangesWithoutAStoreRefuse: without Params.Store a change cannot
// be made durable, so it is refused before anything changes. The account the
// disable and removal are tried on is registered straight into the manager,
// since AddAccount refuses too.
func TestAccountChangesWithoutAStoreRefuse(t *testing.T) {
	p := productionParams(t)
	p.Store = nil
	r := startWith(t, p)
	grant := claudeGrant(t)
	if _, err := r.gateway.AddAccount(context.Background(), grant); !errors.Is(err, ErrNoTokenStore) {
		t.Fatalf("AddAccount without a store = %v, want ErrNoTokenStore", err)
	}
	if _, ok := p.CoreAuth.GetByID(grant.ID); ok {
		t.Fatal("a refused AddAccount left the account held")
	}
	if _, err := p.CoreAuth.Register(context.Background(), grant); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := r.gateway.SetAccountDisabled(context.Background(), grant.ID, true); !errors.Is(err, ErrNoTokenStore) {
		t.Fatalf("SetAccountDisabled without a store = %v, want ErrNoTokenStore", err)
	}
	if err := r.gateway.RemoveAccount(context.Background(), grant.ID); !errors.Is(err, ErrNoTokenStore) {
		t.Fatalf("RemoveAccount without a store = %v, want ErrNoTokenStore", err)
	}
	if got, ok := p.CoreAuth.GetByID(grant.ID); !ok || got.Disabled {
		t.Fatalf("a refused change altered the account: held=%t %+v", ok, got)
	}
}

// TestAddAccountWithdrawsAnUnsavedCredential: Register discards its save
// error, so without the gateway's own save a failed write would return
// success and the account would be gone after a restart. The failed add is
// withdrawn — not held, not routable, no credential left — so nothing serves
// traffic on an account the caller was told failed; a retry adds it.
func TestAddAccountWithdrawsAnUnsavedCredential(t *testing.T) {
	p := productionParams(t)
	store := &faultyStore{Store: p.Store}
	p.Store = store
	r := startBooted(t, p)
	store.refuseSave.Store(true)

	grant := claudeGrant(t)
	if _, err := r.gateway.AddAccount(context.Background(), grant); !errors.Is(err, errSaveRefused) {
		t.Fatalf("AddAccount with a failing save = %v, want the store's error", err)
	}
	if got, ok := p.CoreAuth.GetByID(grant.ID); ok {
		t.Fatalf("the unsaved account is still held (disabled=%t)", got.Disabled)
	}
	if n := registeredModels(grant.ID); n != 0 {
		t.Fatalf("the unsaved account still has %d registered models", n)
	}
	if _, err := os.Stat(filepath.Join(p.Config.AuthDir, grant.FileName)); !os.IsNotExist(err) {
		t.Fatalf("the unsaved account's credential is in the auth directory (stat: %v)", err)
	}

	store.refuseSave.Store(false)
	if _, err := r.gateway.AddAccount(context.Background(), grant); err != nil {
		t.Fatalf("retried AddAccount: %v", err)
	}
}

// TestAddAccountKeepsADisabledAccountAcrossARestart: upstream's file store
// writes nothing for a disabled account whose file does not exist yet unless
// the save says it creates one, so an account added disabled would vanish on
// restart.
func TestAddAccountKeepsADisabledAccountAcrossARestart(t *testing.T) {
	p := productionParams(t)
	authDir := p.Config.AuthDir
	r := startBooted(t, p)
	grant := claudeGrant(t)
	grant.Disabled = true
	grant.Status = coreauth.StatusDisabled
	if _, err := r.gateway.AddAccount(context.Background(), grant); err != nil {
		t.Fatalf("AddAccount(disabled): %v", err)
	}
	if err := r.stop(); !errors.Is(err, context.Canceled) {
		t.Fatalf("stop: Run returned %v, want context.Canceled", err)
	}

	fresh := productionParamsIn(authDir)
	startWith(t, fresh)
	got, ok := fresh.CoreAuth.GetByID(grant.ID)
	if !ok {
		t.Fatal("a fresh gateway does not hold the account added disabled: it was never written")
	}
	if !got.Disabled {
		t.Fatal("the account added disabled came back enabled after a restart")
	}
}

// TestAccountsListsUnderPolicyNames: the admin list names providers as
// policies do (codex is chatgpt), ordered by provider, with the email and
// never a token.
func TestAccountsListsUnderPolicyNames(t *testing.T) {
	p := productionParams(t)
	r, manager := startWith(t, p), p.CoreAuth
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
	if _, err := manager.Register(context.Background(), codex); err != nil {
		t.Fatalf("Register: %v", err)
	}
	grant := claudeGrant(t)
	if _, err := manager.Register(context.Background(), grant); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got := r.gateway.Accounts()
	if len(got) != 2 {
		t.Fatalf("Accounts() = %+v, want 2 accounts", got)
	}
	if got[0].ID != codex.ID || got[0].Provider != "chatgpt" || got[0].Email != "ops@example.com" {
		t.Fatalf("codex account listed as %+v, want provider chatgpt with its email", got[0])
	}
	if got[1].ID != grant.ID || got[1].Provider != "claude" {
		t.Fatalf("claude account listed as %+v", got[1])
	}
	if strings.Contains(fmt.Sprintf("%+v", got), "fake-codex-access-token") {
		t.Fatal("the account list carries a token")
	}
}

// TestNewRefusesAManagementEnvironment: MANAGEMENT_PASSWORD enables every
// /v0/management route whatever the configuration says.
func TestNewRefusesAManagementEnvironment(t *testing.T) {
	// Every variable found in upstream v7.3.12 that enables management; listed
	// here rather than read from managementEnv, so dropping one from the guard
	// fails the test.
	for _, name := range []string{"MANAGEMENT_PASSWORD"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "operator-secret")
			_, err := New(Params{
				Config:     &cliproxyconfig.Config{AuthDir: t.TempDir()},
				ConfigPath: filepath.Join(t.TempDir(), "unused.yaml"),
			})
			if !errors.Is(err, ErrManagementEnv) {
				t.Fatalf("New with %s set = %v, want ErrManagementEnv", name, err)
			}
			if !strings.Contains(err.Error(), name) {
				t.Fatalf("New error %q does not name %s", err, name)
			}
		})
	}
}

// TestRunRefusesAManagementEnvironment: upstream reads MANAGEMENT_PASSWORD when
// Run builds the HTTP server, so a variable set after New must still stop Run.
func TestRunRefusesAManagementEnvironment(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "")
	g, err := New(Params{
		Config:     &cliproxyconfig.Config{Port: freePort(t), AuthDir: t.TempDir()},
		ConfigPath: filepath.Join(t.TempDir(), "unused.yaml"),
		Resolver:   wireResolver,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Setenv("MANAGEMENT_PASSWORD", "operator-secret")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := g.Run(ctx); !errors.Is(err, ErrManagementEnv) {
		t.Fatalf("Run with MANAGEMENT_PASSWORD set = %v, want ErrManagementEnv", err)
	}
	if err := g.WaitReload(ctx); !errors.Is(err, ErrManagementEnv) {
		t.Fatalf("WaitReload after the refused Run = %v, want ErrManagementEnv", err)
	}
}
