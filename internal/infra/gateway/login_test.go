package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/gin-gonic/gin"
	sdkapi "github.com/router-for-me/CLIProxyAPI/v7/sdk/api"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeOAuth is upstream's management start handler with the vendor's code
// exchange replaced, keeping everything the gateway relies on as upstream
// v7.3.15 does it (auth_files_provider_oauth.go RequestAnthropicToken): the
// real session registry, the callback file in the auth directory read and
// deleted by a poller, the state check, the pre-save pending guard and the
// post-auth hook given the start request's context. The real handler is
// exercised by TestLoginStartsWithoutAListener and
// TestLoginHandsTheCallbackToUpstream; only the exchange, which needs the
// vendor, is faked.
type fakeOAuth struct {
	authDir string
	hook    coreauth.PostAuthHook
	// grant is the account the exchange of code yields.
	grant func(code string) *coreauth.Auth
	// refuse, when set, gives the session error a refused exchange of code
	// reports.
	refuse func(code, state string) string
	// hold, when set, blocks every exchange until it is closed.
	hold chan struct{}
	// failStart makes the start request fail as upstream's does when it
	// cannot build a URL.
	failStart bool

	mu      sync.Mutex
	states  []string
	hooked  int
	stopped chan string // receives a state when its poller has returned
}

func newFakeOAuth(authDir string, grant func(code string) *coreauth.Auth) *fakeOAuth {
	return &fakeOAuth{authDir: authDir, grant: grant, stopped: make(chan string, 64)}
}

func (f *fakeOAuth) start(ginCtx *gin.Context) {
	if f.failStart {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate authorization url"})

		return
	}

	state, err := loginSessionID()
	if err != nil {
		ginCtx.JSON(http.StatusInternalServerError, gin.H{"error": "state"})

		return
	}

	sdkapi.RegisterOAuthSession(state, "anthropic")
	f.mu.Lock()
	f.states = append(f.states, state)
	f.mu.Unlock()

	ctx := sdkapi.PopulateAuthContext(context.Background(), ginCtx)
	go f.wait(ctx, state)

	ginCtx.JSON(http.StatusOK, gin.H{"status": "ok", "url": "https://vendor.example/oauth/authorize?state=" + state, "state": state})
}

func (f *fakeOAuth) wait(ctx context.Context, state string) {
	defer func() { f.stopped <- state }()

	path := filepath.Join(f.authDir, ".oauth-anthropic-"+state+".oauth")

	var fields map[string]string

	for {
		if !sdkapi.IsOAuthSessionPending(state, "anthropic") {
			return
		}

		if data, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(data, &fields)
			_ = os.Remove(path)

			break
		}

		time.Sleep(10 * time.Millisecond)
	}

	if fields["state"] != state {
		sdkapi.SetOAuthSessionError(state, "State code error")

		return
	}

	if f.hold != nil {
		<-f.hold
	}

	if f.refuse != nil {
		sdkapi.SetOAuthSessionError(state, f.refuse(fields["code"], state))

		return
	}

	record := f.grant(fields["code"])

	if !sdkapi.IsOAuthSessionPending(state, "anthropic") { // guardOAuthSessionPendingForSave
		return
	}

	f.mu.Lock()
	f.hooked++
	f.mu.Unlock()

	if err := f.hook(ctx, record); err != nil {
		sdkapi.SetOAuthSessionError(state, "Failed to save authentication tokens")

		return
	}

	sdkapi.CompleteOAuthSession(state)
}

// awaitStopped waits until the poller of state has returned.
func (f *fakeOAuth) awaitStopped(t *testing.T, state string) {
	t.Helper()

	deadline := time.After(5 * time.Second)

	for {
		select {
		case s := <-f.stopped:
			if s == state {
				return
			}
		case <-deadline:
			require.Fail(t, "upstream's waiter for the login is still running: the login was not ended")
		}
	}
}

func (f *fakeOAuth) hookCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.hooked
}

// recordingAdd stands in for Gateway.AddAccount.
type recordingAdd struct {
	mu    sync.Mutex
	added []*coreauth.Auth
}

func (r *recordingAdd) add(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.added = append(r.added, auth)

	return auth, nil
}

func (r *recordingAdd) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	return len(r.added)
}

func codeGrant(code string) *coreauth.Auth {
	return &coreauth.Auth{ID: "claude-" + code + ".json", Provider: "claude", Metadata: map[string]any{"email": code + "@example.com"}}
}

// fakeLogin is a Login whose only provider, "claude", is vendor, adding
// through add.
func fakeLogin(t *testing.T, grant func(string) *coreauth.Auth, add func(context.Context, *coreauth.Auth) (*coreauth.Auth, error)) (*Login, *fakeOAuth) {
	t.Helper()
	authDir := t.TempDir()
	vendor := newFakeOAuth(authDir, grant)
	login := newLogin(add, authDir, map[string]loginFlow{"claude": {upstream: "anthropic", start: vendor.start}})
	vendor.hook = login.deliver

	t.Cleanup(func() { endLogins(login) })

	return login, vendor
}

// endLogins ends every login still in progress, so no upstream waiter outlives
// its test.
func endLogins(login *Login) {
	login.mu.Lock()

	pending := make(map[string]*pendingLogin, len(login.sessions))
	maps.Copy(pending, login.sessions)
	login.mu.Unlock()

	for id, p := range pending {
		login.finish(id, p)
	}
}

func stateOf(t *testing.T, authURL string) string {
	t.Helper()

	u, err := url.Parse(authURL)
	require.NoError(t, err, "auth URL %q", authURL)

	state := u.Query().Get("state")
	require.NotEmpty(t, state, "auth URL %q carries no state", authURL)

	return state
}

// callbackFor is the URL the vendor would send the browser to after a sign-in
// started from authURL, carrying code.
func callbackFor(t *testing.T, authURL, code string) string {
	t.Helper()

	return "http://localhost:54545/callback?code=" + code + "&state=" + stateOf(t, authURL)
}

// TestLoginStartThenCompleteAddsTheAccount drives the wizard end to end into a
// running gateway: the account the pasted callback's code yields is held,
// routable and persisted, and upstream saved nothing itself.
func TestLoginStartThenCompleteAddsTheAccount(t *testing.T) {
	params := productionParams(t)
	srv := startBooted(t, params)
	grant := claudeGrant(t)
	login, _ := fakeLogin(t, func(code string) *coreauth.Auth {
		assert.Equal(t, "code-1", code, "the exchange got a code other than the pasted one")

		return grant
	}, srv.gateway.AddAccount)

	before := time.Now()

	session, err := login.StartLogin(context.Background(), "claude")
	require.NoError(t, err, "StartLogin")

	require.NotEmpty(t, session.SessionID, "session id: want our own id")
	require.NotEqual(t, stateOf(t, session.AuthURL), session.SessionID, "session id: want our own id, not upstream's state")

	require.False(t, session.ExpiresAt.Before(before.Add(loginTTL)), "ExpiresAt = %v, want %s after the start", session.ExpiresAt, loginTTL)
	require.False(t, session.ExpiresAt.After(time.Now().Add(loginTTL)), "ExpiresAt = %v, want %s after the start", session.ExpiresAt, loginTTL)

	account, err := login.CompleteLogin(context.Background(), session.SessionID, callbackFor(t, session.AuthURL, "code-1"))
	require.NoError(t, err, "CompleteLogin")

	require.Equal(t, grant.ID, account.ID, "CompleteLogin account")
	require.Equal(t, "claude", account.Provider, "CompleteLogin provider")

	_, ok := params.CoreAuth.GetByID(grant.ID)
	require.True(t, ok, "the completed login's account is not held by the manager")

	require.NotZero(t, registeredModels(grant.ID), "the completed login's account has no registered models: it is not routable")

	_, err = os.Stat(filepath.Join(params.Config.AuthDir, grant.FileName))
	require.NoError(t, err, "the completed login's credential was not persisted")
}

// claudeTokenFile is a login record's token storage, as upstream's
// ClaudeTokenStorage is: the tokens live only here, not in the record's
// Metadata, and SaveTokenToFile writes them with the metadata the store
// injects. The token is valid for two days, so nothing tries to refresh it.
// fail, when set, is what the write returns instead.
type claudeTokenFile struct {
	accessToken, refreshToken, email string
	fail                             error
	metadata                         map[string]any
}

func (s *claudeTokenFile) SetMetadata(m map[string]any) { s.metadata = m }

func (s *claudeTokenFile) SaveTokenToFile(path string) error {
	if s.fail != nil {
		return s.fail
	}

	data := make(map[string]any, len(s.metadata)+5)
	maps.Copy(data, s.metadata)

	data["type"] = "claude"
	data["access_token"] = s.accessToken
	data["refresh_token"] = s.refreshToken
	data["email"] = s.email
	data["expired"] = time.Now().Add(48 * time.Hour).Format(time.RFC3339)

	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}

	return os.WriteFile(path, raw, 0o600)
}

// storageGrant is the record upstream's Claude exchange hands the post-auth
// hook (auth_files_provider_oauth.go RequestAnthropicToken): the tokens in
// Storage, only the email in Metadata.
func storageGrant(t *testing.T, storage *claudeTokenFile) *coreauth.Auth {
	t.Helper()

	id := "claude-" + storage.email + ".json"

	t.Cleanup(func() { cliproxy.GlobalModelRegistry().UnregisterClient(id) })

	return &coreauth.Auth{ID: id, Provider: "claude", FileName: id, Storage: storage, Metadata: map[string]any{"email": storage.email}}
}

// TestLoginHoldsTheAccountWithItsTokens: the executors read an account's
// token from its Metadata, but a login record carries its tokens only in
// Storage. The account a completed login leaves in the manager must be the
// one a restart loads from its file: tokens in Metadata, the file's path, and
// active — or every request goes upstream without a credential until the
// next restart.
func TestLoginHoldsTheAccountWithItsTokens(t *testing.T) {
	params := productionParams(t)
	r := startBooted(t, params)
	storage := &claudeTokenFile{accessToken: "sk-ant-oat-wizard", refreshToken: "sk-ant-ort-wizard", email: "wizard@example.com"}
	grant := storageGrant(t, storage)
	login, _ := fakeLogin(t, func(string) *coreauth.Auth { return grant }, r.gateway.AddAccount)

	session, err := login.StartLogin(context.Background(), "claude")
	require.NoError(t, err, "StartLogin")

	account, err := login.CompleteLogin(context.Background(), session.SessionID, callbackFor(t, session.AuthURL, "code-1"))
	require.NoError(t, err, "CompleteLogin")

	require.Equal(t, grant.FileName, account.ID, "CompleteLogin account")
	require.Equal(t, storage.email, account.Email, "CompleteLogin account email")

	held, ok := params.CoreAuth.GetByID(account.ID)
	require.True(t, ok, "the completed login's account is not held by the manager")

	assert.Equal(t, storage.accessToken, held.Metadata["access_token"],
		"held account's Metadata[access_token]: want the login's token, requests would carry no credential")
	assert.Equal(t, storage.refreshToken, held.Metadata["refresh_token"], "held account's Metadata[refresh_token]")
	assert.Equal(t, filepath.Join(params.Config.AuthDir, grant.FileName), held.Attributes[coreauth.AttributePath],
		"held account's path attribute: want its credential")
	assert.Equal(t, coreauth.StatusActive, held.Status, "held account status")
	assert.False(t, held.Disabled, "held account is disabled")
	assert.NotZero(t, registeredModels(account.ID), "the completed login's account has no registered models: it is not routable")
}

// TestLoginWithAnUnsavedCredentialAddsNothing: when the token store cannot
// write the login's credential, the login fails and nothing is held,
// routable or on disk, so no account serves traffic that a restart drops.
func TestLoginWithAnUnsavedCredentialAddsNothing(t *testing.T) {
	params := productionParams(t)
	r := startBooted(t, params)
	errWrite := errors.New("token file write refused by test")
	storage := &claudeTokenFile{accessToken: "sk-ant-oat-unsaved", refreshToken: "sk-ant-ort-unsaved", email: "unsaved@example.com", fail: errWrite}
	grant := storageGrant(t, storage)
	login, _ := fakeLogin(t, func(string) *coreauth.Auth { return grant }, r.gateway.AddAccount)

	session, err := login.StartLogin(context.Background(), "claude")
	require.NoError(t, err, "StartLogin")

	_, err = login.CompleteLogin(context.Background(), session.SessionID, callbackFor(t, session.AuthURL, "code-1"))
	require.ErrorIs(t, err, errWrite, "CompleteLogin with a failing credential write: want the write's error")

	got, ok := params.CoreAuth.GetByID(grant.ID)
	require.False(t, ok, "the unsaved login's account is held (disabled=%t)", got != nil && got.Disabled)

	require.Zero(t, registeredModels(grant.ID), "the unsaved login's account has registered models")

	_, err = os.Stat(filepath.Join(params.Config.AuthDir, grant.FileName))
	require.ErrorIs(t, err, os.ErrNotExist, "the unsaved login's credential is in the auth directory")
}

// listeningSockets returns the inodes of this process's listening TCP
// sockets: its socket descriptors matched against the kernel's LISTEN rows.
func listeningSockets(t *testing.T) map[string]bool {
	t.Helper()

	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("no /proc/self/fd: %v", err)
	}

	own := make(map[string]bool)

	for _, fd := range fds {
		link, err := os.Readlink("/proc/self/fd/" + fd.Name())
		if err == nil && strings.HasPrefix(link, "socket:[") {
			own[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
		}
	}

	listening := make(map[string]bool)

	for _, table := range []string{"/proc/self/net/tcp", "/proc/self/net/tcp6"} {
		file, err := os.Open(table)
		if err != nil {
			continue
		}

		rows := bufio.NewScanner(file)
		for rows.Scan() {
			fields := strings.Fields(rows.Text())
			if len(fields) > 9 && fields[3] == "0A" && own[fields[9]] {
				listening[fields[9]] = true
			}
		}

		_ = file.Close()
	}

	return listening
}

// TestLoginStartsWithoutAListener runs upstream's real start handlers: each
// returns a vendor authorisation URL, and no listening socket appears while
// the logins are pending. Providers go by their policy names.
func TestLoginStartsWithoutAListener(t *testing.T) {
	r, _ := startProduction(t)
	login := NewLogin(r.gateway)

	t.Cleanup(func() { endLogins(login) })

	before := listeningSockets(t)
	require.NotEmpty(t, before, "found no listening socket of this process, not even the gateway's: the probe proves nothing")

	for _, provider := range []string{"claude", "chatgpt"} {
		session, err := login.StartLogin(context.Background(), provider)
		require.NoError(t, err, "StartLogin(%s)", provider)

		const want = "want the vendor's https authorisation URL with state and PKCE challenge"

		u, err := url.Parse(session.AuthURL)
		require.NoError(t, err, "StartLogin(%s) AuthURL = %q: %s", provider, session.AuthURL, want)
		require.Equal(t, "https", u.Scheme, "StartLogin(%s) AuthURL = %q: %s", provider, session.AuthURL, want)
		require.NotEmpty(t, u.Query().Get("state"), "StartLogin(%s) AuthURL = %q: %s", provider, session.AuthURL, want)
		require.NotEmpty(t, u.Query().Get("code_challenge"), "StartLogin(%s) AuthURL = %q: %s", provider, session.AuthURL, want)
	}

	for inode := range listeningSockets(t) {
		require.True(t, before[inode], "a listening socket (inode %s) appeared while logins were pending", inode)
	}

	_, err := login.StartLogin(context.Background(), "codex")
	require.ErrorIs(t, err, app.ErrUnsupportedProvider, "StartLogin(codex): the wizard speaks policy names")
}

// TestLoginHandsTheCallbackToUpstream runs upstream's real Codex flow with the
// vendor unreachable (a proxy on a closed port): upstream picks up the
// callback file CompleteLogin writes, fails the exchange, and the login
// reports login_failed. Nothing is added.
func TestLoginHandsTheCallbackToUpstream(t *testing.T) {
	params := productionParams(t)
	params.Config.ProxyURL = "http://" + net127(freePort(t))
	r := startWith(t, params)
	login := NewLogin(r.gateway)

	t.Cleanup(func() { endLogins(login) })

	session, err := login.StartLogin(context.Background(), "chatgpt")
	require.NoError(t, err, "StartLogin")

	state := stateOf(t, session.AuthURL)

	_, err = login.CompleteLogin(context.Background(), session.SessionID,
		"http://localhost:1455/auth/callback?code=vendor-code&state="+state)
	require.ErrorIs(t, err, app.ErrLoginFailed, "CompleteLogin with the exchange failing")

	require.NotContains(t, err.Error(), "vendor-code", "the error carries the code")
	require.NotContains(t, err.Error(), state, "the error carries the state")

	_, err = os.Stat(filepath.Join(params.Config.AuthDir, ".oauth-codex-"+state+".oauth"))
	require.ErrorIs(t, err, os.ErrNotExist, "the callback file is still in the auth directory: upstream did not read it")

	require.Empty(t, params.CoreAuth.List(), "a failed login left accounts")
}

func net127(port int) string { return "127.0.0.1:" + strconv.Itoa(port) }

// TestLoginRefusesACallbackForAnotherSignIn: a pasted URL whose state is not
// the session's is login_failed, reaches no exchange and adds nothing, and
// the session stays completable with its own callback.
func TestLoginRefusesACallbackForAnotherSignIn(t *testing.T) {
	adds := &recordingAdd{}
	login, vendor := fakeLogin(t, codeGrant, adds.add)

	session, err := login.StartLogin(context.Background(), "claude")
	require.NoError(t, err, "StartLogin")

	other := "http://localhost:54545/callback?code=stolen&state=someone-elses-state"
	_, err = login.CompleteLogin(context.Background(), session.SessionID, other)
	require.ErrorIs(t, err, app.ErrLoginFailed, "CompleteLogin with another sign-in's callback")

	require.Zero(t, adds.count(), "a callback for another sign-in added accounts")
	require.Zero(t, vendor.hookCalls(), "a callback for another sign-in reached the exchange")

	_, err = login.CompleteLogin(context.Background(), session.SessionID, callbackFor(t, session.AuthURL, "own"))
	require.NoError(t, err, "CompleteLogin with the session's own callback after a refused one")
}

// TestLoginSessionIsUsedOnce: a completed session, and one nobody issued, are
// login_expired; the second completion adds nothing.
func TestLoginSessionIsUsedOnce(t *testing.T) {
	adds := &recordingAdd{}
	login, _ := fakeLogin(t, codeGrant, adds.add)

	session, err := login.StartLogin(context.Background(), "claude")
	require.NoError(t, err, "StartLogin")

	callback := callbackFor(t, session.AuthURL, "code")
	_, err = login.CompleteLogin(context.Background(), session.SessionID, callback)
	require.NoError(t, err, "CompleteLogin")

	_, err = login.CompleteLogin(context.Background(), session.SessionID, callback)
	require.ErrorIs(t, err, app.ErrLoginExpired, "second CompleteLogin")

	_, err = login.CompleteLogin(context.Background(), "never-issued", callback)
	require.ErrorIs(t, err, app.ErrLoginExpired, "CompleteLogin of an unknown session")

	require.Equal(t, 1, adds.count(), "accounts added")
}

// TestLoginExpiresAndIsCleanedUp: an unclaimed login expires, upstream's
// waiter is told to stop, completing it is login_expired, and its slot frees.
func TestLoginExpiresAndIsCleanedUp(t *testing.T) {
	adds := &recordingAdd{}
	login, vendor := fakeLogin(t, codeGrant, adds.add)
	login.ttl = 50 * time.Millisecond
	login.max = 1

	session, err := login.StartLogin(context.Background(), "claude")
	require.NoError(t, err, "StartLogin")

	vendor.awaitStopped(t, stateOf(t, session.AuthURL))

	_, err = login.CompleteLogin(context.Background(), session.SessionID, callbackFor(t, session.AuthURL, "late"))
	require.ErrorIs(t, err, app.ErrLoginExpired, "CompleteLogin after expiry")

	require.Zero(t, adds.count(), "an expired login added accounts")

	login.ttl = loginTTL
	_, err = login.StartLogin(context.Background(), "claude")
	require.NoError(t, err, "StartLogin after the only slot's login expired")
}

// TestPendingLoginsAreBounded: past the bound StartLogin refuses with its own
// error and starts nothing upstream; finishing a login frees its slot.
func TestPendingLoginsAreBounded(t *testing.T) {
	adds := &recordingAdd{}
	login, vendor := fakeLogin(t, codeGrant, adds.add)
	login.max = 2

	first, err := login.StartLogin(context.Background(), "claude")
	require.NoError(t, err, "StartLogin 1")

	_, err = login.StartLogin(context.Background(), "claude")
	require.NoError(t, err, "StartLogin 2")

	_, err = login.StartLogin(context.Background(), "claude")
	require.ErrorIs(t, err, app.ErrLoginsBusy, "StartLogin past the bound")

	vendor.mu.Lock()
	started := len(vendor.states)
	vendor.mu.Unlock()

	require.Equal(t, 2, started, "upstream started logins: the refused one must not start")

	_, err = login.CompleteLogin(context.Background(), first.SessionID, callbackFor(t, first.AuthURL, "code"))
	require.NoError(t, err, "CompleteLogin")

	_, err = login.StartLogin(context.Background(), "claude")
	require.NoError(t, err, "StartLogin after a login finished")
}

// TestLoginCompletesOnlyThroughComplete: a callback that reaches upstream any
// other way — here written straight into the auth directory — yields no
// account, and the session it consumed upstream cannot then be completed.
func TestLoginCompletesOnlyThroughComplete(t *testing.T) {
	adds := &recordingAdd{}
	login, vendor := fakeLogin(t, codeGrant, adds.add)

	session, err := login.StartLogin(context.Background(), "claude")
	require.NoError(t, err, "StartLogin")

	state := stateOf(t, session.AuthURL)
	_, err = sdkapi.WriteOAuthCallbackFileForPendingSession(vendor.authDir, "anthropic", state, "planted", "")
	require.NoError(t, err, "write a callback file")

	vendor.awaitStopped(t, state)

	require.Equal(t, 1, vendor.hookCalls(), "the planted callback reached the hook: the test did not exercise the hook")
	require.Zero(t, adds.count(), "a callback the gateway did not complete added accounts")

	_, err = login.CompleteLogin(context.Background(), session.SessionID, callbackFor(t, session.AuthURL, "planted"))
	require.ErrorIs(t, err, app.ErrLoginExpired, "CompleteLogin after upstream consumed the session")

	require.Zero(t, adds.count(), "accounts added, want none")
}

// TestLoginGivenUpDuringTheExchangeAddsNothing: a completion given up (the
// request went away) while the vendor exchange runs ends the login: its slot
// frees, upstream's session stops being pending, and the exchange finishing
// afterwards adds nothing.
func TestLoginGivenUpDuringTheExchangeAddsNothing(t *testing.T) {
	adds := &recordingAdd{}
	login, vendor := fakeLogin(t, codeGrant, adds.add)
	vendor.hold = make(chan struct{})
	login.max = 1

	session, err := login.StartLogin(context.Background(), "claude")
	require.NoError(t, err, "StartLogin")

	state := stateOf(t, session.AuthURL)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err = login.CompleteLogin(ctx, session.SessionID, callbackFor(t, session.AuthURL, "code"))
	require.ErrorIs(t, err, context.DeadlineExceeded, "CompleteLogin given up: want the context's error")

	require.False(t, sdkapi.IsOAuthSessionPending(state, "anthropic"), "upstream's session is still pending after the login was given up")

	close(vendor.hold)
	vendor.awaitStopped(t, state)

	require.Zero(t, adds.count(), "an exchange finishing after the give-up added accounts")
	require.Zero(t, vendor.hookCalls(), "an exchange finishing after the give-up reached the hook")

	_, err = login.StartLogin(context.Background(), "claude")
	require.NoError(t, err, "StartLogin after the only slot's login was given up")
}

// TestLoginStartFailureFreesTheSlot: a start upstream refuses frees its slot
// and says why, without a malformed wrapped error.
func TestLoginStartFailureFreesTheSlot(t *testing.T) {
	login, vendor := fakeLogin(t, codeGrant, (&recordingAdd{}).add)
	login.max = 1
	vendor.failStart = true

	_, err := login.StartLogin(context.Background(), "claude")
	require.Error(t, err, "StartLogin refused upstream: want a readable error")
	require.NotContains(t, err.Error(), "%!", "StartLogin refused upstream: want a readable error")

	vendor.failStart = false

	_, err = login.StartLogin(context.Background(), "claude")
	require.NoError(t, err, "StartLogin after a failed start")
}

// TestLoginFailureCarriesNoCallbackSecret: a vendor refusal is login_failed,
// adds nothing, and its error carries neither the pasted URL nor its code or
// state, even when upstream's report quotes them.
func TestLoginFailureCarriesNoCallbackSecret(t *testing.T) {
	adds := &recordingAdd{}
	login, vendor := fakeLogin(t, codeGrant, adds.add)
	vendor.refuse = func(code, state string) string {
		return fmt.Sprintf("Failed to exchange authorization code for tokens: invalid_grant for %q (state %s)", code, state)
	}

	session, err := login.StartLogin(context.Background(), "claude")
	require.NoError(t, err, "StartLogin")

	const code = "SECRET-AUTH-CODE-4242"

	state := stateOf(t, session.AuthURL)
	callback := callbackFor(t, session.AuthURL, code)

	_, err = login.CompleteLogin(context.Background(), session.SessionID, callback)
	require.ErrorIs(t, err, app.ErrLoginFailed, "CompleteLogin with a refused exchange")

	for _, secret := range []string{code, state, callback} {
		require.NotContains(t, err.Error(), secret, "the error carries a secret")
	}

	require.Zero(t, adds.count(), "a failed login added accounts")
}
