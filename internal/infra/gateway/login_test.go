package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	sdkapi "github.com/router-for-me/CLIProxyAPI/v7/sdk/api"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

// fakeOAuth is upstream's management start handler with the vendor's code
// exchange replaced, keeping everything the gateway relies on as upstream
// v7.3.12 does it (auth_files_provider_oauth.go RequestAnthropicToken): the
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

func (f *fakeOAuth) start(c *gin.Context) {
	if f.failStart {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate authorization url"})
		return
	}
	state, err := loginSessionID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "state"})
		return
	}
	sdkapi.RegisterOAuthSession(state, "anthropic")
	f.mu.Lock()
	f.states = append(f.states, state)
	f.mu.Unlock()
	ctx := sdkapi.PopulateAuthContext(context.Background(), c)
	go f.wait(ctx, state)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "url": "https://vendor.example/oauth/authorize?state=" + state, "state": state})
}

func (f *fakeOAuth) wait(ctx context.Context, state string) {
	defer func() { f.stopped <- state }()
	path := filepath.Join(f.authDir, ".oauth-anthropic-"+state+".oauth")
	var m map[string]string
	for {
		if !sdkapi.IsOAuthSessionPending(state, "anthropic") {
			return
		}
		if data, err := os.ReadFile(path); err == nil {
			_ = json.Unmarshal(data, &m)
			_ = os.Remove(path)
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if m["state"] != state {
		sdkapi.SetOAuthSessionError(state, "State code error")
		return
	}
	if f.hold != nil {
		<-f.hold
	}
	if f.refuse != nil {
		sdkapi.SetOAuthSessionError(state, f.refuse(m["code"], state))
		return
	}
	record := f.grant(m["code"])
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
			t.Fatalf("upstream's waiter for the login is still running: the login was not ended")
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
func endLogins(l *Login) {
	l.mu.Lock()
	pending := make(map[string]*pendingLogin, len(l.sessions))
	for id, p := range l.sessions {
		pending[id] = p
	}
	l.mu.Unlock()
	for id, p := range pending {
		l.finish(id, p)
	}
}

func stateOf(t *testing.T, authURL string) string {
	t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		t.Fatalf("auth URL %q: %v", authURL, err)
	}
	state := u.Query().Get("state")
	if state == "" {
		t.Fatalf("auth URL %q carries no state", authURL)
	}
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
	p := productionParams(t)
	r := startBooted(t, p)
	grant := claudeGrant(t)
	login, _ := fakeLogin(t, func(code string) *coreauth.Auth {
		if code != "code-1" {
			t.Errorf("the exchange got code %q, want the pasted one", code)
		}
		return grant
	}, r.gateway.AddAccount)

	before := time.Now()
	session, err := login.StartLogin(context.Background(), "claude")
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	if session.SessionID == "" || session.SessionID == stateOf(t, session.AuthURL) {
		t.Fatalf("session id %q: want our own id, not upstream's state", session.SessionID)
	}
	if session.ExpiresAt.Before(before.Add(loginTTL)) || session.ExpiresAt.After(time.Now().Add(loginTTL)) {
		t.Fatalf("ExpiresAt = %v, want %s after the start", session.ExpiresAt, loginTTL)
	}

	account, err := login.CompleteLogin(context.Background(), session.SessionID, callbackFor(t, session.AuthURL, "code-1"))
	if err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	if account.ID != grant.ID || account.Provider != "claude" {
		t.Fatalf("CompleteLogin returned %+v, want account %s of provider claude", account, grant.ID)
	}
	if _, ok := p.CoreAuth.GetByID(grant.ID); !ok {
		t.Fatal("the completed login's account is not held by the manager")
	}
	if registeredModels(grant.ID) == 0 {
		t.Fatal("the completed login's account has no registered models: it is not routable")
	}
	if _, err := os.Stat(filepath.Join(p.Config.AuthDir, grant.FileName)); err != nil {
		t.Fatalf("the completed login's credential was not persisted: %v", err)
	}
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
	for k, v := range s.metadata {
		data[k] = v
	}
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
	p := productionParams(t)
	r := startBooted(t, p)
	storage := &claudeTokenFile{accessToken: "sk-ant-oat-wizard", refreshToken: "sk-ant-ort-wizard", email: "wizard@example.com"}
	grant := storageGrant(t, storage)
	login, _ := fakeLogin(t, func(string) *coreauth.Auth { return grant }, r.gateway.AddAccount)

	session, err := login.StartLogin(context.Background(), "claude")
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	account, err := login.CompleteLogin(context.Background(), session.SessionID, callbackFor(t, session.AuthURL, "code-1"))
	if err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	if account.ID != grant.FileName || account.Email != storage.email {
		t.Fatalf("CompleteLogin returned %+v, want account %s of %s", account, grant.FileName, storage.email)
	}
	held, ok := p.CoreAuth.GetByID(account.ID)
	if !ok {
		t.Fatal("the completed login's account is not held by the manager")
	}
	if got := held.Metadata["access_token"]; got != storage.accessToken {
		t.Errorf("held account's Metadata[access_token] = %v, want the login's token: requests would carry no credential", got)
	}
	if got := held.Metadata["refresh_token"]; got != storage.refreshToken {
		t.Errorf("held account's Metadata[refresh_token] = %v, want the login's refresh token", got)
	}
	if got, want := held.Attributes[coreauth.AttributePath], filepath.Join(p.Config.AuthDir, grant.FileName); got != want {
		t.Errorf("held account's path attribute = %q, want its credential %q", got, want)
	}
	if held.Status != coreauth.StatusActive || held.Disabled {
		t.Errorf("held account is status %q, disabled=%t; want active", held.Status, held.Disabled)
	}
	if registeredModels(account.ID) == 0 {
		t.Error("the completed login's account has no registered models: it is not routable")
	}
}

// TestLoginWithAnUnsavedCredentialAddsNothing: when the token store cannot
// write the login's credential, the login fails and nothing is held,
// routable or on disk, so no account serves traffic that a restart drops.
func TestLoginWithAnUnsavedCredentialAddsNothing(t *testing.T) {
	p := productionParams(t)
	r := startBooted(t, p)
	errWrite := errors.New("token file write refused by test")
	storage := &claudeTokenFile{accessToken: "sk-ant-oat-unsaved", refreshToken: "sk-ant-ort-unsaved", email: "unsaved@example.com", fail: errWrite}
	grant := storageGrant(t, storage)
	login, _ := fakeLogin(t, func(string) *coreauth.Auth { return grant }, r.gateway.AddAccount)

	session, err := login.StartLogin(context.Background(), "claude")
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	if _, err := login.CompleteLogin(context.Background(), session.SessionID, callbackFor(t, session.AuthURL, "code-1")); !errors.Is(err, errWrite) {
		t.Fatalf("CompleteLogin with a failing credential write = %v, want the write's error", err)
	}
	if got, ok := p.CoreAuth.GetByID(grant.ID); ok {
		t.Fatalf("the unsaved login's account is held (disabled=%t)", got.Disabled)
	}
	if n := registeredModels(grant.ID); n != 0 {
		t.Fatalf("the unsaved login's account has %d registered models", n)
	}
	if _, err := os.Stat(filepath.Join(p.Config.AuthDir, grant.FileName)); !os.IsNotExist(err) {
		t.Fatalf("the unsaved login's credential is in the auth directory (stat: %v)", err)
	}
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
		link, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name()))
		if err == nil && strings.HasPrefix(link, "socket:[") {
			own[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
		}
	}
	listening := make(map[string]bool)
	for _, table := range []string{"/proc/self/net/tcp", "/proc/self/net/tcp6"} {
		f, err := os.Open(table)
		if err != nil {
			continue
		}
		rows := bufio.NewScanner(f)
		for rows.Scan() {
			fields := strings.Fields(rows.Text())
			if len(fields) > 9 && fields[3] == "0A" && own[fields[9]] {
				listening[fields[9]] = true
			}
		}
		_ = f.Close()
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
	if len(before) == 0 {
		t.Fatal("found no listening socket of this process, not even the gateway's: the probe proves nothing")
	}
	for _, provider := range []string{"claude", "chatgpt"} {
		session, err := login.StartLogin(context.Background(), provider)
		if err != nil {
			t.Fatalf("StartLogin(%s): %v", provider, err)
		}
		u, err := url.Parse(session.AuthURL)
		if err != nil || u.Scheme != "https" || u.Query().Get("state") == "" || u.Query().Get("code_challenge") == "" {
			t.Fatalf("StartLogin(%s) AuthURL = %q, want the vendor's https authorisation URL with state and PKCE challenge", provider, session.AuthURL)
		}
	}
	for inode := range listeningSockets(t) {
		if !before[inode] {
			t.Fatalf("a listening socket (inode %s) appeared while logins were pending", inode)
		}
	}
	if _, err := login.StartLogin(context.Background(), "codex"); !errors.Is(err, app.ErrUnsupportedProvider) {
		t.Fatalf("StartLogin(codex) = %v, want ErrUnsupportedProvider: the wizard speaks policy names", err)
	}
}

// TestLoginHandsTheCallbackToUpstream runs upstream's real Codex flow with the
// vendor unreachable (a proxy on a closed port): upstream picks up the
// callback file CompleteLogin writes, fails the exchange, and the login
// reports login_failed. Nothing is added.
func TestLoginHandsTheCallbackToUpstream(t *testing.T) {
	p := productionParams(t)
	p.Config.ProxyURL = "http://" + net127(freePort(t))
	r := startWith(t, p)
	login := NewLogin(r.gateway)
	t.Cleanup(func() { endLogins(login) })

	session, err := login.StartLogin(context.Background(), "chatgpt")
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	state := stateOf(t, session.AuthURL)
	_, err = login.CompleteLogin(context.Background(), session.SessionID,
		"http://localhost:1455/auth/callback?code=vendor-code&state="+state)
	if !errors.Is(err, app.ErrLoginFailed) {
		t.Fatalf("CompleteLogin with the exchange failing = %v, want ErrLoginFailed", err)
	}
	if strings.Contains(err.Error(), "vendor-code") || strings.Contains(err.Error(), state) {
		t.Fatalf("the error %q carries the code or state", err)
	}
	if _, err := os.Stat(filepath.Join(p.Config.AuthDir, ".oauth-codex-"+state+".oauth")); !os.IsNotExist(err) {
		t.Fatalf("the callback file is still in the auth directory (stat: %v): upstream did not read it", err)
	}
	if n := len(p.CoreAuth.List()); n != 0 {
		t.Fatalf("a failed login left %d accounts", n)
	}
}

func net127(port int) string { return "127.0.0.1:" + strconv.Itoa(port) }

// TestLoginRefusesACallbackForAnotherSignIn: a pasted URL whose state is not
// the session's is login_failed, reaches no exchange and adds nothing, and
// the session stays completable with its own callback.
func TestLoginRefusesACallbackForAnotherSignIn(t *testing.T) {
	adds := &recordingAdd{}
	login, vendor := fakeLogin(t, codeGrant, adds.add)

	session, err := login.StartLogin(context.Background(), "claude")
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	other := "http://localhost:54545/callback?code=stolen&state=someone-elses-state"
	if _, err := login.CompleteLogin(context.Background(), session.SessionID, other); !errors.Is(err, app.ErrLoginFailed) {
		t.Fatalf("CompleteLogin with another sign-in's callback = %v, want ErrLoginFailed", err)
	}
	if n := adds.count(); n != 0 || vendor.hookCalls() != 0 {
		t.Fatalf("a callback for another sign-in reached the exchange (%d hook calls) or added %d accounts", vendor.hookCalls(), n)
	}
	if _, err := login.CompleteLogin(context.Background(), session.SessionID, callbackFor(t, session.AuthURL, "own")); err != nil {
		t.Fatalf("CompleteLogin with the session's own callback after a refused one: %v", err)
	}
}

// TestLoginSessionIsUsedOnce: a completed session, and one nobody issued, are
// login_expired; the second completion adds nothing.
func TestLoginSessionIsUsedOnce(t *testing.T) {
	adds := &recordingAdd{}
	login, _ := fakeLogin(t, codeGrant, adds.add)

	session, err := login.StartLogin(context.Background(), "claude")
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	callback := callbackFor(t, session.AuthURL, "code")
	if _, err := login.CompleteLogin(context.Background(), session.SessionID, callback); err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	if _, err := login.CompleteLogin(context.Background(), session.SessionID, callback); !errors.Is(err, app.ErrLoginExpired) {
		t.Fatalf("second CompleteLogin = %v, want ErrLoginExpired", err)
	}
	if _, err := login.CompleteLogin(context.Background(), "never-issued", callback); !errors.Is(err, app.ErrLoginExpired) {
		t.Fatalf("CompleteLogin of an unknown session = %v, want ErrLoginExpired", err)
	}
	if n := adds.count(); n != 1 {
		t.Fatalf("%d accounts added, want 1", n)
	}
}

// TestLoginExpiresAndIsCleanedUp: an unclaimed login expires, upstream's
// waiter is told to stop, completing it is login_expired, and its slot frees.
func TestLoginExpiresAndIsCleanedUp(t *testing.T) {
	adds := &recordingAdd{}
	login, vendor := fakeLogin(t, codeGrant, adds.add)
	login.ttl = 50 * time.Millisecond
	login.max = 1

	session, err := login.StartLogin(context.Background(), "claude")
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	vendor.awaitStopped(t, stateOf(t, session.AuthURL))
	if _, err := login.CompleteLogin(context.Background(), session.SessionID, callbackFor(t, session.AuthURL, "late")); !errors.Is(err, app.ErrLoginExpired) {
		t.Fatalf("CompleteLogin after expiry = %v, want ErrLoginExpired", err)
	}
	if n := adds.count(); n != 0 {
		t.Fatalf("an expired login added %d accounts", n)
	}
	login.ttl = loginTTL
	if _, err := login.StartLogin(context.Background(), "claude"); err != nil {
		t.Fatalf("StartLogin after the only slot's login expired: %v", err)
	}
}

// TestPendingLoginsAreBounded: past the bound StartLogin refuses with its own
// error and starts nothing upstream; finishing a login frees its slot.
func TestPendingLoginsAreBounded(t *testing.T) {
	adds := &recordingAdd{}
	login, vendor := fakeLogin(t, codeGrant, adds.add)
	login.max = 2

	first, err := login.StartLogin(context.Background(), "claude")
	if err != nil {
		t.Fatalf("StartLogin 1: %v", err)
	}
	if _, err := login.StartLogin(context.Background(), "claude"); err != nil {
		t.Fatalf("StartLogin 2: %v", err)
	}
	if _, err := login.StartLogin(context.Background(), "claude"); !errors.Is(err, app.ErrLoginsBusy) {
		t.Fatalf("StartLogin past the bound = %v, want ErrLoginsBusy", err)
	}
	vendor.mu.Lock()
	started := len(vendor.states)
	vendor.mu.Unlock()
	if started != 2 {
		t.Fatalf("upstream started %d logins, want 2: the refused one must not start", started)
	}

	if _, err := login.CompleteLogin(context.Background(), first.SessionID, callbackFor(t, first.AuthURL, "code")); err != nil {
		t.Fatalf("CompleteLogin: %v", err)
	}
	if _, err := login.StartLogin(context.Background(), "claude"); err != nil {
		t.Fatalf("StartLogin after a login finished: %v", err)
	}
}

// TestLoginCompletesOnlyThroughComplete: a callback that reaches upstream any
// other way — here written straight into the auth directory — yields no
// account, and the session it consumed upstream cannot then be completed.
func TestLoginCompletesOnlyThroughComplete(t *testing.T) {
	adds := &recordingAdd{}
	login, vendor := fakeLogin(t, codeGrant, adds.add)

	session, err := login.StartLogin(context.Background(), "claude")
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	state := stateOf(t, session.AuthURL)
	if _, err := sdkapi.WriteOAuthCallbackFileForPendingSession(vendor.authDir, "anthropic", state, "planted", ""); err != nil {
		t.Fatalf("write a callback file: %v", err)
	}
	vendor.awaitStopped(t, state)
	if vendor.hookCalls() != 1 {
		t.Fatalf("the planted callback reached the hook %d times, want 1: the test did not exercise the hook", vendor.hookCalls())
	}
	if n := adds.count(); n != 0 {
		t.Fatalf("a callback the gateway did not complete added %d accounts", n)
	}
	if _, err := login.CompleteLogin(context.Background(), session.SessionID, callbackFor(t, session.AuthURL, "planted")); !errors.Is(err, app.ErrLoginExpired) {
		t.Fatalf("CompleteLogin after upstream consumed the session = %v, want ErrLoginExpired", err)
	}
	if n := adds.count(); n != 0 {
		t.Fatalf("%d accounts added, want none", n)
	}
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
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	state := stateOf(t, session.AuthURL)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := login.CompleteLogin(ctx, session.SessionID, callbackFor(t, session.AuthURL, "code")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CompleteLogin given up = %v, want the context's error", err)
	}
	if sdkapi.IsOAuthSessionPending(state, "anthropic") {
		t.Fatal("upstream's session is still pending after the login was given up")
	}
	close(vendor.hold)
	vendor.awaitStopped(t, state)
	if n := adds.count(); n != 0 || vendor.hookCalls() != 0 {
		t.Fatalf("an exchange finishing after the give-up reached the hook %d times and added %d accounts", vendor.hookCalls(), n)
	}
	if _, err := login.StartLogin(context.Background(), "claude"); err != nil {
		t.Fatalf("StartLogin after the only slot's login was given up: %v", err)
	}
}

// TestLoginStartFailureFreesTheSlot: a start upstream refuses frees its slot
// and says why, without a malformed wrapped error.
func TestLoginStartFailureFreesTheSlot(t *testing.T) {
	login, vendor := fakeLogin(t, codeGrant, (&recordingAdd{}).add)
	login.max = 1
	vendor.failStart = true

	_, err := login.StartLogin(context.Background(), "claude")
	if err == nil || strings.Contains(err.Error(), "%!") {
		t.Fatalf("StartLogin refused upstream = %v, want a readable error", err)
	}
	vendor.failStart = false
	if _, err := login.StartLogin(context.Background(), "claude"); err != nil {
		t.Fatalf("StartLogin after a failed start: %v", err)
	}
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
	if err != nil {
		t.Fatalf("StartLogin: %v", err)
	}
	const code = "SECRET-AUTH-CODE-4242"
	state := stateOf(t, session.AuthURL)
	callback := callbackFor(t, session.AuthURL, code)

	_, err = login.CompleteLogin(context.Background(), session.SessionID, callback)
	if !errors.Is(err, app.ErrLoginFailed) {
		t.Fatalf("CompleteLogin with a refused exchange = %v, want ErrLoginFailed", err)
	}
	for _, secret := range []string{code, state, callback} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("the error %q carries %q", err, secret)
		}
	}
	if n := adds.count(); n != 0 {
		t.Fatalf("a failed login added %d accounts", n)
	}
}
