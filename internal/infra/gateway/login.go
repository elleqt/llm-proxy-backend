package gateway

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	sdkapi "github.com/router-for-me/CLIProxyAPI/v7/sdk/api"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

const (
	// loginTTL is how long a started login can be completed. Upstream's
	// waiter gives up five minutes after the start request
	// (auth_files_provider_oauth.go RequestAnthropicToken waitForFile(…,
	// 5*time.Minute), RequestCodexToken deadline := time.Now().Add(5 *
	// time.Minute)); its session registry keeps the state for 30 minutes, but
	// nothing reads the callback after the waiter stops. The expiry is counted
	// from before the start request, so it falls before upstream's.
	loginTTL = 5 * time.Minute
	// maxPendingLogins bounds the logins in progress, each an upstream waiter
	// goroutine polling the auth directory.
	maxPendingLogins = 8
	// loginFinishWait bounds CompleteLogin: upstream polls for the callback
	// every 500 ms, then exchanges the code with the vendor.
	loginFinishWait = time.Minute
	// loginPoll is how often CompleteLogin reads upstream's session status.
	loginPoll = 100 * time.Millisecond
	// loginSessionHeader carries the gateway's session id on the synthetic
	// start request; upstream hands the request's headers back to the
	// post-auth hook (PopulateAuthContext → coreauth.GetRequestInfo).
	loginSessionHeader = "X-Llm-Proxy-Login-Session"
)

// Returned by the post-auth hook, which makes upstream's saveTokenRecord
// return before its own store.Save ("post-auth hook failed: …"): the gateway
// adds the account itself. Upstream logs the error and marks its session
// failed ("Failed to save authentication tokens").
var (
	errHandedToGateway = errors.New("gateway: the vendor login is added by the gateway, not saved by upstream")
	errNotCompleted    = errors.New("gateway: a vendor login finished for no session in progress; dropped")
)

// loginFlow is one provider's upstream sign-in: the management handler method
// that starts it and the provider name upstream's session registry and
// callback files use.
type loginFlow struct {
	upstream string
	start    func(*gin.Context)
}

// Login runs vendor sign-ins for an administrator who is not at the gateway's
// console, on upstream's embedder path: sdk/api's management handler
// (NewHandlerWithoutConfigFilePath) is called directly, never routed.
//
//   - StartLogin calls RequestAnthropicToken or RequestCodexToken with a
//     synthetic gin.Context and reads {url, state} from the JSON it writes.
//     Without the is_webui query neither binds a callback listener (only
//     isWebUIRequest starts startCallbackForwarder) nor prints anything
//     secret; both leave a goroutine polling the auth directory for
//     ".oauth-<provider>-<state>.oauth" every 500 ms while the session is
//     pending.
//   - CompleteLogin checks that the pasted URL carries a code and the
//     session's state, then hands the code to that goroutine through
//     sdkapi.WriteOAuthCallbackFileForPendingSession (written 0600 and
//     renamed into place; upstream reads and deletes it). Upstream exchanges
//     the code and passes the record to the post-auth hook before it would
//     save it. The hook gives the record to the waiting CompleteLogin, which
//     adds it through AddAccount, and returns an error so upstream saves
//     nothing itself. The record carries its tokens only in Storage;
//     AddAccount saves it and holds the account the store loads back.
//   - A login ends — expired, given up or finished — with
//     sdkapi.CompleteOAuthSession(state): upstream's goroutine stops at its
//     next poll, and its pre-save guard (guardOAuthSessionPendingForSave)
//     drops an exchange still in flight.
//
// A session completes through CompleteLogin and nothing else: no port is
// bound, CompleteLogin is the only writer of callback files, and only
// CompleteLogin adds the record the hook hands over. A callback reaching
// upstream another way (a file planted in the auth directory, which needs the
// session's state) consumes upstream's session, and CompleteLogin then finds
// it no longer pending: login_expired, nothing added.
type Login struct {
	add     func(context.Context, *coreauth.Auth) (*coreauth.Auth, error)
	authDir string
	flows   map[string]loginFlow

	ttl, finishWait, poll time.Duration
	max                   int

	mu sync.Mutex
	// sessions holds every login in progress, claimed or not; its size is
	// bounded by max.
	sessions map[string]*pendingLogin
}

var _ app.VendorLogins = (*Login)(nil)

// NewLogin serves Claude and Codex sign-ins for g under their policy names.
// Upstream's handler gets g's configuration as it is now, with the auth
// directory made absolute: its proxy settings reach the code exchange, and a
// configuration pushed later does not.
func NewLogin(g *Gateway) *Login {
	var cfg cliproxyconfig.Config
	if current := g.CurrentConfig(); current != nil {
		cfg = *current
	}
	cfg.AuthDir = g.authDir
	h := sdkapi.NewHandlerWithoutConfigFilePath(&cfg, g.coreAuth)
	l := newLogin(g.AddAccount, g.authDir, map[string]loginFlow{
		policyProvider("claude"): {upstream: "anthropic", start: h.RequestAnthropicToken},
		policyProvider("codex"):  {upstream: "codex", start: h.RequestCodexToken},
	})
	h.SetPostAuthHook(l.deliver)
	return l
}

func newLogin(add func(context.Context, *coreauth.Auth) (*coreauth.Auth, error), authDir string, flows map[string]loginFlow) *Login {
	return &Login{
		add:        add,
		authDir:    authDir,
		flows:      flows,
		ttl:        loginTTL,
		finishWait: loginFinishWait,
		poll:       loginPoll,
		max:        maxPendingLogins,
		sessions:   make(map[string]*pendingLogin),
	}
}

// pendingLogin is one login in progress.
type pendingLogin struct {
	state     string
	upstream  string
	expiresAt time.Time
	timer     *time.Timer
	// claimed is set, under Login.mu, by the one CompleteLogin that owns the
	// session, or by its expiry.
	claimed bool
	// result receives the record upstream's exchange produced.
	result chan *coreauth.Auth
}

// StartLogin starts a sign-in for provider, a policy name ("claude",
// "chatgpt"), and returns its session with the authorisation URL.
func (l *Login) StartLogin(ctx context.Context, provider string) (app.VendorLogin, error) {
	flow, ok := l.flows[provider]
	if !ok {
		return app.VendorLogin{}, fmt.Errorf("%w: %q", app.ErrUnsupportedProvider, provider)
	}
	if err := ctx.Err(); err != nil {
		return app.VendorLogin{}, err
	}
	id, err := loginSessionID()
	if err != nil {
		return app.VendorLogin{}, err
	}
	p := &pendingLogin{upstream: flow.upstream, result: make(chan *coreauth.Auth, 1)}

	// Reserve the slot and publish the session before upstream starts, so a
	// record can find it; it is unclaimed until CompleteLogin, so nothing can
	// complete it meanwhile.
	l.mu.Lock()
	if len(l.sessions) >= l.max {
		l.mu.Unlock()
		return app.VendorLogin{}, app.ErrLoginsBusy
	}
	startedAt := time.Now()
	p.expiresAt = startedAt.Add(l.ttl)
	l.sessions[id] = p
	l.mu.Unlock()

	authURL, state, err := requestLogin(flow.start, id)
	if err != nil {
		l.finish(id, p)
		return app.VendorLogin{}, fmt.Errorf("gateway: %s login did not start: %w", provider, err)
	}
	l.mu.Lock()
	p.state = state
	p.timer = time.AfterFunc(time.Until(p.expiresAt), func() { l.expire(id, p) })
	l.mu.Unlock()
	return app.VendorLogin{SessionID: id, AuthURL: authURL, ExpiresAt: p.expiresAt}, nil
}

// requestLogin calls an upstream start handler as the management API would
// be called, without is_webui, and returns the URL and state it answers with.
func requestLogin(start func(*gin.Context), sessionID string) (authURL, state string, err error) {
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set(loginSessionHeader, sessionID)
	c.Request = req
	start(c)

	var body struct {
		URL   string `json:"url"`
		State string `json:"state"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		return "", "", fmt.Errorf("upstream answered %d with an unreadable body", rec.Code)
	}
	if rec.Code != http.StatusOK {
		// A state upstream registered before failing is abandoned.
		if body.State != "" {
			sdkapi.CompleteOAuthSession(body.State)
		}
		return "", "", fmt.Errorf("upstream answered %d: %s", rec.Code, body.Error)
	}
	if body.URL == "" || sdkapi.ValidateOAuthState(body.State) != nil {
		sdkapi.CompleteOAuthSession(body.State)
		return "", "", errors.New("upstream answered without an authorisation URL and state")
	}
	return body.URL, body.State, nil
}

// deliver is upstream's post-auth hook. It runs on upstream's exchange
// goroutine with the start request's headers in ctx, and never lets upstream
// save the record.
func (l *Login) deliver(ctx context.Context, auth *coreauth.Auth) error {
	var id string
	if info := coreauth.GetRequestInfo(ctx); info != nil {
		id = info.Headers.Get(loginSessionHeader)
	}
	l.mu.Lock()
	p, ok := l.sessions[id]
	l.mu.Unlock()
	if !ok {
		return errNotCompleted
	}
	select {
	case p.result <- auth:
	default:
	}
	return errHandedToGateway
}

// expire ends an unclaimed login once its time is up. Marking it claimed and
// withdrawing it happen under one lock, so no CompleteLogin can claim it
// meanwhile.
func (l *Login) expire(id string, p *pendingLogin) {
	l.mu.Lock()
	unclaimed := l.sessions[id] == p && !p.claimed
	if unclaimed {
		p.claimed = true
		delete(l.sessions, id)
	}
	l.mu.Unlock()
	if unclaimed {
		sdkapi.CompleteOAuthSession(p.state)
	}
}

// finish ends a login: its slot frees, and upstream's session is completed,
// which stops its waiter and makes its pre-save guard drop an exchange still
// in flight. Safe to call more than once.
func (l *Login) finish(id string, p *pendingLogin) {
	l.mu.Lock()
	if l.sessions[id] == p {
		delete(l.sessions, id)
	}
	if p.timer != nil {
		p.timer.Stop()
	}
	state := p.state
	l.mu.Unlock()
	if state != "" {
		sdkapi.CompleteOAuthSession(state)
	}
}

// CompleteLogin finishes session sessionID with the URL the vendor sign-in
// ended on and adds the account through the gateway.
//
// A URL that carries no code, or not this session's state, is ErrLoginFailed
// and leaves the session as it was: upstream is not told, and the
// administrator can paste again. Otherwise the session is claimed, once: an
// unknown, expired or already claimed session is ErrLoginExpired. A vendor
// refusal is ErrLoginFailed.
func (l *Login) CompleteLogin(ctx context.Context, sessionID, callbackURL string) (app.VendorAccount, error) {
	cb, err := parseCallback(callbackURL)
	if err != nil {
		return app.VendorAccount{}, err
	}

	l.mu.Lock()
	p, ok := l.sessions[sessionID]
	if !ok || p.claimed || p.state == "" || !time.Now().Before(p.expiresAt) {
		l.mu.Unlock()
		return app.VendorAccount{}, app.ErrLoginExpired
	}
	if cb.state != p.state {
		l.mu.Unlock()
		return app.VendorAccount{}, fmt.Errorf("%w: the callback belongs to another sign-in", app.ErrLoginFailed)
	}
	p.claimed = true
	p.timer.Stop()
	l.mu.Unlock()
	defer l.finish(sessionID, p)

	if cb.vendorError != "" {
		return app.VendorAccount{}, fmt.Errorf("%w: the vendor refused the sign-in", app.ErrLoginFailed)
	}
	if _, err := sdkapi.WriteOAuthCallbackFileForPendingSession(l.authDir, p.upstream, p.state, cb.code, ""); err != nil {
		if !sdkapi.IsOAuthSessionPending(p.state, p.upstream) {
			return app.VendorAccount{}, app.ErrLoginExpired
		}
		return app.VendorAccount{}, fmt.Errorf("gateway: hand the callback to upstream: %w", err)
	}

	auth, err := l.await(ctx, p, cb, callbackURL)
	if err != nil {
		return app.VendorAccount{}, err
	}
	stored, err := l.add(ctx, auth)
	if err != nil {
		return app.VendorAccount{}, err
	}
	return vendorAccount(stored), nil
}

// await waits, bounded, for upstream's exchange: the record through the
// hook, or a failure in upstream's session status.
func (l *Login) await(ctx context.Context, p *pendingLogin, cb callback, callbackURL string) (*coreauth.Auth, error) {
	tick := time.NewTicker(l.poll)
	defer tick.Stop()
	deadline := time.NewTimer(l.finishWait)
	defer deadline.Stop()
	for {
		select {
		case auth := <-p.result:
			return auth, nil
		case <-tick.C:
			_, status, ok := sdkapi.GetOAuthSession(p.state)
			if ok && status == "" {
				continue
			}
			// The hook hands the record over before upstream marks the
			// session failed.
			select {
			case auth := <-p.result:
				return auth, nil
			default:
			}
			if !ok {
				return nil, fmt.Errorf("%w: upstream ended the sign-in", app.ErrLoginFailed)
			}
			return nil, fmt.Errorf("%w: %s", app.ErrLoginFailed, redactCallback(status, callbackURL, cb))
		case <-deadline.C:
			return nil, fmt.Errorf("%w: the vendor sign-in did not finish within %s", app.ErrLoginFailed, l.finishWait)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// callback is what a pasted callback URL carries.
type callback struct {
	code, state, vendorError string
}

// parseCallback reads the code, state and error from the URL the vendor
// sign-in ended on, as upstream's own parser does (internal/misc/oauth.go
// ParseOAuthCallback): scheme and host are optional, the fragment is read too,
// and Claude's "code#state" form is split. Nothing pasted is echoed in an
// error.
func parseCallback(raw string) (callback, error) {
	raw = strings.TrimSpace(raw)
	switch {
	case raw == "":
		return callback{}, fmt.Errorf("%w: no callback URL", app.ErrLoginFailed)
	case strings.Contains(raw, "://"):
	case strings.HasPrefix(raw, "?"):
		raw = "http://localhost" + raw
	case strings.ContainsAny(raw, "/?#:"):
		raw = "http://" + raw
	default:
		raw = "http://localhost/?" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return callback{}, fmt.Errorf("%w: the callback URL does not parse", app.ErrLoginFailed)
	}
	values := u.Query()
	if frag, err := url.ParseQuery(u.Fragment); err == nil {
		for k, vs := range frag {
			if values.Get(k) == "" {
				values[k] = vs
			}
		}
	}
	cb := callback{
		code:        strings.TrimSpace(values.Get("code")),
		state:       strings.TrimSpace(values.Get("state")),
		vendorError: strings.TrimSpace(values.Get("error")),
	}
	if cb.state == "" {
		if code, state, ok := strings.Cut(cb.code, "#"); ok {
			cb.code, cb.state = code, state
		}
	}
	if cb.state == "" || (cb.code == "" && cb.vendorError == "") {
		return callback{}, fmt.Errorf("%w: the callback URL carries no code and state", app.ErrLoginFailed)
	}
	return cb, nil
}

// redactCallback removes the pasted URL, its code and its state from msg, raw,
// quoted and query-escaped.
func redactCallback(msg, callbackURL string, cb callback) string {
	secrets := []string{callbackURL, cb.code, cb.state}
	slices.SortFunc(secrets, func(a, b string) int { return cmp.Compare(len(b), len(a)) })
	for _, s := range secrets {
		if s == "" {
			continue
		}
		msg = strings.ReplaceAll(msg, strconv.Quote(s), "[redacted]")
		msg = strings.ReplaceAll(msg, s, "[redacted]")
		msg = strings.ReplaceAll(msg, url.QueryEscape(s), "[redacted]")
	}
	return msg
}

// loginSessionID is 256 random bits: the session id and a callback URL are
// all CompleteLogin needs.
func loginSessionID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("gateway: login session id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
