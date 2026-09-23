package gateway

import (
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"

	cliproxyconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/stretchr/testify/mock"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway/faketest"
)

// observed is one refusal a recordingObserver was told of.
type observed struct {
	authFailed   string
	owner, model string
	reason       DenyReason
	denied       bool
}

// recordingObserver keeps every refusal in the order the gate reported it.
type recordingObserver struct {
	mu  sync.Mutex
	all []observed
}

func (o *recordingObserver) AuthFailed(reason string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.all = append(o.all, observed{authFailed: reason})
}

func (o *recordingObserver) Denied(owner, model string, reason DenyReason) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.all = append(o.all, observed{owner: owner, model: model, reason: reason, denied: true})
}

func (o *recordingObserver) seen() []observed {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]observed(nil), o.all...)
}

// TestGateReportsEveryRefusal: through the real server, every refusal the gate
// answers is reported once — a missing and a bad credential by reason, a policy
// denial and a model no provider serves under the owner's label, a route off the
// allow-list with no owner — and the owner is the principal's label, never its
// ids. Reporting a denial costs no read: each 403 reads the token and its owner
// once, as the real resolver does for any request.
func TestGateReportsEveryRefusal(t *testing.T) {
	observer := &recordingObserver{}
	owner := identity.User{
		ID: wirePrincipal.UserID, Kind: identity.KindHuman, Status: identity.StatusActive,
		Email: "alice@example.com", Policy: mustPolicy("acme:*"),
	}
	token := credentials.Token{ID: wirePrincipal.TokenID, UserID: owner.ID, Hash: credentials.HashSecret(wireSecret)}
	users, tokens := mocks.NewUserRepo(t), mocks.NewTokenRepo(t)
	// Two denied requests carry the token: two reads of each, and not one more.
	tokens.EXPECT().ByHash(mock.Anything, credentials.HashSecret(wireSecret)).Return(token, nil).Times(2)
	users.EXPECT().ByID(mock.Anything, owner.ID).Return(owner, nil).Times(2)
	tokens.EXPECT().ByHash(mock.Anything, credentials.HashSecret("sk-not-a-token")).Return(credentials.Token{}, app.ErrNotFound).Once()
	w := startOnTheWireWith(t, &faketest.Vendor{Payload: []byte(`{}`)}, Params{
		Config:   &cliproxyconfig.Config{},
		Resolver: app.NewTokenResolver(users, tokens),
		Observer: observer,
	})

	for _, c := range []struct {
		method, path, key, body string
		want                    int
	}{
		{http.MethodGet, "/v1/models", "", "", http.StatusUnauthorized},
		{http.MethodGet, "/v1/models", "sk-not-a-token", "", http.StatusUnauthorized},
		{http.MethodPost, "/v1/chat/completions", wireSecret, `{"model":"` + w.alias + `","messages":[]}`, http.StatusForbidden},
		{http.MethodPost, "/v1/chat/completions", wireSecret, `{"model":"Client-Invented-Model","messages":[]}`, http.StatusForbidden},
		{http.MethodGet, "/v1/ws", wireSecret, "", http.StatusNotFound},
	} {
		req, err := http.NewRequest(c.method, w.baseURL+c.path, strings.NewReader(c.body))
		if err != nil {
			t.Fatal(err)
		}
		if c.key != "" {
			req.Header.Set("Authorization", "Bearer "+c.key)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", c.method, c.path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Fatalf("%s %s with key %q = %d, want %d", c.method, c.path, c.key, resp.StatusCode, c.want)
		}
	}

	want := []observed{
		{authFailed: AuthMissing},
		{authFailed: AuthInvalid},
		{owner: "alice@example.com", model: w.alias, reason: DenyModelNotAllowed, denied: true},
		{owner: "alice@example.com", model: "Client-Invented-Model", reason: DenyUnknownModel, denied: true},
		{reason: DenyRouteNotAllowed, denied: true},
	}
	if got := observer.seen(); !reflect.DeepEqual(got, want) {
		t.Fatalf("observed %+v\nwant     %+v", got, want)
	}
}
