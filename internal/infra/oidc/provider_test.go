package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/infra/oidc"
)

const (
	clientID     = "llm-proxy"
	clientSecret = "client-secret-value"
	redirectURL  = "https://proxy.example.com/api/auth/oidc/callback"
	groupsClaim  = "team_groups"
)

// fakeIdP is a minimal OpenID provider: discovery, a key set, and a token endpoint
// that answers any code with whatever ID token the test mints.
type fakeIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey

	mu    sync.Mutex
	mint  func(issuer string) map[string]any
	forms []url.Values
	// signingKey, when set, signs the ID token instead of key. It is never
	// published in the key set, so the signature cannot verify.
	signingKey *rsa.PrivateKey
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	f := &fakeIdP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/auth",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.forms = append(f.forms, r.PostForm)
		mint, key := f.mint, f.signingKey
		f.mu.Unlock()
		if key == nil {
			key = f.key
		}
		writeJSON(w, map[string]any{
			"access_token": "access-token-value",
			"token_type":   "Bearer",
			"expires_in":   300,
			"id_token":     sign(t, key, mint(f.srv.URL)),
		})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func sign(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		t.Errorf("signer: %v", err)
		return ""
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Errorf("sign: %v", err)
	}
	return raw
}

func (f *fakeIdP) setMint(m func(issuer string) map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mint = m
}

func (f *fakeIdP) lastForm() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.forms) == 0 {
		return nil
	}
	return f.forms[len(f.forms)-1]
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

var challenge = app.Challenge{
	State:    "state-abc",
	Nonce:    "nonce-abc",
	Verifier: "verifier-abcdefghijklmnopqrstuvwxyz0123456789-._~",
}

// validClaims is a token the relying party must accept for challenge.
func validClaims(issuer string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":            issuer,
		"sub":            "subject-1",
		"aud":            clientID,
		"iat":            now.Unix(),
		"exp":            now.Add(5 * time.Minute).Unix(),
		"nonce":          challenge.Nonce,
		"email":          "person@example.com",
		"email_verified": true,
		groupsClaim:      []string{"/gate", "/team-a"},
		// A claim literally named "groups" that is NOT the configured one: reading it
		// instead of groupsClaim would change the answer.
		"groups": []string{"/decoy"},
	}
}

func newProvider(t *testing.T, idp *fakeIdP) *oidc.Provider {
	t.Helper()
	p, err := oidc.New(context.Background(), oidc.Config{
		Issuer:       idp.srv.URL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		GroupsClaim:  groupsClaim,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestExchangeAcceptsAValidTokenBoundToTheLogin(t *testing.T) {
	idp := newFakeIdP(t)
	idp.setMint(validClaims)
	p := newProvider(t, idp)

	// The authorization request carries the state, the nonce, and the S256 challenge
	// of the verifier — never the verifier itself.
	auth, err := url.Parse(p.AuthURL(challenge))
	if err != nil {
		t.Fatalf("parse AuthURL: %v", err)
	}
	q := auth.Query()
	sum := sha256.Sum256([]byte(challenge.Verifier))
	if q.Get("state") != challenge.State || q.Get("nonce") != challenge.Nonce ||
		q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatalf("AuthURL query = %v, want state, nonce and the S256 challenge", q)
	}
	if strings.Contains(auth.String(), challenge.Verifier) {
		t.Fatal("AuthURL reveals the PKCE verifier")
	}

	got, err := p.Exchange(context.Background(), "the-code", challenge)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	form := idp.lastForm()
	if form.Get("code") != "the-code" || form.Get("code_verifier") != challenge.Verifier {
		t.Fatalf("token request = %v, want the code and the PKCE verifier", form)
	}
	want := app.Claims{
		Issuer: idp.srv.URL, Subject: "subject-1",
		Email: "person@example.com", EmailVerified: true,
		Groups: []string{"/gate", "/team-a"},
	}
	if got.Issuer != want.Issuer || got.Subject != want.Subject || got.Email != want.Email ||
		got.EmailVerified != want.EmailVerified || !slices.Equal(got.Groups, want.Groups) {
		t.Fatalf("claims = %+v, want %+v", got, want)
	}
}

func TestExchangeRejectsATokenItCannotTrust(t *testing.T) {
	// An attacker's key, used under the published key id: only signature
	// verification tells this token from a genuine one.
	forged, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(c map[string]any)
		key    *rsa.PrivateKey
	}{
		{"signed by a key the IdP never published", func(map[string]any) {}, forged},
		{"issued by another issuer", func(c map[string]any) { c["iss"] = "https://other-idp.example.com" }, nil},
		{"nonce of another login", func(c map[string]any) { c["nonce"] = "nonce-of-someone-else" }, nil},
		{"issued to another client", func(c map[string]any) { c["aud"] = "another-client" }, nil},
		{"expired", func(c map[string]any) {
			c["iat"] = time.Now().Add(-2 * time.Hour).Unix()
			c["exp"] = time.Now().Add(-time.Hour).Unix()
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idp := newFakeIdP(t)
			idp.setMint(func(issuer string) map[string]any {
				c := validClaims(issuer)
				tc.mutate(c)
				return c
			})
			idp.signingKey = tc.key
			p := newProvider(t, idp)

			_, err := p.Exchange(context.Background(), "the-code", challenge)
			if !errors.Is(err, app.ErrInvalidCredentials) {
				t.Fatalf("err = %v, want ErrInvalidCredentials", err)
			}
			for _, secret := range []string{clientSecret, challenge.Verifier, "the-code"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error %q leaks %q", err, secret)
				}
			}
		})
	}
}

// The name is the name claim, else preferred_username, else the email's local
// part — each only if something is left once it is cleaned — trimmed, without
// control characters, at most 100 runes. A claim of the wrong type is skipped.
func TestExchangeNamesThePerson(t *testing.T) {
	long := strings.Repeat("é", 150)
	for _, tc := range []struct {
		name   string
		claims map[string]any
		want   string
	}{
		{"name claim", map[string]any{"name": "  Ada Lovelace ", "preferred_username": "ada"}, "Ada Lovelace"},
		{"preferred_username when there is no name", map[string]any{"preferred_username": "ada"}, "ada"},
		{"preferred_username when the name is blank", map[string]any{"name": " \t ", "preferred_username": "ada"}, "ada"},
		{"email local part when neither is given", map[string]any{}, "person"},
		{"a name that is not a string is skipped", map[string]any{"name": 42, "preferred_username": []string{"x"}}, "person"},
		{"control characters dropped", map[string]any{"name": "Ada\u0000 Love\nlace\u001b"}, "Ada Lovelace"},
		{"cut to 100 runes", map[string]any{"name": long}, strings.Repeat("é", 100)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idp := newFakeIdP(t)
			idp.setMint(func(issuer string) map[string]any {
				c := validClaims(issuer)
				maps.Copy(c, tc.claims)
				return c
			})
			got, err := newProvider(t, idp).Exchange(context.Background(), "the-code", challenge)
			if err != nil {
				t.Fatalf("Exchange: %v", err)
			}
			if got.Name != tc.want {
				t.Fatalf("Name = %q, want %q", got.Name, tc.want)
			}
		})
	}

	// No name, no username, no email: no name either.
	idp := newFakeIdP(t)
	idp.setMint(func(issuer string) map[string]any {
		c := validClaims(issuer)
		delete(c, "email")
		return c
	})
	got, err := newProvider(t, idp).Exchange(context.Background(), "the-code", challenge)
	if err != nil || got.Name != "" {
		t.Fatalf("Name = %q, err %v; want empty", got.Name, err)
	}
}
