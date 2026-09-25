package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/infra/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	clientID     = "llm-proxy"
	clientSecret = "client-secret-value"
	redirectURL  = "https://proxy.example.com/api/auth/oidc/callback"
	groupsClaim  = "team_groups"
)

// fakeIDP is a minimal OpenID provider: discovery, a key set, and a token endpoint
// that answers any code with whatever ID token the test mints.
type fakeIDP struct {
	srv *httptest.Server
	key *rsa.PrivateKey

	mu    sync.Mutex
	mint  func(issuer string) map[string]any
	forms []url.Values
	// signingKey, when set, signs the ID token instead of key. It is never
	// published in the key set, so the signature cannot verify.
	signingKey *rsa.PrivateKey
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "generate key")

	fake := &fakeIDP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                fake.srv.URL,
			"authorization_endpoint":                fake.srv.URL + "/auth",
			"token_endpoint":                        fake.srv.URL + "/token",
			"jwks_uri":                              fake.srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("/token", func(writer http.ResponseWriter, req *http.Request) {
		if err := req.ParseForm(); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)

			return
		}

		fake.mu.Lock()
		fake.forms = append(fake.forms, req.PostForm)
		mint, key := fake.mint, fake.signingKey
		fake.mu.Unlock()

		if key == nil {
			key = fake.key
		}

		// The handler runs off the test goroutine: assert, never require.
		idToken, err := sign(key, mint(fake.srv.URL))
		if !assert.NoError(t, err, "sign ID token") {
			http.Error(writer, err.Error(), http.StatusInternalServerError)

			return
		}

		writeJSON(writer, map[string]any{
			"access_token": "access-token-value",
			"token_type":   "Bearer",
			"expires_in":   300,
			"id_token":     idToken,
		})
	})
	fake.srv = httptest.NewServer(mux)
	t.Cleanup(fake.srv.Close)

	return fake
}

func sign(key *rsa.PrivateKey, claims map[string]any) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		return "", fmt.Errorf("signer: %w", err)
	}

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	return raw, nil
}

func (f *fakeIDP) setMint(m func(issuer string) map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.mint = m
}

func (f *fakeIDP) lastForm() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()

	if len(f.forms) == 0 {
		return nil
	}

	return f.forms[len(f.forms)-1]
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
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

func newProvider(t *testing.T, idp *fakeIDP) *oidc.Provider {
	t.Helper()

	provider, err := oidc.New(context.Background(), oidc.Config{
		Issuer:       idp.srv.URL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		GroupsClaim:  groupsClaim,
	})
	require.NoError(t, err, "New")

	return provider
}

func TestExchangeAcceptsAValidTokenBoundToTheLogin(t *testing.T) {
	idp := newFakeIDP(t)
	idp.setMint(validClaims)
	provider := newProvider(t, idp)

	// The authorization request carries the state, the nonce, and the S256 challenge
	// of the verifier — never the verifier itself.
	auth, err := url.Parse(provider.AuthURL(challenge))
	require.NoError(t, err, "parse AuthURL")

	query := auth.Query()

	sum := sha256.Sum256([]byte(challenge.Verifier))
	require.Equal(t, challenge.State, query.Get("state"), "AuthURL state")
	require.Equal(t, challenge.Nonce, query.Get("nonce"), "AuthURL nonce")
	require.Equal(t, "S256", query.Get("code_challenge_method"), "AuthURL code_challenge_method")
	require.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), query.Get("code_challenge"), "AuthURL code_challenge")
	require.NotContains(t, auth.String(), challenge.Verifier, "AuthURL reveals the PKCE verifier")

	got, err := provider.Exchange(context.Background(), "the-code", challenge)
	require.NoError(t, err, "Exchange")

	form := idp.lastForm()
	require.Equal(t, "the-code", form.Get("code"), "token request code")
	require.Equal(t, challenge.Verifier, form.Get("code_verifier"), "token request PKCE verifier")

	want := app.Claims{
		Issuer: idp.srv.URL, Subject: "subject-1",
		Email: "person@example.com", EmailVerified: true,
		Groups: []string{"/gate", "/team-a"},
	}
	require.Equal(t, want.Issuer, got.Issuer, "claims issuer")
	require.Equal(t, want.Subject, got.Subject, "claims subject")
	require.Equal(t, want.Email, got.Email, "claims email")
	require.Equal(t, want.EmailVerified, got.EmailVerified, "claims email_verified")
	require.Equal(t, want.Groups, got.Groups, "claims groups")
}

func TestExchangeRejectsATokenItCannotTrust(t *testing.T) {
	// An attacker's key, used under the published key id: only signature
	// verification tells this token from a genuine one.
	forged, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "generate key")

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
			idp := newFakeIDP(t)
			idp.setMint(func(issuer string) map[string]any {
				c := validClaims(issuer)
				tc.mutate(c)

				return c
			})
			idp.signingKey = tc.key
			p := newProvider(t, idp)

			_, err := p.Exchange(context.Background(), "the-code", challenge)
			require.ErrorIs(t, err, app.ErrInvalidCredentials)

			for _, secret := range []string{clientSecret, challenge.Verifier, "the-code"} {
				require.NotContains(t, err.Error(), secret, "error leaks a secret")
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
			idp := newFakeIDP(t)
			idp.setMint(func(issuer string) map[string]any {
				c := validClaims(issuer)
				maps.Copy(c, tc.claims)

				return c
			})

			got, err := newProvider(t, idp).Exchange(context.Background(), "the-code", challenge)
			require.NoError(t, err, "Exchange")
			require.Equal(t, tc.want, got.Name, "Name")
		})
	}

	// No name, no username, no email: no name either.
	idp := newFakeIDP(t)
	idp.setMint(func(issuer string) map[string]any {
		c := validClaims(issuer)
		delete(c, "email")

		return c
	})

	got, err := newProvider(t, idp).Exchange(context.Background(), "the-code", challenge)
	require.NoError(t, err, "Exchange")
	require.Empty(t, got.Name, "Name")
}
