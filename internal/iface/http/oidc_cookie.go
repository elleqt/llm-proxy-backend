package http

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
)

// minSessionKeyLen is the shortest key NewRouter accepts for sealing the OIDC challenge;
// config.MinSessionKeyLen enforces the same floor when the variable is read.
const minSessionKeyLen = 32

// oidcChallengeTTL is how long a started OpenID Connect login may take.
const oidcChallengeTTL = 10 * time.Minute

// errChallenge is every reason a challenge cookie is refused. The reasons are not
// told apart: a forged, tampered, stale or truncated cookie all mean the same thing,
// and none of them is worth a different answer.
var errChallenge = errors.New("web: unusable oidc challenge cookie")

// errShortSessionKey refuses a session key below minSessionKeyLen; the caller adds
// the floor, so the message reads "... at least 32 bytes".
var errShortSessionKey = errors.New("web: the session key must be at least")

// challengeSealer keeps the OpenID Connect challenge in the browser, authenticated and
// encrypted.
//
// The challenge (state, nonce, PKCE verifier) must survive from the redirect to the
// IdP until the callback. It lives in a cookie rather than in server memory or the
// database because that is the option with nothing to exhaust: /oidc/start is
// anonymous, and a server-side store keyed by a random id is a table any client can
// fill by requesting it in a loop — bounded, it evicts the logins of real people; not,
// it grows without limit. A cookie also survives a restart and needs no sweep.
// Encryption, not only a MAC, because the verifier is a secret that must not be
// readable where the cookie is stored, and the seal carries its own expiry, because a
// cookie's Max-Age is only the browser's promise.
type challengeSealer struct {
	aead  cipher.AEAD
	clock app.Clock
}

// sealedChallenge is the plaintext inside the cookie.
type sealedChallenge struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Expires  int64  `json:"e"`
}

// newChallengeSealer derives the AES-256-GCM key from key with HKDF-SHA256, so the
// configured secret is never used directly and a later second use of it gets an
// independent key under another label.
func newChallengeSealer(key []byte, clock app.Clock) (*challengeSealer, error) {
	if len(key) < minSessionKeyLen {
		return nil, fmt.Errorf("%w %d bytes", errShortSessionKey, minSessionKeyLen)
	}

	k, err := hkdf.Key(sha256.New, key, nil, "llmproxy oidc challenge cookie v1", 32)
	if err != nil {
		return nil, fmt.Errorf("web: derive challenge key: %w", err)
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, fmt.Errorf("web: challenge cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("web: challenge cipher: %w", err)
	}

	return &challengeSealer{aead: aead, clock: clock}, nil
}

// seal returns the cookie value for ch. The cookie name is the additional data, so a
// value sealed for this cookie opens as nothing else.
func (s *challengeSealer) seal(ch app.Challenge) (string, error) {
	plain, err := json.Marshal(sealedChallenge{
		State: ch.State, Nonce: ch.Nonce, Verifier: ch.Verifier,
		Expires: s.clock.Now().Add(oidcChallengeTTL).Unix(),
	})
	if err != nil {
		return "", fmt.Errorf("web: encode challenge: %w", err)
	}

	nonce := make([]byte, s.aead.NonceSize(), s.aead.NonceSize()+len(plain)+s.aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("web: challenge nonce: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(s.aead.Seal(nonce, nonce, plain, []byte(oidcCookieName))), nil
}

// open returns the challenge value sealed, or errChallenge.
func (s *challengeSealer) open(value string) (app.Challenge, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) < s.aead.NonceSize() {
		return app.Challenge{}, errChallenge
	}

	n := s.aead.NonceSize()

	plain, err := s.aead.Open(nil, raw[:n], raw[n:], []byte(oidcCookieName))
	if err != nil {
		return app.Challenge{}, errChallenge
	}

	var sc sealedChallenge
	if err := json.Unmarshal(plain, &sc); err != nil {
		return app.Challenge{}, errChallenge
	}

	if !s.clock.Now().Before(time.Unix(sc.Expires, 0)) {
		return app.Challenge{}, errChallenge
	}

	return app.Challenge{State: sc.State, Nonce: sc.Nonce, Verifier: sc.Verifier}, nil
}
