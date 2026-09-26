// Package credentials holds the proxy's own API keys (Token) and the sealing of the
// vendor accounts' OAuth credentials stored in the database (Sealer). It is pure
// code: nothing here does I/O beyond reading the system's random source.
package credentials

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// MinSealerKeyLen is the shortest key NewSealer accepts; config.MinCredentialsKeyLen
// enforces the same floor when LLMPROXY_CREDENTIALS_KEY is read.
const MinSealerKeyLen = 32

// sealerInfo labels the key derived for vendor credentials. A second use of the same
// secret must derive its key under a label of its own, never this one.
const sealerInfo = "llmproxy vendor credentials v1"

// sealVersion is the first byte of every sealed value. It names the construction
// (this key derivation, AES-256-GCM, a 12-byte random nonce), so a later key
// rotation or change of construction can tell stored values apart; Open refuses
// any other.
const sealVersion byte = 0x01

var (
	// ErrShortSealerKey refuses a key below MinSealerKeyLen.
	ErrShortSealerKey = errors.New("credentials: the sealer key must be at least 32 bytes")
	// ErrUnsealable is every reason a sealed value does not open: a wrong key, a value
	// sealed for another id, an unknown version, a truncated or tampered value. They
	// are not told apart; each means the stored credential cannot be used.
	ErrUnsealable = errors.New("credentials: the sealed credential cannot be opened")
)

// Sealer encrypts and authenticates vendor credentials for storage. The id a value
// is sealed for is its additional data, so sealed bytes copied onto another
// account's row do not open there. It is safe for concurrent use.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer derives the AES-256-GCM key from key with HKDF-SHA256, as the OIDC
// challenge cookie does, so the configured secret is never used directly. The same
// key always derives the same cipher: values sealed before a restart open after it.
func NewSealer(key []byte) (*Sealer, error) {
	if len(key) < MinSealerKeyLen {
		return nil, ErrShortSealerKey
	}

	derived, err := hkdf.Key(sha256.New, key, nil, sealerInfo, 32)
	if err != nil {
		return nil, fmt.Errorf("credentials: derive the sealer key: %w", err)
	}

	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf("credentials: sealer cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("credentials: sealer cipher: %w", err)
	}

	return &Sealer{aead: aead}, nil
}

// Seal returns sealVersion || nonce || ciphertext+tag for plaintext stored under
// id. The nonce is fresh from crypto/rand on every call: under one GCM key a
// repeated nonce discloses plaintext and lets tags be forged.
func (s *Sealer) Seal(id string, plaintext []byte) ([]byte, error) {
	nonceLen := s.aead.NonceSize()
	out := append(make([]byte, 0, 1+nonceLen+len(plaintext)+s.aead.Overhead()), sealVersion)
	out = out[:1+nonceLen]

	nonce := out[1:]
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("credentials: seal nonce: %w", err)
	}

	return s.aead.Seal(out, nonce, plaintext, []byte(id)), nil
}

// Open returns the plaintext Seal sealed for id. Every failure is ErrUnsealable.
func (s *Sealer) Open(id string, sealed []byte) ([]byte, error) {
	header := 1 + s.aead.NonceSize()
	if len(sealed) < header+s.aead.Overhead() || sealed[0] != sealVersion {
		return nil, ErrUnsealable
	}

	plaintext, err := s.aead.Open(nil, sealed[1:header], sealed[header:], []byte(id))
	if err != nil {
		return nil, ErrUnsealable
	}

	return plaintext, nil
}
