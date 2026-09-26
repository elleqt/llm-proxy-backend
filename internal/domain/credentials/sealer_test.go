package credentials

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// sealerKey is exactly MinSealerKeyLen bytes: the shortest key NewSealer takes.
var sealerKey = bytes.Repeat([]byte("k"), MinSealerKeyLen)

// credentialJSON stands in for a vendor account's credential file.
const credentialJSON = `{"access_token":"at-secret","refresh_token":"rt-secret","type":"claude"}`

const sealedID = "claude-user@example.com.json"

func newTestSealer(t *testing.T, key []byte) *Sealer {
	t.Helper()

	sealer, err := NewSealer(key)
	require.NoError(t, err, "NewSealer")

	return sealer
}

// withByte returns a copy of b with b[i] replaced by v.
func withByte(b []byte, i int, v byte) []byte {
	c := bytes.Clone(b)
	c[i] = v

	return c
}

// A credential sealed for an account opens for that account — also through another
// Sealer built from the same key, as after a restart — and the stored bytes do not
// carry the plaintext.
func TestSealerOpensWhatItSealed(t *testing.T) {
	sealed, err := newTestSealer(t, sealerKey).Seal(sealedID, []byte(credentialJSON))
	require.NoError(t, err, "Seal")

	leaked := bytes.Contains(sealed, []byte("at-secret"))
	require.False(t, leaked, "the sealed bytes carry the access token")

	opened, err := newTestSealer(t, sealerKey).Open(sealedID, sealed)
	require.NoError(t, err, "Open")
	require.JSONEq(t, credentialJSON, string(opened), "opened plaintext")
}

// openCase is one stored value Open must refuse.
type openCase struct {
	sealer *Sealer
	id     string
	sealed []byte
}

// Every way a stored value can be wrong — tampered anywhere, moved to another
// account, read with another key, from an unknown format version, truncated — is
// the one error ErrUnsealable, with no plaintext.
func TestSealerOpensNothingButTheValueSealedForTheID(t *testing.T) {
	sealer := newTestSealer(t, sealerKey)

	sealed, err := sealer.Seal(sealedID, []byte(credentialJSON))
	require.NoError(t, err, "Seal")

	other := newTestSealer(t, bytes.Repeat([]byte("o"), MinSealerKeyLen))

	cases := map[string]openCase{
		"another id":      {sealer, "codex-user@example.com.json", sealed},
		"another key":     {other, sealedID, sealed},
		"unknown version": {sealer, sealedID, withByte(sealed, 0, 0x02)},
		"empty":           {sealer, sealedID, nil},
		"version only":    {sealer, sealedID, sealed[:1]},
		// The version byte and the 12-byte nonce, no ciphertext and no tag.
		"header only":   {sealer, sealedID, sealed[:1+12]},
		"truncated tag": {sealer, sealedID, sealed[:len(sealed)-1]},
	}
	for i := range sealed {
		cases[fmt.Sprintf("byte %d flipped", i)] = openCase{sealer, sealedID, withByte(sealed, i, sealed[i]^0x01)}
	}

	for name, tc := range cases {
		plain, err := tc.sealer.Open(tc.id, tc.sealed)
		require.ErrorIs(t, err, ErrUnsealable, name)
		require.Nil(t, plain, name)
	}
}

// The key is an operator's secret, not a derived one: below 32 bytes it is refused
// rather than stretched. 32 bytes is enough.
func TestNewSealerRefusesAShortKey(t *testing.T) {
	_, err := NewSealer(sealerKey[:MinSealerKeyLen-1])
	require.ErrorIs(t, err, ErrShortSealerKey)

	_, err = NewSealer(sealerKey)
	require.NoError(t, err, "a key of exactly MinSealerKeyLen bytes")
}

// Every seal draws a fresh nonce, so sealing the same credential twice never gives
// the same bytes: under one GCM key a repeated nonce discloses the plaintexts' XOR
// and lets tags be forged.
func TestSealDrawsAFreshNonceEveryTime(t *testing.T) {
	sealer := newTestSealer(t, sealerKey)

	first, err := sealer.Seal(sealedID, []byte(credentialJSON))
	require.NoError(t, err, "first Seal")

	second, err := sealer.Seal(sealedID, []byte(credentialJSON))
	require.NoError(t, err, "second Seal")
	require.NotEqual(t, first, second, "two seals of the same plaintext are equal")
}

// The stored format is a contract with every row already in the database: a value
// built from the specification alone — HKDF-SHA256 over the key with the info
// "llmproxy vendor credentials v1", AES-256-GCM, 0x01 || nonce(12) ||
// ciphertext+tag, the account id as additional data — must open, and Seal must
// produce that layout. A change of construction fails here instead of at boot.
func TestSealerReadsTheSpecifiedFormat(t *testing.T) {
	derived, err := hkdf.Key(sha256.New, sealerKey, nil, "llmproxy vendor credentials v1", 32)
	require.NoError(t, err)

	block, err := aes.NewCipher(derived)
	require.NoError(t, err)

	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	nonce := []byte("fixed-nonce!") // 12 bytes, as GCM's standard nonce
	require.Len(t, nonce, gcm.NonceSize())

	vector := append([]byte{0x01}, nonce...)
	vector = append(vector, gcm.Seal(nil, nonce, []byte(credentialJSON), []byte(sealedID))...)

	sealer := newTestSealer(t, sealerKey)

	opened, err := sealer.Open(sealedID, vector)
	require.NoError(t, err, "a value sealed as specified does not open")
	require.JSONEq(t, credentialJSON, string(opened))

	sealed, err := sealer.Seal(sealedID, []byte(credentialJSON))
	require.NoError(t, err)
	require.Equal(t, byte(0x01), sealed[0], "the format version byte")
	require.Len(t, sealed, 1+gcm.NonceSize()+len(credentialJSON)+gcm.Overhead(), "version, nonce, ciphertext and tag")
}
