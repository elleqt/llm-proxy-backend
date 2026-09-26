package login

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	"github.com/elleqt/llm-proxy-backend/internal/infra/gateway"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// storageStore is a gateway.CredentialStore over a strict mock repository and
// a real sealer, serializing login records into scratch, a directory of its
// own.
type storageStore struct {
	store   *gateway.CredentialStore
	repo    *mocks.VendorCredentialRepo
	sealer  *credentials.Sealer
	scratch string
}

func newStorageStore(t *testing.T) storageStore {
	t.Helper()

	repo, clock := mocks.NewVendorCredentialRepo(t), mocks.NewClock(t)
	clock.EXPECT().Now().Return(time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)).Maybe()

	sealer, err := credentials.NewSealer(bytes.Repeat([]byte("k"), credentials.MinSealerKeyLen))
	require.NoError(t, err)

	scratch := t.TempDir()

	store, err := gateway.NewCredentialStore(repo, sealer, clock, scratch)
	require.NoError(t, err)

	return storageStore{store: store, repo: repo, sealer: sealer, scratch: scratch}
}

// assertScratchEmpty asserts that no plaintext is left in the scratch
// directory.
func (s storageStore) assertScratchEmpty(t *testing.T) {
	t.Helper()

	entries, err := os.ReadDir(s.scratch)
	require.NoError(t, err)
	assert.Empty(t, entries, "the login's plaintext credential was left in the scratch directory")
}

// TestCredentialStoreSavesALoginThroughItsTokenFile: a fresh login's record
// carries its tokens only in Storage. The row must hold what the vendor's own
// SaveTokenToFile writes (tokens, email, type and the metadata the store
// injects), and the temporary file must be gone once Save returns.
func TestCredentialStoreSavesALoginThroughItsTokenFile(t *testing.T) {
	st := newStorageStore(t)
	storage := &claudeTokenFile{accessToken: "sk-ant-oat-store", refreshToken: "sk-ant-ort-store", email: "store@example.com"}
	grant := storageGrant(t, storage)

	var row app.VendorCredential

	st.repo.EXPECT().Upsert(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, written app.VendorCredential) error {
		row = written

		return nil
	}).Once()

	key, err := st.store.Save(coreauth.WithAuthCreationIntent(t.Context()), grant)
	require.NoError(t, err)
	require.Equal(t, grant.FileName, key)
	assert.Equal(t, "claude", row.Provider, "the row's provider: want the token file's type")

	plaintext, err := st.sealer.Open(key, row.Sealed)
	require.NoError(t, err)

	var fields map[string]any
	require.NoError(t, json.Unmarshal(plaintext, &fields))

	assert.NotEmpty(t, fields["expired"], "the token file's expiry is not in the row")
	delete(fields, "expired")
	assert.Equal(t, map[string]any{
		"type": "claude", "access_token": storage.accessToken, "refresh_token": storage.refreshToken,
		"email": storage.email, "disabled": false,
	}, fields)
	st.assertScratchEmpty(t)
}

// TestCredentialStoreRemovesTheScratchFileWhenTheTokenFileFails: a token file
// that cannot be written fails Save with its error, writes no row (no
// repository call is expected) and leaves nothing in the scratch directory.
func TestCredentialStoreRemovesTheScratchFileWhenTheTokenFileFails(t *testing.T) {
	st := newStorageStore(t)
	errWrite := errors.New("token file write refused by test")
	grant := storageGrant(t, &claudeTokenFile{
		accessToken: "sk-ant-oat-failed", refreshToken: "sk-ant-ort-failed", email: "failed@example.com", fail: errWrite,
	})

	_, err := st.store.Save(coreauth.WithAuthCreationIntent(t.Context()), grant)
	require.ErrorIs(t, err, errWrite)
	st.assertScratchEmpty(t)
}

// TestCredentialStoreRemovesTheScratchFileWhenTheTokenFileWriterPanics: the
// vendor's SaveTokenToFile runs inside Save; if it panics after writing the
// plaintext, a recovering caller (the web router recovers panics) keeps the
// process up, and the scratch directory must still be gone.
func TestCredentialStoreRemovesTheScratchFileWhenTheTokenFileWriterPanics(t *testing.T) {
	st := newStorageStore(t)
	grant := storageGrant(t, &claudeTokenFile{
		accessToken: "sk-ant-oat-panic", refreshToken: "sk-ant-ort-panic", email: "panic@example.com", panicAfterWrite: true,
	})

	require.Panics(t, func() { _, _ = st.store.Save(coreauth.WithAuthCreationIntent(t.Context()), grant) })
	st.assertScratchEmpty(t)
}

// TestCredentialStoreRefusesALoginWithoutTokens: the vendor's storage writes
// both token keys even when they are empty. A record that would store a
// credential unable to authenticate is refused, and nothing is left behind.
func TestCredentialStoreRefusesALoginWithoutTokens(t *testing.T) {
	st := newStorageStore(t)
	grant := storageGrant(t, &claudeTokenFile{email: "tokenless@example.com"})

	_, err := st.store.Save(coreauth.WithAuthCreationIntent(t.Context()), grant)
	// errTokenlessCredential is unexported in package gateway: its message is
	// what this package can match.
	require.ErrorContains(t, err, "carries no access or refresh token")
	st.assertScratchEmpty(t)
}
