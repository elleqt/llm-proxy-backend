package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// storeNow is the frozen clock of every credential store test.
var storeNow = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

// storeFixture is a CredentialStore over a strict mock repository, a real
// sealer and a frozen clock, serializing into a scratch directory of its own.
type storeFixture struct {
	store  *CredentialStore
	repo   *mocks.VendorCredentialRepo
	sealer *credentials.Sealer
}

func newStoreFixture(t *testing.T) storeFixture {
	t.Helper()

	repo, clock := mocks.NewVendorCredentialRepo(t), mocks.NewClock(t)
	clock.EXPECT().Now().Return(storeNow).Maybe()

	sealer := testSealer(t, 'k')

	store, err := NewCredentialStore(repo, sealer, clock, t.TempDir())
	require.NoError(t, err)

	return storeFixture{store: store, repo: repo, sealer: sealer}
}

// testSealer is a sealer whose key is MinSealerKeyLen bytes of fill.
func testSealer(t *testing.T, fill byte) *credentials.Sealer {
	t.Helper()

	sealer, err := credentials.NewSealer(bytes.Repeat([]byte{fill}, credentials.MinSealerKeyLen))
	require.NoError(t, err)

	return sealer
}

// keep is a repository write that succeeds and records the row it was handed.
func keep(row *app.VendorCredential) func(context.Context, app.VendorCredential) error {
	return func(_ context.Context, written app.VendorCredential) error {
		*row = written

		return nil
	}
}

// opened is the credential JSON a written row seals, as fields.
func opened(t *testing.T, sealer *credentials.Sealer, row app.VendorCredential) map[string]any {
	t.Helper()

	plaintext, err := sealer.Open(row.ID, row.Sealed)
	require.NoError(t, err, "the written row does not open under its own id")

	var fields map[string]any
	require.NoError(t, json.Unmarshal(plaintext, &fields))

	return fields
}

// runtimeAuth is a stored account as the manager saves it after a refresh or
// a cooldown change: no Storage, the credential in Metadata.
func runtimeAuth() *coreauth.Auth {
	const id = "claude-runtime@example.com.json"

	return &coreauth.Auth{ID: id, FileName: id, Provider: "claude", Metadata: map[string]any{
		"type": "claude", "email": "runtime@example.com", "access_token": "at-1",
	}}
}

// TestCredentialStoreSaveWithCreationIntentUpserts: AddAccount's save, the
// only one carrying creation intent, inserts the row sealed under the
// account's key, with the metadata normalized and the disabled flag written
// as FileTokenStore writes them, and marks the record as held in Postgres.
func TestCredentialStoreSaveWithCreationIntentUpserts(t *testing.T) {
	fx := newStoreFixture(t)
	auth := &coreauth.Auth{ID: "codex-new@example.com.json", Provider: "codex", Metadata: map[string]any{
		"type": "codex", "email": "new@example.com", "access_token": "at-new", "proxy-url": "http://proxy.example.com:3128",
	}}

	var row app.VendorCredential
	fx.repo.EXPECT().Upsert(mock.Anything, mock.Anything).RunAndReturn(keep(&row)).Once()

	key, err := fx.store.Save(coreauth.WithAuthCreationIntent(t.Context()), auth)
	require.NoError(t, err)
	require.Equal(t, auth.ID, key, "a record without a file name is keyed by its id")

	assert.Equal(t, app.VendorCredential{ID: key, Provider: "codex", Sealed: row.Sealed, CreatedAt: storeNow, UpdatedAt: storeNow}, row)
	assert.Equal(t, map[string]any{
		"type": "codex", "email": "new@example.com", "access_token": "at-new",
		"proxy_url": "http://proxy.example.com:3128", "disabled": false,
	}, opened(t, fx.sealer, row))
	assert.Equal(t, key, auth.FileName)
	assert.Equal(t, key, auth.Attributes[coreauth.AttributeSource])
	assert.Equal(t, coreauth.AuthSourcePostgres, auth.Attributes[coreauth.AttributeSourceBackend])
}

// TestCredentialStoreRuntimeSaveWritesOnlyAChange: a save without creation
// intent updates the row (an Upsert would fail the strict mock). Upstream
// saves on every cooldown transition; a fresh nonce makes every ciphertext
// differ, so an unchanged record must not be written again, while a changed
// one must.
func TestCredentialStoreRuntimeSaveWritesOnlyAChange(t *testing.T) {
	fx := newStoreFixture(t)
	auth := runtimeAuth()

	fx.repo.EXPECT().Update(mock.Anything, mock.Anything).Return(nil).Once()

	for range 2 {
		key, err := fx.store.Save(t.Context(), auth)
		require.NoError(t, err)
		require.Equal(t, auth.ID, key)
	}

	auth.Metadata["access_token"] = "at-2"

	var row app.VendorCredential
	fx.repo.EXPECT().Update(mock.Anything, mock.Anything).RunAndReturn(keep(&row)).Once()

	_, err := fx.store.Save(t.Context(), auth)
	require.NoError(t, err)
	assert.Equal(t, "at-2", opened(t, fx.sealer, row)["access_token"], "the changed record was not written")
}

// TestCredentialStoreRuntimeSaveNeverRecreatesARemovedAccount: a row that is
// gone when a runtime save updates it means the account was removed; Save
// writes nothing, reports no key, and forgets what it knew of the row.
func TestCredentialStoreRuntimeSaveNeverRecreatesARemovedAccount(t *testing.T) {
	fx := newStoreFixture(t)
	auth := runtimeAuth()

	fx.repo.EXPECT().Update(mock.Anything, mock.Anything).Return(nil).Once()

	_, err := fx.store.Save(t.Context(), auth)
	require.NoError(t, err)

	auth.Metadata["access_token"] = "at-2"

	fx.repo.EXPECT().Update(mock.Anything, mock.Anything).Return(app.ErrNotFound).Once()

	key, err := fx.store.Save(t.Context(), auth)
	require.NoError(t, err, "a runtime save of a removed account")
	require.Empty(t, key, "a runtime save of a removed account")

	// Back to the content first written: the store must ask the repository
	// again, not trust the digest of a row that is gone.
	auth.Metadata["access_token"] = "at-1"

	fx.repo.EXPECT().Update(mock.Anything, mock.Anything).Return(app.ErrNotFound).Once()

	key, err = fx.store.Save(t.Context(), auth)
	require.NoError(t, err)
	require.Empty(t, key)
}

// TestCredentialStoreDeleteForgetsTheRow: after Delete, saving the content
// last written reaches the repository instead of being skipped as unchanged.
func TestCredentialStoreDeleteForgetsTheRow(t *testing.T) {
	fx := newStoreFixture(t)
	auth := runtimeAuth()

	fx.repo.EXPECT().Update(mock.Anything, mock.Anything).Return(nil).Once()

	key, err := fx.store.Save(t.Context(), auth)
	require.NoError(t, err)

	fx.repo.EXPECT().Delete(mock.Anything, key).Return(nil).Once()
	require.NoError(t, fx.store.Delete(t.Context(), key))

	fx.repo.EXPECT().Update(mock.Anything, mock.Anything).Return(app.ErrNotFound).Once()

	key, err = fx.store.Save(t.Context(), auth)
	require.NoError(t, err)
	require.Empty(t, key, "a runtime save after Delete re-created the account")
}

// TestCredentialStoreSaveRefusesARecordWithoutAKey: a blank file name and no
// id leave no row id; nothing reaches the repository.
func TestCredentialStoreSaveRefusesARecordWithoutAKey(t *testing.T) {
	fx := newStoreFixture(t)

	_, err := fx.store.Save(coreauth.WithAuthCreationIntent(t.Context()), &coreauth.Auth{
		FileName: "  ", Provider: "claude", Metadata: map[string]any{"access_token": "at-keyless"},
	})
	require.ErrorIs(t, err, errNoCredentialKey)
}

// TestCredentialStoreRemovesLeftoverScratchDirs: a login that crashed between
// writing its token file and removing it leaves plaintext in the scratch
// directory; the next NewCredentialStore removes it, and only it. A directory
// younger than scratchGrace is left alone: processes on one host share
// os.TempDir(), and it may be another process's login in progress.
func TestCredentialStoreRemovesLeftoverScratchDirs(t *testing.T) {
	scratch := t.TempDir()
	stale := filepath.Join(scratch, "llmproxy-credential-1234")
	fresh := filepath.Join(scratch, "llmproxy-credential-5678")
	unrelated := filepath.Join(scratch, "unrelated")

	for _, dir := range []string{stale, fresh, unrelated} {
		require.NoError(t, os.Mkdir(dir, 0o700))
	}

	require.NoError(t, os.WriteFile(filepath.Join(stale, "credential.json"), []byte(`{"access_token":"at-left"}`), 0o600))

	// Set the times after the write: writing into a directory updates its mtime.
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	require.NoError(t, os.Chtimes(stale, now.Add(-2*scratchGrace), now.Add(-2*scratchGrace)))
	require.NoError(t, os.Chtimes(fresh, now, now))

	clock := mocks.NewClock(t)
	clock.EXPECT().Now().Return(now).Once()

	_, err := NewCredentialStore(mocks.NewVendorCredentialRepo(t), testSealer(t, 'k'), clock, scratch)
	require.NoError(t, err)

	assert.NoDirExists(t, stale, "a crashed login's plaintext outlived the restart")
	assert.DirExists(t, fresh, "NewCredentialStore removed another process's login in progress")
	assert.DirExists(t, unrelated, "NewCredentialStore removed a directory that is not its own")
}
