package gateway

// COMPAT(credentials-import): the tests of the one-shot import of the credential files; remove next release (RELEASING.md).

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/app/mocks"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/pgtest"
	"github.com/elleqt/llm-proxy-backend/internal/infra/postgres/vendorcreds"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// importedClaudeFile is a Claude credential file as the previous release wrote
// it: upstream's ClaudeTokenStorage fields plus the disabled flag its file
// store adds on every save.
const importedClaudeFile = `{"type":"claude","email":"user@example.com","id_token":"",` +
	`"access_token":"fake-claude-access-token","refresh_token":"fake-claude-refresh-token",` +
	`"last_refresh":"2026-09-01T00:00:00Z","expired":"2026-09-01T08:00:00Z","disabled":false}`

// importedClaudeID is the id upstream's file store gives importedClaudeFile
// written straight under the auth directory: its file name.
const importedClaudeID = "claude-user@example.com.json"

// importNow is what the clock says during an import.
var importNow = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

// writeAuthFile writes content as dir/name, creating the directories between.
func writeAuthFile(t *testing.T, dir, name, content string) {
	t.Helper()

	path := filepath.Join(dir, name)
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o700))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

// TestImportReadsNothingOnceDone: with the marker set the files are never read
// again. A file the import would refuse is there to prove it: reading it would
// fail the call, and the strict mocks fail on any Import, clock or log call.
func TestImportReadsNothingOnceDone(t *testing.T) {
	dir := t.TempDir()
	writeAuthFile(t, dir, importedClaudeID, importedClaudeFile)
	writeAuthFile(t, dir, "claude-broken@example.com.json", `{"type":`)

	repo := mocks.NewVendorCredentialRepo(t)
	repo.EXPECT().ImportDone(mock.Anything).Return(true, nil).Once()

	err := ImportFileCredentials(t.Context(), dir, repo, testSealer(t, 'i'), mocks.NewClock(t), mocks.NewInfoLogger(t))
	require.NoError(t, err)
}

// TestImportOfAMissingDirectorySetsTheMarker: a fresh install has no auth
// directory yet; the import writes no row but still sets the marker, so a
// directory that appears later is never imported.
func TestImportOfAMissingDirectorySetsTheMarker(t *testing.T) {
	repo := mocks.NewVendorCredentialRepo(t)
	repo.EXPECT().ImportDone(mock.Anything).Return(false, nil).Once()
	repo.EXPECT().Import(mock.Anything, mock.MatchedBy(func(rows []app.VendorCredential) bool { return len(rows) == 0 })).
		Return(true, nil).Once()

	clock := mocks.NewClock(t)
	clock.EXPECT().Now().Return(importNow).Once()

	var logged string

	logs := mocks.NewInfoLogger(t)
	logs.EXPECT().Info(mock.Anything, mock.Anything).
		Run(func(msg string, attrs ...slog.Attr) { logged = fmt.Sprint(msg, attrs) }).Once()

	err := ImportFileCredentials(t.Context(), filepath.Join(t.TempDir(), "missing"), repo, testSealer(t, 'i'), clock, logs)
	require.NoError(t, err)
	require.Contains(t, logged, "count=0")
}

// TestImportSealsEachFileUnderTheFileStoresID: every account the previous
// release loads becomes one row under the id upstream's file store gave it
// (usage_events.vendor_account_id refers to it), nested directories and an
// upper-case suffix included; the row opens to exactly the file's content, and
// keeps the file's time as its creation. The login hand-off and cooldown files
// are no credentials.
func TestImportSealsEachFileUnderTheFileStoresID(t *testing.T) {
	dir := t.TempDir()
	writeAuthFile(t, dir, importedClaudeID, importedClaudeFile)
	writeAuthFile(t, dir, filepath.Join("team", "claude-other@example.com.JSON"),
		strings.ReplaceAll(importedClaudeFile, "user@example.com", "other@example.com"))
	writeAuthFile(t, dir, ".oauth-claude-state.oauth", `{"code":"c","state":"s"}`)
	writeAuthFile(t, dir, "claude-user@example.com.cds", `{}`)

	fileStore := sdkauth.NewFileTokenStore()
	fileStore.SetBaseDir(dir)

	listed, err := fileStore.List(t.Context())
	require.NoError(t, err)
	require.Len(t, listed, 2, "accounts upstream's file store loads")

	var rows []app.VendorCredential

	repo := mocks.NewVendorCredentialRepo(t)
	repo.EXPECT().ImportDone(mock.Anything).Return(false, nil).Once()
	repo.EXPECT().Import(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, imported []app.VendorCredential) (bool, error) {
			rows = imported

			return true, nil
		}).Once()

	clock := mocks.NewClock(t)
	clock.EXPECT().Now().Return(importNow).Once()

	logs := mocks.NewInfoLogger(t)
	logs.EXPECT().Info(mock.Anything, mock.Anything).Once()

	sealer := testSealer(t, 'i')
	require.NoError(t, ImportFileCredentials(t.Context(), dir, repo, sealer, clock, logs))
	require.Len(t, rows, len(listed), "imported rows")

	byID := make(map[string]app.VendorCredential, len(rows))
	for _, row := range rows {
		byID[row.ID] = row
	}

	for _, auth := range listed {
		row, ok := byID[auth.ID]
		require.True(t, ok, "no row under the file store's id %q; rows %v", auth.ID, byID)

		plaintext, err := sealer.Open(auth.ID, row.Sealed)
		require.NoError(t, err, "open %s", auth.ID)

		content, err := os.ReadFile(filepath.Join(dir, auth.ID))
		require.NoError(t, err)
		require.JSONEq(t, string(content), string(plaintext), "sealed credential of %s", auth.ID)
		require.Equal(t, "claude", row.Provider, "provider of %s", auth.ID)
		require.WithinDuration(t, auth.CreatedAt, row.CreatedAt, 0, "created_at of %s is the file's time", auth.ID)
		require.Equal(t, importNow, row.UpdatedAt, "updated_at of %s", auth.ID)
	}
}

// TestARemovedImportedAccountStaysGone: import, remove the account as
// RemoveAccount does (the store deletes its row), start again with the file
// still in the directory: the marker keeps the import from running twice, so
// the account stays gone. Against the real repository, so the marker is the
// settings row the SQL writes.
func TestARemovedImportedAccountStaysGone(t *testing.T) {
	dir := t.TempDir()
	writeAuthFile(t, dir, importedClaudeID, importedClaudeFile)

	repo, sealer := vendorcreds.New(pgtest.NewTestPool(t)), testSealer(t, 'i')

	// One import only: the strict mocks fail a second Now or Info.
	clock := mocks.NewClock(t)
	clock.EXPECT().Now().Return(importNow).Once()

	logs := mocks.NewInfoLogger(t)
	logs.EXPECT().Info(mock.Anything, mock.Anything).Once()

	store, err := NewCredentialStore(repo, sealer, clock, t.TempDir())
	require.NoError(t, err)

	require.NoError(t, ImportFileCredentials(t.Context(), dir, repo, sealer, clock, logs), "first boot")

	accounts, err := store.List(t.Context())
	require.NoError(t, err)
	require.Len(t, accounts, 1, "accounts after the import")
	require.Equal(t, importedClaudeID, accounts[0].ID)

	require.NoError(t, store.Delete(t.Context(), importedClaudeID), "remove the account")
	require.NoError(t, ImportFileCredentials(t.Context(), dir, repo, sealer, clock, logs), "second boot")

	accounts, err = store.List(t.Context())
	require.NoError(t, err)
	require.Empty(t, accounts, "the removed account came back from its file")
}

// TestImportRefusesAFileTheFileStoreDrops: upstream's file store silently
// skips a file it cannot load, which is exactly a truncated write. Importing
// without it would lose the account for good, so the import fails naming the
// file (and nothing of its content), and writes nothing: no rows, no marker.
func TestImportRefusesAFileTheFileStoreDrops(t *testing.T) {
	for _, tc := range []struct{ name, content string }{
		{"truncated", importedClaudeFile[:40]},
		{"empty", ""},
		{"invalid weight", `{"type":"claude","email":"broken@example.com","access_token":"fake-claude-access-token","weight":1.5}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeAuthFile(t, dir, importedClaudeID, importedClaudeFile)
			writeAuthFile(t, dir, "claude-broken@example.com.json", tc.content)

			// No Import expectation: the strict mock fails the test if the
			// import writes anything.
			repo := mocks.NewVendorCredentialRepo(t)
			repo.EXPECT().ImportDone(mock.Anything).Return(false, nil).Once()

			err := ImportFileCredentials(t.Context(), dir, repo, testSealer(t, 'i'), mocks.NewClock(t), mocks.NewInfoLogger(t))
			require.ErrorIs(t, err, errCredentialFile)
			require.Contains(t, err.Error(), "claude-broken@example.com.json", "the error names the file")
			require.NotContains(t, err.Error(), "fake-claude", "the error quotes the credential")
		})
	}
}

// TestImportSkipsGeminiFiles: upstream's file store skips gemini credentials on
// purpose, so the previous release never loaded them either; the import logs
// the file and goes on with the rest.
func TestImportSkipsGeminiFiles(t *testing.T) {
	dir := t.TempDir()
	writeAuthFile(t, dir, importedClaudeID, importedClaudeFile)
	writeAuthFile(t, dir, "gemini-user@example.com.json",
		`{"type":"gemini","email":"user@example.com","token":{"access_token":"fake-gemini-access-token"}}`)

	var rows []app.VendorCredential

	repo := mocks.NewVendorCredentialRepo(t)
	repo.EXPECT().ImportDone(mock.Anything).Return(false, nil).Once()
	repo.EXPECT().Import(mock.Anything, mock.Anything).
		RunAndReturn(func(_ context.Context, imported []app.VendorCredential) (bool, error) {
			rows = imported

			return true, nil
		}).Once()

	clock := mocks.NewClock(t)
	clock.EXPECT().Now().Return(importNow).Once()

	var logged []string

	logs := mocks.NewInfoLogger(t)
	logs.EXPECT().Info(mock.Anything, mock.Anything).
		Run(func(msg string, attrs ...slog.Attr) { logged = append(logged, fmt.Sprint(msg, attrs)) }).Times(2)

	require.NoError(t, ImportFileCredentials(t.Context(), dir, repo, testSealer(t, 'i'), clock, logs))
	require.Len(t, rows, 1, "imported rows")
	require.Equal(t, importedClaudeID, rows[0].ID)
	require.Contains(t, logged[0], "file=gemini-user@example.com.json", "the skip is logged by file name")
	require.Contains(t, logged[1], "count=1")
}
