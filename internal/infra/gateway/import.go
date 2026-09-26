package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	sdkauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// errCredentialFile is a *.json file in the auth directory that upstream's file
// store drops without a word (unreadable, empty, invalid JSON, invalid weight):
// the previous release never loaded it, and importing without it would lose
// the account for good once the marker is set, so the import stops instead.
//
// COMPAT(credentials-import): part of the one-shot import; remove next release (RELEASING.md).
var errCredentialFile = errors.New("gateway: a credential file cannot be imported; fix or remove it, then start again")

// importFile is one *.json file under the auth directory: the id upstream's
// file store gives the account it holds, and its path.
//
// COMPAT(credentials-import): part of the one-shot import; remove next release (RELEASING.md).
type importFile struct{ id, path string }

// ImportFileCredentials moves the vendor credentials the previous release kept
// as one JSON file per account under authDir into repo, sealed, once: with the
// marker set it returns at once and never reads the files again, so an account
// removed after the import stays removed. A missing authDir imports nothing and
// still sets the marker. The rows and the marker are written in one
// transaction (repo.Import); any failure returns an error with nothing written,
// and the next start retries. The files are left as they are. Boot calls it
// before the credential store is registered and before upstream loads anything.
//
// COMPAT(credentials-import): the one-shot import of the credential files; remove next release (RELEASING.md).
func ImportFileCredentials(ctx context.Context, authDir string, repo app.VendorCredentialRepo,
	sealer *credentials.Sealer, clock app.Clock, log app.InfoLogger,
) error {
	done, err := repo.ImportDone(ctx)
	if err != nil {
		return fmt.Errorf("gateway: credentials import: %w", err)
	}

	if done {
		return nil
	}

	records, err := fileCredentials(ctx, authDir, log)
	if err != nil {
		return err
	}

	now := clock.Now()
	rows := make([]app.VendorCredential, 0, len(records))

	for _, auth := range records {
		plaintext, errJSON := canonicalJSON(auth.Metadata)
		if errJSON != nil {
			return fmt.Errorf("gateway: credentials import: %s: %w", auth.ID, errJSON)
		}

		sealed, errSeal := sealer.Seal(auth.ID, plaintext)
		if errSeal != nil {
			return fmt.Errorf("gateway: credentials import: %s: %w", auth.ID, errSeal)
		}

		rows = append(rows, app.VendorCredential{
			ID:        auth.ID,
			Provider:  credentialProvider(auth.Metadata, auth.Provider),
			Sealed:    sealed,
			CreatedAt: auth.CreatedAt,
			UpdatedAt: now,
		})
	}

	imported, err := repo.Import(ctx, rows)
	if err != nil {
		return fmt.Errorf("gateway: credentials import: %w", err)
	}

	// False: another process set the marker since ImportDone, and its import
	// stands; this one wrote nothing.
	if imported {
		log.Info("gateway: imported the vendor credential files into the database; the files are left as they are",
			slog.Int("count", len(rows)), slog.String("dir", authDir))
	}

	return nil
}

// fileCredentials is what the previous release loads from authDir at boot:
// upstream's file store lists it, so the ids and the parsing are the same. The
// store drops a file it cannot load without a word (sdk/auth/filestore.go
// List), so every *.json file walked here must come back as the record with
// its id: a gemini file is a deliberate upstream skip, logged; any other
// unlisted file fails with errCredentialFile naming it. Records the token store
// would never hold are logged and skipped. A missing authDir holds nothing.
// Records not tied to a walked file (upstream's plugin parsers, which the
// gateway never registers) are not imported.
//
// COMPAT(credentials-import): part of the one-shot import; remove next release (RELEASING.md).
func fileCredentials(ctx context.Context, authDir string, log app.InfoLogger) ([]*coreauth.Auth, error) {
	// As FileTokenStore.SetBaseDir does, so both see the same directory.
	authDir = strings.TrimSpace(authDir)

	_, err := os.Stat(authDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("gateway: credentials import: %w", err)
	}

	files, err := credentialFiles(authDir)
	if err != nil {
		return nil, err
	}

	fileStore := sdkauth.NewFileTokenStore()
	fileStore.SetBaseDir(authDir)

	listed, err := fileStore.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("gateway: credentials import: list %s: %w", authDir, err)
	}

	byID := make(map[string]*coreauth.Auth, len(listed))
	for _, auth := range listed {
		byID[auth.ID] = auth
	}

	records := make([]*coreauth.Auth, 0, len(files))

	for _, file := range files {
		auth, ok := byID[file.id]

		switch {
		case !ok && geminiFile(file.path):
			log.Info("gateway: credentials import skips a gemini credential file, as the previous release did",
				slog.String("file", file.id))
		case !ok:
			return nil, fmt.Errorf("%w: %s", errCredentialFile, file.id)
		case !storeHolds(auth):
			log.Info("gateway: credentials import skips a credential the token store does not hold",
				slog.String("file", file.id))
		default:
			records = append(records, auth)
		}
	}

	return records, nil
}

// credentialFiles walks authDir for credential files exactly as
// FileTokenStore.List does: every non-directory entry whose name ends in .json,
// in any case; the login hand-off (.oauth) and cooldown (.cds) files are not.
// A walk error fails the import, as it fails that List.
//
// COMPAT(credentials-import): part of the one-shot import; remove next release (RELEASING.md).
func credentialFiles(authDir string) ([]importFile, error) {
	var files []importFile

	err := filepath.WalkDir(authDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			return nil
		}

		files = append(files, importFile{id: fileStoreID(authDir, path), path: path})

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("gateway: credentials import: walk %s: %w", authDir, err)
	}

	return files, nil
}

// fileStoreID is the id upstream's file store gives the account in the file
// at path under authDir: the path relative to authDir, lower-cased on Windows
// (FileTokenStore.idFor, sdk/auth/filestore.go:403-415, unexported).
//
// COMPAT(credentials-import): part of the one-shot import; remove next release (RELEASING.md).
func fileStoreID(authDir, path string) string {
	id := path

	if rel, err := filepath.Rel(authDir, path); err == nil && rel != "" {
		id = rel
	}

	if runtime.GOOS == "windows" {
		id = strings.ToLower(id)
	}

	return id
}

// geminiFile reports whether the file at path is JSON whose type is gemini:
// the one kind of credential upstream's file store skips on purpose
// (sdk/auth/filestore.go:246-250).
//
// COMPAT(credentials-import): part of the one-shot import; remove next release (RELEASING.md).
func geminiFile(path string) bool {
	data, err := os.ReadFile(path) //nolint:gosec // G304: a file the walk of the operator's auth directory just found
	if err != nil {
		return false
	}

	var fields map[string]any

	if json.Unmarshal(data, &fields) != nil {
		return false
	}

	provider, _ := fields[metadataType].(string)

	return strings.EqualFold(strings.TrimSpace(provider), "gemini")
}
