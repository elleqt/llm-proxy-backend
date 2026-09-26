package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/credentials"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// scratchPattern names the temporary directory a fresh login's token storage
// is serialized into (an os.MkdirTemp pattern). NewCredentialStore removes
// every directory of this name under its scratch dir that is at least
// scratchGrace old: one left there belongs to a process that died between the
// write and the removal.
const scratchPattern = "llmproxy-credential-*"

// scratchGrace is how old a scratch directory must be before NewCredentialStore
// treats it as a crashed process's leftover. A serialization takes
// milliseconds; a younger directory may be another process's login in
// progress, since processes on one host share os.TempDir().
const scratchGrace = time.Minute

// credentialFile is the file SaveTokenToFile writes inside a scratch directory.
const credentialFile = "credential.json" //nolint:gosec // G101 false positive: a file name, not a credential.

// Credential metadata keys the store reads, named as upstream's FileTokenStore
// reads them (sdk/auth/filestore.go).
const (
	metadataType     = "type"
	metadataDisabled = "disabled"
	metadataEmail    = "email"
)

var (
	// errCredentialStoreDeps reports NewCredentialStore called without one of
	// its dependencies.
	errCredentialStoreDeps = errors.New("gateway: the credential store needs a repository, a sealer and a clock")
	// errNoCredentialKey reports a record Save cannot key: a blank file name
	// and no id. AddAccount assigns an id before saving, so only a caller
	// bypassing it gets this.
	errNoCredentialKey = errors.New("gateway: the credential has neither a file name nor an id")
	// errTokenlessCredential reports a fresh login whose serialized credential
	// has neither an access nor a refresh token: stored, it could never
	// authenticate.
	errTokenlessCredential = errors.New("gateway: the saved credential carries no access or refresh token")
)

// tokenFileWriter is upstream's token storage, coreauth.Auth.Storage, whose
// interface type lives in an upstream internal package: the vendor's own
// serialization of a fresh login's credential.
type tokenFileWriter interface {
	SaveTokenToFile(path string) error
}

// metadataSetter is the optional interface through which FileTokenStore.Save
// hands a login record's metadata to its storage before the write
// (sdk/auth/filestore.go:108-121, v7.3.18).
type metadataSetter interface {
	SetMetadata(metadata map[string]any)
}

var _ coreauth.Store = (*CredentialStore)(nil)

// CredentialStore is upstream's token store over Postgres: each vendor
// account is one app.VendorCredential row whose Sealed column is the
// credential JSON FileTokenStore would have written to a file, sealed under
// the account's id. The plaintext never reaches the repository. It
// implements neither SetBaseDir nor CooldownStateStoreProvider: it has no
// directory, and cooldown state stays in memory.
type CredentialStore struct {
	repo       app.VendorCredentialRepo
	sealer     *credentials.Sealer
	clock      app.Clock
	scratchDir string

	// mu serializes Save and Delete, as FileTokenStore's mutex does, and
	// guards digests.
	mu sync.Mutex
	// digests holds, per row id, the SHA-256 of the plaintext last written or
	// listed. An entry exists only while the row is known to hold exactly
	// that plaintext; any write whose outcome is unknown drops it.
	digests map[string][32]byte
}

// NewCredentialStore returns the store over repo, sealing with sealer and
// stamping rows with clock. A fresh login's token storage is serialized
// under scratchDir; "" means os.TempDir(), which boot passes, so the
// plaintext never touches the grants volume. Directories a crashed process
// left there are removed first, so no plaintext outlives a restart; one
// younger than scratchGrace is kept, since processes on one host share
// os.TempDir() and it may be another process's login in progress.
func NewCredentialStore(repo app.VendorCredentialRepo, sealer *credentials.Sealer, clock app.Clock,
	scratchDir string,
) (*CredentialStore, error) {
	if repo == nil || sealer == nil || clock == nil {
		return nil, errCredentialStoreDeps
	}

	if scratchDir == "" {
		scratchDir = os.TempDir()
	}

	if err := removeStaleScratchDirs(scratchDir, clock); err != nil {
		return nil, err
	}

	return &CredentialStore{
		repo:       repo,
		sealer:     sealer,
		clock:      clock,
		scratchDir: scratchDir,
		digests:    make(map[string][32]byte),
	}, nil
}

// removeStaleScratchDirs removes the scratchPattern directories under dir that
// are at least scratchGrace old. The clock is read only when there is one to
// judge.
func removeStaleScratchDirs(dir string, clock app.Clock) error {
	leftovers, err := filepath.Glob(filepath.Join(dir, scratchPattern))
	if err != nil {
		return fmt.Errorf("gateway: find leftover credential scratch dirs: %w", err)
	}

	if len(leftovers) == 0 {
		return nil
	}

	now := clock.Now()

	for _, leftover := range leftovers {
		info, err := os.Lstat(leftover)
		if errors.Is(err, os.ErrNotExist) {
			continue // its owner removed it meanwhile
		}

		if err != nil {
			return fmt.Errorf("gateway: inspect leftover credential scratch dir %q: %w", leftover, err)
		}

		if now.Sub(info.ModTime()) < scratchGrace {
			continue
		}

		if err := os.RemoveAll(leftover); err != nil {
			return fmt.Errorf("gateway: remove leftover credential scratch dir %q: %w", leftover, err)
		}
	}

	return nil
}

// Save writes auth's credential under its key (credentialKey) and returns
// the key. The credential JSON is what FileTokenStore.Save would have
// written: a fresh login's Storage serialized by the vendor's own
// SaveTokenToFile, otherwise the metadata, both with the disabled flag.
//
// Only a save with creation intent (AddAccount) inserts a row. Any other
// save (a refresh, a cooldown transition) only updates one: when the row is
// gone the account was removed, and Save returns "", nil instead of
// re-creating it. A runtime save of content equal to the row's is skipped:
// upstream saves on every cooldown transition, and a fresh nonce would make
// each of them a write.
func (s *CredentialStore) Save(ctx context.Context, auth *coreauth.Auth) (string, error) {
	if auth == nil {
		return "", errNilAccount
	}

	key := credentialKey(auth)
	if key == "" {
		return "", errNoCredentialKey
	}

	coreauth.NormalizeCredentialMetadata(auth.Metadata)

	if err := coreauth.ValidateAuthWeight(auth); err != nil {
		return "", fmt.Errorf("gateway: account %q: %w", key, err)
	}

	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}

	auth.Metadata[metadataDisabled] = auth.Disabled

	s.mu.Lock()
	defer s.mu.Unlock()

	fields, err := s.credentialFields(auth)
	if err != nil {
		return "", err
	}

	plaintext, err := canonicalJSON(fields)
	if err != nil {
		return "", err
	}

	digest := sha256.Sum256(plaintext)
	creating := coreauth.HasAuthCreationIntent(ctx)

	if last, seen := s.digests[key]; seen && last == digest && !creating {
		stampCredential(auth, key)

		return key, nil
	}

	// Until the write below succeeds, the row's content is unknown.
	delete(s.digests, key)

	sealed, err := s.sealer.Seal(key, plaintext)
	if err != nil {
		return "", fmt.Errorf("gateway: seal account %q: %w", key, err)
	}

	now := s.clock.Now()
	row := app.VendorCredential{
		ID:        key,
		Provider:  credentialProvider(fields, auth.Provider),
		Sealed:    sealed,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if creating {
		err = s.repo.Upsert(ctx, row)
	} else {
		err = s.repo.Update(ctx, row)
	}

	switch {
	case !creating && errors.Is(err, app.ErrNotFound):
		// The account was removed; a runtime save never brings it back.
		return "", nil
	case err != nil:
		return "", fmt.Errorf("gateway: store account %q: %w", key, err)
	}

	s.digests[key] = digest
	stampCredential(auth, key)

	return key, nil
}

// Delete removes the account's row; a missing row is not an error. The
// digest goes first: whatever the repository did, the row's content is no
// longer known.
func (s *CredentialStore) Delete(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.digests, id)

	if err := s.repo.Delete(ctx, id); err != nil {
		return fmt.Errorf("gateway: delete account %q: %w", id, err)
	}

	return nil
}

// List reads every stored account, as FileTokenStore.List reads the auth
// directory. A row that does not open (sealed under another key, moved to
// another id, tampered with) or does not parse fails List naming the
// account: boot lists the store once before upstream loads it (upstream only
// warns), so it stops rather than drop an account silently. The digests
// become exactly what was read.
func (s *CredentialStore) List(ctx context.Context) ([]*coreauth.Auth, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("gateway: list vendor credentials: %w", err)
	}

	auths := make([]*coreauth.Auth, 0, len(rows))
	digests := make(map[string][32]byte, len(rows))

	for _, row := range rows {
		plaintext, err := s.sealer.Open(row.ID, row.Sealed)
		if err != nil {
			return nil, fmt.Errorf("gateway: account %q cannot be opened with LLMPROXY_CREDENTIALS_KEY "+
				"(sealed under another key, or tampered with): %w", row.ID, err)
		}

		auth, err := authFromRow(row, plaintext)
		if err != nil {
			return nil, err
		}

		auths = append(auths, auth)
		digests[row.ID] = sha256.Sum256(plaintext)
	}

	s.digests = digests

	return auths, nil
}

// credentialFields returns the credential JSON Save writes, as fields: the
// metadata of a stored account or, for a fresh login's record, whatever the
// vendor's SaveTokenToFile writes after the metadata is handed to it, as
// FileTokenStore.Save does. A login record without a token is refused.
func (s *CredentialStore) credentialFields(auth *coreauth.Auth) (map[string]any, error) {
	if auth.Storage == nil {
		return auth.Metadata, nil
	}

	if setter, ok := auth.Storage.(metadataSetter); ok {
		setter.SetMetadata(auth.Metadata)
	}

	fields, err := s.serialize(auth.Storage)
	if err != nil {
		return nil, err
	}

	if !carriesToken(fields) {
		return nil, errTokenlessCredential
	}

	return fields, nil
}

// serialize has storage write its credential file into a fresh directory
// under the scratch dir and reads it back. The directory is removed before
// serialize returns, whether or not the write succeeded, so no plaintext
// outlives the call; one a crash leaves behind is removed by the next
// NewCredentialStore.
func (s *CredentialStore) serialize(storage tokenFileWriter) (map[string]any, error) {
	dir, err := os.MkdirTemp(s.scratchDir, scratchPattern)
	if err != nil {
		return nil, fmt.Errorf("gateway: create a credential scratch dir: %w", err)
	}

	fields, errRead := readTokenFile(storage, filepath.Join(dir, credentialFile))
	errRemove := os.RemoveAll(dir)

	switch {
	case errRead != nil:
		return nil, errRead
	case errRemove != nil:
		return nil, fmt.Errorf("gateway: remove the credential scratch dir %q: %w", dir, errRemove)
	}

	return fields, nil
}

// readTokenFile has storage write its credential file at file and reads the
// file back as fields.
func readTokenFile(storage tokenFileWriter, file string) (map[string]any, error) {
	if err := storage.SaveTokenToFile(file); err != nil {
		return nil, fmt.Errorf("gateway: serialize the login credential: %w", err)
	}

	data, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, fmt.Errorf("gateway: read the serialized login credential: %w", err)
	}

	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, fmt.Errorf("gateway: the serialized login credential is not JSON: %w", err)
	}

	return fields, nil
}

// carriesToken reports whether fields hold a non-blank access or refresh
// token. The vendors' storages write both keys even when they are empty, so
// presence alone proves nothing.
func carriesToken(fields map[string]any) bool {
	for _, name := range [...]string{"access_token", "refresh_token"} {
		if token, isString := fields[name].(string); isString && strings.TrimSpace(token) != "" {
			return true
		}
	}

	return false
}

// canonicalJSON is v as the JSON object it marshals to, re-marshaled from a
// map[string]any: keys sorted, numbers and nesting as any JSON reader sees
// them. Equal credentials give equal bytes, so their digests compare; the
// file import seals the same form.
func canonicalJSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("gateway: marshal the credential: %w", err)
	}

	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("gateway: the credential is not a JSON object: %w", err)
	}

	canonical, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("gateway: marshal the credential: %w", err)
	}

	return canonical, nil
}

// credentialKey is the account's row id: its file name, which upstream's
// file store keyed it by (a path relative to AUTH_DIR, kept as
// usage_events.vendor_account_id), else its id. The path attribute is
// ignored: nothing here has a file.
func credentialKey(auth *coreauth.Auth) string {
	if name := strings.TrimSpace(auth.FileName); name != "" {
		return name
	}

	return auth.ID
}

// credentialProvider is the provider a credential's fields name in "type",
// else fallback: the row's provider column, and List's provider with
// fallback "unknown" as FileTokenStore reads a file.
func credentialProvider(fields map[string]any, fallback string) string {
	if kind, isString := fields[metadataType].(string); isString {
		if kind = strings.TrimSpace(kind); kind != "" {
			return kind
		}
	}

	return fallback
}

// stampCredential marks auth as held under key in Postgres, as
// FileTokenStore.Save marks a record with its file: the file name when
// unset, and the source attributes.
func stampCredential(auth *coreauth.Auth, key string) {
	if strings.TrimSpace(auth.FileName) == "" {
		auth.FileName = key
	}

	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string, 2)
	}

	auth.Attributes[coreauth.AttributeSource] = key
	auth.Attributes[coreauth.AttributeSourceBackend] = coreauth.AuthSourcePostgres
}

// authFromRow rebuilds a stored account as FileTokenStore.readAuthFiles
// rebuilds one from its file (non-plugin branch, sdk/auth/filestore.go:312-361,
// v7.3.18): the row's id where the file's relative path was, Postgres as the
// source, the row's timestamps where the file's mtime was. No path
// attribute: upstream reads it only as a cache key in executors this
// gateway does not route to and in the file watcher, which is hollow here.
func authFromRow(row app.VendorCredential, plaintext []byte) (*coreauth.Auth, error) {
	metadata := make(map[string]any)
	if err := json.Unmarshal(plaintext, &metadata); err != nil {
		return nil, fmt.Errorf("gateway: account %q: the stored credential is not JSON: %w", row.ID, err)
	}

	coreauth.NormalizeCredentialMetadata(metadata)

	if err := coreauth.ValidateAuthWeight(&coreauth.Auth{Metadata: metadata}); err != nil {
		return nil, fmt.Errorf("gateway: account %q: %w", row.ID, err)
	}

	disabled, _ := metadata[metadataDisabled].(bool)
	status := coreauth.StatusActive

	if disabled {
		status = coreauth.StatusDisabled
	}

	proxyURL, _ := metadata["proxy_url"].(string)

	auth := &coreauth.Auth{
		ID:       row.ID,
		Provider: credentialProvider(metadata, "unknown"),
		FileName: row.ID,
		Label:    credentialLabel(metadata),
		Prefix:   credentialPrefix(metadata),
		ProxyURL: strings.TrimSpace(proxyURL),
		Status:   status,
		Disabled: disabled,
		Attributes: map[string]string{
			coreauth.AttributeSource:        row.ID,
			coreauth.AttributeSourceBackend: coreauth.AuthSourcePostgres,
		},
		Metadata:  metadata,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}

	if email, isString := metadata[metadataEmail].(string); isString && email != "" {
		auth.Attributes[metadataEmail] = email
	}

	coreauth.ApplyCustomHeadersFromMetadata(auth)

	return auth, nil
}

// credentialLabel is FileTokenStore.labelFor: the label, else the email,
// else the project id.
func credentialLabel(metadata map[string]any) string {
	for _, key := range [...]string{"label", metadataEmail, "project_id"} {
		if label, isString := metadata[key].(string); isString && label != "" {
			return label
		}
	}

	return ""
}

// credentialPrefix is the model prefix readAuthFiles accepts: trimmed of
// spaces and slashes, and dropped when a slash remains inside it.
func credentialPrefix(metadata map[string]any) string {
	raw, _ := metadata["prefix"].(string)
	prefix := strings.Trim(strings.TrimSpace(raw), "/")

	if strings.Contains(prefix, "/") {
		return ""
	}

	return prefix
}
