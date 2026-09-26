// Package settings edits the upstream configuration the gateway runs with, and
// loads it at boot (LoadBootConfig).
package settings

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/elleqt/llm-proxy-backend/internal/app"
	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
	"github.com/pmezard/go-difflib/difflib"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	"gopkg.in/yaml.v3"
)

// ownedKeys are the top-level keys of the upstream configuration the gateway owns.
// A document setting one is refused rather than applied or silently ignored, and
// the running value is carried over from the configuration that owns it:
//
//   - host, port, tls: the proxied listener, fixed at boot behind the reverse proxy.
//   - trusted-proxies (upstream v7.3.18): whose forwarded headers that listener
//     believes for a client's address. Upstream applies it only when it builds
//     its server (internal/api/server.go NewServer), never on a push, so an edit
//     would be stored without running; and it uses the address only in its own
//     logs — the gateway's rate limits and audit key on the web listener's
//     X-Real-IP. It stays at upstream's default, an empty list, which believes
//     no forwarded header.
//   - pprof, discovery: upstream applies both on every reload, starting an
//     unauthenticated pprof server or mDNS advertising — listeners outside the
//     deployment's three.
//   - debug: upstream's debug logging, switched on for the whole process by a
//     reload (internal/api/server_reload.go util.SetLogLevel), logs request
//     details; the composition root keeps it off.
//   - logging-to-file, logs-max-total-size-mb: a change to either makes upstream's
//     reload call logging.ConfigureLogOutput, which re-points the global logrus
//     at stdout or at rotating files behind the process log's slog bridge. They
//     stay at their zero values, and every upstream record reaches the process
//     log through the bridge.
//   - auth-dir: the credential store, which upstream never re-points on reload.
//   - remote-management, api-keys, plugins, ws-auth: what the gateway refuses or
//     forces (gateway.admit) — management stays off, access is by user token only,
//     no plugin can register a provider, websocket authentication stays on.
//   - home: runtime-only in upstream (no YAML tag); named so the key is refused
//     rather than dropped.
//   - openai-compatibility and every "*-api-key" family: config-derived
//     credentials PushConfig cannot add, so they are boot-only.
var ownedKeys = []string{
	"host", "port", "tls", "trusted-proxies", "pprof", "discovery", "debug", "auth-dir",
	"logging-to-file", "logs-max-total-size-mb",
	"remote-management", "api-keys", "plugins", "ws-auth", "openai-compatibility",
}

// isOwnedKey reports whether a top-level key is gateway-owned. Any key ending in
// "-api-key" is, so a credential family a future upstream adds is boot-only too.
func isOwnedKey(key string) bool {
	return key == "home" || strings.HasSuffix(key, "-api-key") || slices.Contains(ownedKeys, key)
}

// inertKeys are top-level keys of the upstream configuration that have no effect
// in the gateway: gateway.admit forces save-cooldown-status and request-log off
// (cooldown state stays in memory, and no request logger is installed), and
// error-logs-max-files bounds error log files nothing writes. Update refuses a
// document that adds one or changes its value (refuseInertKeys).
//
// COMPAT(credentials-import): a document saved by an earlier release may still set
// one; LoadBootConfig warns and Update keeps it while unchanged. Remove next release
// (RELEASING.md): the keys join ownedKeys, refused in any document, and this list,
// inertKeyWarning, inertValues and refuseInertKeys go away.
var inertKeys = []string{"save-cooldown-status", "request-log", "error-logs-max-files"}

// inertKeyWarning is logged at boot, with the key, for each inert key the stored
// document sets.
const inertKeyWarning = "settings: key has no effect and is ignored; remove it from the settings document"

// inertValues returns the value of every inert key doc sets at the top level,
// decoded, by key; nil when it sets none.
func inertValues(doc string) (map[string]any, error) {
	root, err := documentRoot(doc)
	if err != nil {
		return nil, err
	}

	var values map[string]any

	for keyAt := 0; keyAt+1 < len(root.Content); keyAt += 2 {
		key := root.Content[keyAt].Value
		if !slices.Contains(inertKeys, key) {
			continue
		}

		var value any
		if err := root.Content[keyAt+1].Decode(&value); err != nil {
			return nil, app.InvalidSetting(key, err.Error())
		}

		if values == nil {
			values = make(map[string]any, len(inertKeys))
		}

		values[key] = value
	}

	return values, nil
}

// ownedField is a gateway-owned field of sdkconfig.Config: its top-level key and
// its index path in the struct.
type ownedField struct {
	key   string
	index []int
}

// ownedFields lists every Config field whose key isOwnedKey, found by reflection
// over the YAML tags (the inline SDKConfig included), plus Home, which has none.
var ownedFields = func() []ownedField {
	var (
		out  []ownedField
		walk func(t reflect.Type, prefix []int)
	)

	walk = func(t reflect.Type, prefix []int) {
		for i := range t.NumField() {
			field := t.Field(i)
			index := append(slices.Clone(prefix), i)

			name, opts, _ := strings.Cut(field.Tag.Get("yaml"), ",")
			switch {
			case opts == "inline":
				walk(field.Type, index)
			case field.Name == "Home":
				out = append(out, ownedField{"home", index})
			case name != "-" && isOwnedKey(name):
				out = append(out, ownedField{name, index})
			}
		}
	}
	walk(reflect.TypeFor[sdkconfig.Config](), nil)

	return out
}()

func (f ownedField) of(cfg *sdkconfig.Config) reflect.Value {
	return reflect.ValueOf(cfg).Elem().FieldByIndex(f.index)
}

// overlayOwned sets every gateway-owned field of dst to a deep copy of owner's.
func overlayOwned(dst, owner *sdkconfig.Config) {
	src := owner.CloneForRuntime()
	for _, f := range ownedFields {
		f.of(dst).Set(f.of(src))
	}
}

// emptyDocumentConfig is what upstream parses an empty document into: the value
// every owned field of an editable document must still have after parsing.
var emptyDocumentConfig = sync.OnceValues(func() (*sdkconfig.Config, error) {
	return sdkconfig.ParseConfigBytes([]byte("{}"))
})

// checkOwnedUnset refuses a parsed document that set a gateway-owned field by any
// route the literal key check does not see (an alias used as a key, say), naming
// the first such field.
func checkOwnedUnset(cfg *sdkconfig.Config) error {
	empty, err := emptyDocumentConfig()
	if err != nil {
		return fmt.Errorf("app: parse the empty settings document: %w", err)
	}

	for _, f := range ownedFields {
		if !reflect.DeepEqual(f.of(cfg).Interface(), f.of(empty).Interface()) {
			return app.ForbiddenSetting(f.key)
		}
	}

	return nil
}

// Fields are the typed form fields of the editable document.
type Fields struct {
	ProxyURL         string
	RequestRetry     int
	MaxRetryInterval int // seconds
}

// View is the stored editable document and its typed fields.
type View struct {
	YAML   string
	Fields Fields
}

// Patch patches individual typed fields; a nil field is left as it is.
type Patch struct {
	ProxyURL         *string
	RequestRetry     *int
	MaxRetryInterval *int
}

// Update replaces the whole document (YAML) or patches typed fields
// (Fields); exactly one of the two is set.
type Update struct {
	YAML   *string
	Fields *Patch
	DryRun bool
}

// UpdateResult is what an update did. Diff is the unified diff of the
// running configuration's editable part against the proposed one, with proxy
// credentials redacted; Settings is the proposed document, applied unless Applied
// is false.
type UpdateResult struct {
	Applied  bool
	Diff     string
	Settings View
}

// Service edits the upstream configuration the gateway runs with.
//
// The stored document is the editable part only. The running configuration is that
// document parsed by upstream, with every gateway-owned field (ownedFields) taken
// from the configuration the gateway already runs — at boot, from the
// composition root's defaults (LoadBootConfig).
type Service struct {
	repo    app.SettingsRepo
	gateway app.ConfigPusher
	audit   app.AuditSink
	clock   app.Clock

	// mu serialises updates, so the stored document always matches the last
	// configuration pushed: two interleaved updates could otherwise push in one
	// order and persist in the other.
	mu sync.Mutex
}

func New(repo app.SettingsRepo, gateway app.ConfigPusher, audit app.AuditSink, clock app.Clock) *Service {
	return &Service{repo: repo, gateway: gateway, audit: audit, clock: clock}
}

// Get returns the stored document and its typed fields. Nothing is redacted: the
// document is the administrator's to edit, and a redacted copy sent back whole would
// overwrite the proxy credentials.
func (s *Service) Get(ctx context.Context, actor identity.User) (View, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return View{}, err
	}

	doc, err := storedDocument(ctx, s.repo)
	if err != nil {
		return View{}, err
	}

	cfg, err := parseDocument(doc)
	if err != nil {
		return View{}, fmt.Errorf("app: stored settings: %w", err)
	}

	return view(doc, cfg), nil
}

// Update validates the proposed document and, unless DryRun, pushes it to the
// gateway and then persists it: a configuration the gateway refused is never
// stored, and a stored one is always what runs. If persisting fails, the previous
// configuration is pushed back. The audit record carries the redacted diff.
func (s *Service) Update(ctx context.Context, actor identity.User, req Update) (UpdateResult, error) {
	if err := app.RequireAdmin(actor); err != nil {
		return UpdateResult{}, err
	}

	if err := req.validate(); err != nil {
		return UpdateResult{}, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	doc, err := s.proposedDocument(ctx, req)
	if err != nil {
		return UpdateResult{}, err
	}

	cfg, err := parseDocument(doc)
	if err != nil {
		return UpdateResult{}, err
	}

	// A field patch keeps every key but the three it sets, none of them inert, so
	// only a whole document can add or change an inert key.
	if req.YAML != nil {
		if err := s.refuseInertKeys(ctx, doc); err != nil {
			return UpdateResult{}, err
		}
	}

	running := s.gateway.CurrentConfig()
	if running == nil {
		return UpdateResult{}, app.ErrNoRunningConfig
	}

	settings := view(doc, cfg)
	next := cfg.CloneForRuntime()
	overlayOwned(next, running)

	diff, err := editableDiff(running, next)
	if err != nil {
		return UpdateResult{}, err
	}

	res := UpdateResult{Diff: diff, Settings: settings}
	if req.DryRun {
		return res, nil
	}

	if err := s.gateway.PushConfig(next); err != nil {
		return UpdateResult{}, fmt.Errorf("app: push settings: %w", err)
	}

	now := s.clock.Now()
	if err := s.repo.SetUpstreamDocument(ctx, doc, actor.ID, now); err != nil {
		// running was admitted when it was pushed; re-pushing it is idempotent.
		//
		// Known residual: if the write committed but the driver still reported an
		// error (the connection dropped after COMMIT), the previous configuration
		// runs while the database holds the new document, and the next boot
		// applies it. The operator sees this error; repeating the update converges.
		if errBack := s.gateway.PushConfig(running); errBack != nil {
			//nolint:errorlint // The failed restore is reported, not wrapped: callers match the persist failure alone.
			return UpdateResult{}, fmt.Errorf(
				"app: settings applied but not persisted, and the previous configuration could not be restored (%v): %w",
				errBack, err)
		}

		return UpdateResult{}, fmt.Errorf("app: persist settings (previous configuration restored): %w", err)
	}

	if err := s.audit.Record(ctx, app.AuditEvent{
		At:      now,
		ActorID: actor.ID,
		Action:  "settings.update",
		Target:  "upstream",
		Detail:  map[string]any{"diff": diff},
	}); err != nil {
		return UpdateResult{}, fmt.Errorf("app: settings.update applied but not audited: %w", err)
	}

	res.Applied = true

	return res, nil
}

// proposedDocument is the document an update proposes: the one it carries whole,
// or the stored one with its fields patched in.
func (s *Service) proposedDocument(ctx context.Context, req Update) (string, error) {
	if req.YAML != nil {
		return *req.YAML, nil
	}

	base, err := storedDocument(ctx, s.repo)
	if err != nil {
		return "", err
	}

	return patchDocument(base, *req.Fields)
}

// refuseInertKeys refuses a proposed document that adds an inert key or changes
// its value compared with the stored document: app.ForbiddenSetting naming the
// key, the refusal an owned key gets. Removing one is accepted. The stored
// document is read only when the proposed one sets an inert key.
//
// COMPAT(credentials-import): a key the stored document already sets, carried
// over with the same value, is accepted, so a document saved by an earlier
// release still takes edits; remove next release (RELEASING.md), when the keys
// join ownedKeys and parseDocument refuses them in any document.
func (s *Service) refuseInertKeys(ctx context.Context, doc string) error {
	proposed, err := inertValues(doc)
	if err != nil {
		return err
	}

	if len(proposed) == 0 {
		return nil
	}

	base, err := storedDocument(ctx, s.repo)
	if err != nil {
		return err
	}

	stored, err := inertValues(base)
	if err != nil {
		return fmt.Errorf("app: stored settings: %w", err)
	}

	for _, key := range inertKeys {
		value, set := proposed[key]
		if !set {
			continue
		}

		if previous, had := stored[key]; !had || !reflect.DeepEqual(previous, value) {
			return app.ForbiddenSetting(key)
		}
	}

	return nil
}

// errNoOwnedDefaults refuses a boot configuration without the gateway-owned values
// every running configuration must carry.
var errNoOwnedDefaults = errors.New("app: boot configuration needs the gateway-owned defaults")

// LoadBootConfig builds the gateway's boot configuration: the stored document
// parsed by upstream, with every gateway-owned field taken from owned (listen
// address, auth directory, the boot-only credential families). A stored document
// that no longer passes the checks Update applies is an error, not ignored.
//
// COMPAT(credentials-import): an inert key the stored document still sets is not
// an error: log gets one warning per key, and gateway.admit forces the setting
// off. Remove next release (RELEASING.md), when the keys join ownedKeys.
func LoadBootConfig(ctx context.Context, repo app.SettingsRepo, owned *sdkconfig.Config, log app.Logger) (*sdkconfig.Config, error) {
	if owned == nil {
		return nil, errNoOwnedDefaults
	}

	doc, err := storedDocument(ctx, repo)
	if err != nil {
		return nil, err
	}

	cfg, err := parseDocument(doc)
	if err != nil {
		return nil, fmt.Errorf("app: stored settings: %w", err)
	}

	inert, err := inertValues(doc)
	if err != nil {
		return nil, fmt.Errorf("app: stored settings: %w", err)
	}

	for _, key := range inertKeys {
		if _, set := inert[key]; set {
			log.Warn(inertKeyWarning, slog.String("key", key))
		}
	}

	overlayOwned(cfg, owned)

	return cfg, nil
}

// defaultDocument is the upstream settings document a deployment starts with
// before an administrator saves one: Claude's dated model IDs aliased to their
// short names, forked so both stay listed and routable, and the deprecated or
// retired Claude models hidden. A saved document replaces it entirely.
const defaultDocument = `oauth-model-alias:
  claude:
    - name: claude-haiku-4-5-20251001
      alias: claude-haiku-4-5
      fork: true
    - name: claude-sonnet-4-5-20250929
      alias: claude-sonnet-4-5
      fork: true
    - name: claude-opus-4-5-20251101
      alias: claude-opus-4-5
      fork: true
oauth-excluded-models:
  claude:
    - claude-opus-4-1-20250805
    - claude-opus-4-20250514
    - claude-sonnet-4-20250514
    - claude-3-7-sonnet-20250219
    - claude-3-5-haiku-20241022
`

// storedDocument is the stored document, or the default one when none was saved.
func storedDocument(ctx context.Context, repo app.SettingsRepo) (string, error) {
	doc, err := repo.UpstreamDocument(ctx)
	if errors.Is(err, app.ErrNotFound) {
		return defaultDocument, nil
	}

	if err != nil {
		return "", fmt.Errorf("app: read settings: %w", err)
	}

	return doc, nil
}

func view(doc string, cfg *sdkconfig.Config) View {
	return View{YAML: doc, Fields: Fields{
		ProxyURL:         cfg.ProxyURL,
		RequestRetry:     cfg.RequestRetry,
		MaxRetryInterval: cfg.MaxRetryInterval,
	}}
}

// validate refuses an update that carries both a document and fields, or neither,
// and fields that do not validate.
func (req Update) validate() error {
	switch {
	case req.YAML != nil && req.Fields != nil:
		return app.InvalidSetting("fields", "yaml and fields are mutually exclusive")
	case req.YAML == nil && req.Fields == nil:
		return app.InvalidSetting("yaml", "one of yaml or fields is required")
	}

	if req.Fields != nil {
		return req.Fields.validate()
	}

	return nil
}

func (p Patch) validate() error {
	if p.ProxyURL != nil {
		if _, err := proxyutil.Parse(*p.ProxyURL); err != nil {
			return app.InvalidSetting("proxyURL", err.Error())
		}
	}

	if p.RequestRetry != nil && *p.RequestRetry < 0 {
		return app.InvalidSetting("requestRetry", "must not be negative")
	}

	if p.MaxRetryInterval != nil && *p.MaxRetryInterval < 0 {
		return app.InvalidSetting("maxRetryInterval", "must not be negative")
	}

	return nil
}

// patchDocument sets the patched keys in doc, keeping every other key and its
// comments.
func patchDocument(doc string, patch Patch) (string, error) {
	root, err := documentRoot(doc)
	if err != nil {
		return "", err
	}
	// A block mapping, so an empty document patched does not come out as "{...}".
	root.Style = 0
	if patch.ProxyURL != nil {
		setScalar(root, "proxy-url", "!!str", *patch.ProxyURL)
	}

	if patch.RequestRetry != nil {
		setScalar(root, "request-retry", "!!int", strconv.Itoa(*patch.RequestRetry))
	}

	if patch.MaxRetryInterval != nil {
		setScalar(root, "max-retry-interval", "!!int", strconv.Itoa(*patch.MaxRetryInterval))
	}

	return encodeYAML(&yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}})
}

func setScalar(mapping *yaml.Node, key, tag, value string) {
	scalar := &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == key {
			// Keep the old value's comments with the new value.
			old := mapping.Content[i+1]
			scalar.LineComment, scalar.HeadComment, scalar.FootComment = old.LineComment, old.HeadComment, old.FootComment
			mapping.Content[i+1] = scalar

			return
		}
	}

	mapping.Content = append(mapping.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, scalar)
}

// documentRoot parses doc and returns its top-level mapping; an empty document is
// an empty mapping.
//
// A stream of more than one document is refused (app.ForbiddenSetting, field "document"):
// upstream reads the first document only, so anything after it would be stored,
// served back by Get and silently ignored. So is a YAML merge key anywhere
// (app.ForbiddenSetting, field "<<"): a merge can set a key the literal key check never sees.
func documentRoot(doc string) (*yaml.Node, error) {
	dec := yaml.NewDecoder(strings.NewReader(doc))

	var document yaml.Node
	if err := dec.Decode(&document); errors.Is(err, io.EOF) {
		return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}, nil
	} else if err != nil {
		return nil, app.InvalidSetting("yaml", err.Error())
	}

	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, app.ForbiddenSetting("document")
	}

	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, app.InvalidSetting("yaml", "the document must be a mapping")
	}

	if hasMergeKey(document.Content[0]) {
		return nil, app.ForbiddenSetting("<<")
	}

	return document.Content[0], nil
}

// hasMergeKey reports whether a mapping at or under node has a merge key. Aliases
// are not followed: the node they name is walked where it is defined.
func hasMergeKey(node *yaml.Node) bool {
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			if k := node.Content[i]; k.Value == "<<" || k.ShortTag() == "!!merge" {
				return true
			}
		}
	}

	return slices.ContainsFunc(node.Content, hasMergeKey)
}

// parseDocument checks an editable document and parses it the way upstream does.
// A gateway-owned field is ErrForbiddenSetting naming it: first by its literal
// top-level key, then — for whatever route the key check misses — by comparing
// every owned field of the parsed result with an empty document's. A key upstream
// does not know, at any depth, is ErrInvalidSettings, so a misspelt setting is
// refused rather than silently ignored.
func parseDocument(doc string) (*sdkconfig.Config, error) {
	root, err := documentRoot(doc)
	if err != nil {
		return nil, err
	}

	for i := 0; i+1 < len(root.Content); i += 2 {
		if key := root.Content[i].Value; isOwnedKey(key) {
			return nil, app.ForbiddenSetting(key)
		}
	}

	data := []byte(doc)
	if len(root.Content) == 0 {
		// Upstream refuses an empty payload; an empty document means all defaults.
		data = []byte("{}")
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var probe sdkconfig.Config
	if err := dec.Decode(&probe); err != nil {
		return nil, app.InvalidSetting("yaml", err.Error())
	}

	cfg, err := sdkconfig.ParseConfigBytes(data)
	if err != nil {
		return nil, app.InvalidSetting("yaml", err.Error())
	}

	if err := checkOwnedUnset(cfg); err != nil {
		return nil, err
	}

	if _, err := proxyutil.Parse(cfg.ProxyURL); err != nil {
		return nil, app.InvalidSetting("proxy-url", err.Error())
	}

	return cfg, nil
}

// editableDiff is the unified diff between the editable parts of two
// configurations, proxy credentials redacted.
func editableDiff(from, to *sdkconfig.Config) (string, error) {
	fromYAML, err := editableYAML(from)
	if err != nil {
		return "", err
	}

	toYAML, err := editableYAML(to)
	if err != nil {
		return "", err
	}

	diff, err := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A: difflib.SplitLines(fromYAML), B: difflib.SplitLines(toYAML),
		FromFile: "running", ToFile: "proposed", Context: 3,
	})
	if err != nil {
		return "", fmt.Errorf("app: diff settings: %w", err)
	}

	return diff, nil
}

// editableYAML renders cfg without its gateway-owned keys and with every secret
// redacted (redactSecrets). Only the rendering is redacted; cfg is not touched.
func editableYAML(cfg *sdkconfig.Config) (string, error) {
	var node yaml.Node
	if err := node.Encode(cfg); err != nil {
		return "", fmt.Errorf("app: render settings: %w", err)
	}

	redactSecrets(reflect.TypeFor[sdkconfig.Config](), &node)

	kept := node.Content[:0]
	for i := 0; i+1 < len(node.Content); i += 2 {
		if !isOwnedKey(node.Content[i].Value) {
			kept = append(kept, node.Content[i], node.Content[i+1])
		}
	}

	node.Content = kept

	return encodeYAML(&node)
}

func encodeYAML(node *yaml.Node) (string, error) {
	var buf bytes.Buffer

	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)

	if err := enc.Encode(node); err != nil {
		return "", fmt.Errorf("app: render settings: %w", err)
	}

	if err := enc.Close(); err != nil {
		return "", fmt.Errorf("app: render settings: %w", err)
	}

	return buf.String(), nil
}

// redacted replaces a secret in a rendering.
const redacted = "REDACTED"

// secretKeys are keys whose value is a credential wherever they appear, whatever
// upstream's JSON tag says.
var secretKeys = []string{"api-key", "secret-key", "credential", "password", "token"}

// redactSecrets walks the rendering node of a value of type typ, and redacts:
//
//   - every field upstream keeps out of JSON (`json:"-"`) — its own mark for what
//     management responses must not show, such as the TURN username and
//     credential of the Codex live media relay — and every field named in
//     secretKeys: a set value becomes REDACTED;
//   - every proxy-url, at any depth, to upstream's log-safe form
//     (proxyutil.Redact: scheme and host only, userinfo marked).
//
// It is structural: a secret field upstream adds is covered by its tag, not by a
// list of paths here.
func redactSecrets(typ reflect.Type, node *yaml.Node) {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}

	if node.Kind == yaml.DocumentNode {
		for _, c := range node.Content {
			redactSecrets(typ, c)
		}

		return
	}

	switch {
	case typ.Kind() == reflect.Struct && node.Kind == yaml.MappingNode:
		redactStructFields(typ, node)
	case (typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array) && node.Kind == yaml.SequenceNode:
		for _, c := range node.Content {
			redactSecrets(typ.Elem(), c)
		}
	case typ.Kind() == reflect.Map && node.Kind == yaml.MappingNode:
		for i := 1; i < len(node.Content); i += 2 {
			redactSecrets(typ.Elem(), node.Content[i])
		}
	}
}

// redactStructFields is redactSecrets for the mapping node rendered from struct t:
// each field is redacted, rewritten or walked into as its key and tags say.
func redactStructFields(t reflect.Type, node *yaml.Node) {
	for keyAt := 0; keyAt+1 < len(node.Content); keyAt += 2 {
		field, ok := fieldByYAMLKey(t, node.Content[keyAt].Value)
		if !ok {
			continue
		}

		value := node.Content[keyAt+1]
		switch key, _, _ := strings.Cut(field.Tag.Get("yaml"), ","); {
		case key == "proxy-url" && value.Kind == yaml.ScalarNode:
			value.Value = proxyutil.Redact(value.Value)
		case field.Tag.Get("json") == "-" || slices.Contains(secretKeys, key):
			if value.Kind != yaml.ScalarNode || value.Value != "" {
				node.Content[keyAt+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: redacted}
			}
		default:
			redactSecrets(field.Type, value)
		}
	}
}

// fieldByYAMLKey finds the field of struct t rendered under key, looking through
// inline fields.
func fieldByYAMLKey(t reflect.Type, key string) (reflect.StructField, bool) {
	for field := range t.Fields() {
		name, opts, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		if opts == "inline" {
			if inner, ok := fieldByYAMLKey(field.Type, key); ok {
				return inner, true
			}

			continue
		}

		if name == "" {
			name = strings.ToLower(field.Name)
		}

		if field.IsExported() && name == key {
			return field, true
		}
	}

	return reflect.StructField{}, false
}
