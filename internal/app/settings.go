package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/pmezard/go-difflib/difflib"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	"gopkg.in/yaml.v3"

	"github.com/elleqt/llm-proxy-backend/internal/domain/identity"
)

var (
	// ErrForbiddenSetting is what a *SettingError about a gateway-owned field
	// unwraps to.
	ErrForbiddenSetting = errors.New("app: setting is owned by the gateway")
	// ErrInvalidSettings is what a *SettingError about a malformed document or
	// field unwraps to.
	ErrInvalidSettings = errors.New("app: invalid settings")
	// ErrNoRunningConfig reports a gateway that holds no configuration yet, so
	// there is nothing to diff against or apply over.
	ErrNoRunningConfig = errors.New("app: the gateway has no running configuration")
)

// SettingError names the request field or top-level YAML key a settings update is
// refused for. It unwraps to ErrForbiddenSetting or ErrInvalidSettings.
type SettingError struct {
	Field  string
	Reason string
	kind   error
}

func (e *SettingError) Error() string {
	msg := e.kind.Error()
	if e.Field != "" {
		msg += ": " + e.Field
	}
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	return msg
}

func (e *SettingError) Unwrap() error { return e.kind }

func forbidden(field string) error {
	return &SettingError{Field: field, Reason: "owned by the gateway", kind: ErrForbiddenSetting}
}

func invalid(field, reason string) error {
	return &SettingError{Field: field, Reason: reason, kind: ErrInvalidSettings}
}

// ownedKeys are the top-level keys of the upstream configuration the gateway owns.
// A document setting one is refused rather than applied or silently ignored, and
// the running value is carried over from the configuration that owns it:
//
//   - host, port, tls: the proxied listener, fixed at boot behind the reverse proxy.
//   - trusted-proxies (upstream v7.3.15): whose forwarded headers that listener
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
	"remote-management", "api-keys", "plugins", "ws-auth", "openai-compatibility",
}

// isOwnedKey reports whether a top-level key is gateway-owned. Any key ending in
// "-api-key" is, so a credential family a future upstream adds is boot-only too.
func isOwnedKey(key string) bool {
	return key == "home" || strings.HasSuffix(key, "-api-key") || slices.Contains(ownedKeys, key)
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
	var out []ownedField
	var walk func(t reflect.Type, prefix []int)
	walk = func(t reflect.Type, prefix []int) {
		for i := range t.NumField() {
			f := t.Field(i)
			index := append(slices.Clone(prefix), i)
			name, opts, _ := strings.Cut(f.Tag.Get("yaml"), ",")
			switch {
			case opts == "inline":
				walk(f.Type, index)
			case f.Name == "Home":
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
			return forbidden(f.key)
		}
	}
	return nil
}

// SettingsFields are the typed form fields of the editable document.
type SettingsFields struct {
	ProxyURL         string
	RequestRetry     int
	MaxRetryInterval int // seconds
}

// SettingsView is the stored editable document and its typed fields.
type SettingsView struct {
	YAML   string
	Fields SettingsFields
}

// SettingsPatch patches individual typed fields; a nil field is left as it is.
type SettingsPatch struct {
	ProxyURL         *string
	RequestRetry     *int
	MaxRetryInterval *int
}

// SettingsUpdate replaces the whole document (YAML) or patches typed fields
// (Fields); exactly one of the two is set.
type SettingsUpdate struct {
	YAML   *string
	Fields *SettingsPatch
	DryRun bool
}

// SettingsUpdateResult is what an update did. Diff is the unified diff of the
// running configuration's editable part against the proposed one, with proxy
// credentials redacted; Settings is the proposed document, applied unless Applied
// is false.
type SettingsUpdateResult struct {
	Applied  bool
	Diff     string
	Settings SettingsView
}

// Settings edits the upstream configuration the gateway runs with.
//
// The stored document is the editable part only. The running configuration is that
// document parsed by upstream, with every gateway-owned field (ownedFields) taken
// from the configuration the gateway already runs — at boot, from the
// composition root's defaults (LoadBootConfig).
type Settings struct {
	repo    SettingsRepo
	gateway ConfigPusher
	audit   AuditSink
	clock   Clock

	// mu serialises updates, so the stored document always matches the last
	// configuration pushed: two interleaved updates could otherwise push in one
	// order and persist in the other.
	mu sync.Mutex
}

func NewSettings(repo SettingsRepo, gateway ConfigPusher, audit AuditSink, clock Clock) *Settings {
	return &Settings{repo: repo, gateway: gateway, audit: audit, clock: clock}
}

// Get returns the stored document and its typed fields. Nothing is redacted: the
// document is the administrator's to edit, and a redacted copy sent back whole would
// overwrite the proxy credentials.
func (s *Settings) Get(ctx context.Context, actor identity.User) (SettingsView, error) {
	if err := requireAdmin(actor); err != nil {
		return SettingsView{}, err
	}
	doc, err := storedDocument(ctx, s.repo)
	if err != nil {
		return SettingsView{}, err
	}
	cfg, err := parseDocument(doc)
	if err != nil {
		return SettingsView{}, fmt.Errorf("app: stored settings: %w", err)
	}
	return view(doc, cfg), nil
}

// Update validates the proposed document and, unless DryRun, pushes it to the
// gateway and then persists it: a configuration the gateway refused is never
// stored, and a stored one is always what runs. If persisting fails, the previous
// configuration is pushed back. The audit record carries the redacted diff.
func (s *Settings) Update(ctx context.Context, actor identity.User, req SettingsUpdate) (SettingsUpdateResult, error) {
	if err := requireAdmin(actor); err != nil {
		return SettingsUpdateResult{}, err
	}
	switch {
	case req.YAML != nil && req.Fields != nil:
		return SettingsUpdateResult{}, invalid("fields", "yaml and fields are mutually exclusive")
	case req.YAML == nil && req.Fields == nil:
		return SettingsUpdateResult{}, invalid("yaml", "one of yaml or fields is required")
	}
	if req.Fields != nil {
		if err := req.Fields.validate(); err != nil {
			return SettingsUpdateResult{}, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	doc := ""
	if req.YAML != nil {
		doc = *req.YAML
	} else {
		base, err := storedDocument(ctx, s.repo)
		if err != nil {
			return SettingsUpdateResult{}, err
		}
		if doc, err = patchDocument(base, *req.Fields); err != nil {
			return SettingsUpdateResult{}, err
		}
	}
	cfg, err := parseDocument(doc)
	if err != nil {
		return SettingsUpdateResult{}, err
	}

	running := s.gateway.CurrentConfig()
	if running == nil {
		return SettingsUpdateResult{}, ErrNoRunningConfig
	}
	settings := view(doc, cfg)
	next := cfg.CloneForRuntime()
	overlayOwned(next, running)
	diff, err := editableDiff(running, next)
	if err != nil {
		return SettingsUpdateResult{}, err
	}
	res := SettingsUpdateResult{Diff: diff, Settings: settings}
	if req.DryRun {
		return res, nil
	}

	if err := s.gateway.PushConfig(next); err != nil {
		return SettingsUpdateResult{}, fmt.Errorf("app: push settings: %w", err)
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
			return SettingsUpdateResult{}, fmt.Errorf("app: settings applied but not persisted, and the previous configuration could not be restored (%v): %w", errBack, err)
		}
		return SettingsUpdateResult{}, fmt.Errorf("app: persist settings (previous configuration restored): %w", err)
	}
	if err := s.audit.Record(ctx, AuditEvent{
		At:      now,
		ActorID: actor.ID,
		Action:  "settings.update",
		Target:  "upstream",
		Detail:  map[string]any{"diff": diff},
	}); err != nil {
		return SettingsUpdateResult{}, fmt.Errorf("app: settings.update applied but not audited: %w", err)
	}
	res.Applied = true
	return res, nil
}

// LoadBootConfig builds the gateway's boot configuration: the stored document
// parsed by upstream, with every gateway-owned field taken from owned (listen
// address, auth directory, the boot-only credential families). A stored document
// that no longer passes the checks Update applies is an error, not ignored.
func LoadBootConfig(ctx context.Context, repo SettingsRepo, owned *sdkconfig.Config) (*sdkconfig.Config, error) {
	if owned == nil {
		return nil, errors.New("app: boot configuration needs the gateway-owned defaults")
	}
	doc, err := storedDocument(ctx, repo)
	if err != nil {
		return nil, err
	}
	cfg, err := parseDocument(doc)
	if err != nil {
		return nil, fmt.Errorf("app: stored settings: %w", err)
	}
	overlayOwned(cfg, owned)
	return cfg, nil
}

// defaultDocument is the upstream settings document a deployment starts with
// before an administrator saves one: Claude's dated model IDs aliased to their
// short names, forked so both stay listed and routable. A saved document
// replaces it entirely.
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
`

// storedDocument is the stored document, or the default one when none was saved.
func storedDocument(ctx context.Context, repo SettingsRepo) (string, error) {
	doc, err := repo.UpstreamDocument(ctx)
	if errors.Is(err, ErrNotFound) {
		return defaultDocument, nil
	}
	if err != nil {
		return "", fmt.Errorf("app: read settings: %w", err)
	}
	return doc, nil
}

func view(doc string, cfg *sdkconfig.Config) SettingsView {
	return SettingsView{YAML: doc, Fields: SettingsFields{
		ProxyURL:         cfg.ProxyURL,
		RequestRetry:     cfg.RequestRetry,
		MaxRetryInterval: cfg.MaxRetryInterval,
	}}
}

func (p SettingsPatch) validate() error {
	if p.ProxyURL != nil {
		if _, err := proxyutil.Parse(*p.ProxyURL); err != nil {
			return invalid("proxyURL", err.Error())
		}
	}
	if p.RequestRetry != nil && *p.RequestRetry < 0 {
		return invalid("requestRetry", "must not be negative")
	}
	if p.MaxRetryInterval != nil && *p.MaxRetryInterval < 0 {
		return invalid("maxRetryInterval", "must not be negative")
	}
	return nil
}

// patchDocument sets the patched keys in doc, keeping every other key and its
// comments.
func patchDocument(doc string, p SettingsPatch) (string, error) {
	root, err := documentRoot(doc)
	if err != nil {
		return "", err
	}
	// A block mapping, so an empty document patched does not come out as "{...}".
	root.Style = 0
	if p.ProxyURL != nil {
		setScalar(root, "proxy-url", "!!str", *p.ProxyURL)
	}
	if p.RequestRetry != nil {
		setScalar(root, "request-retry", "!!int", fmt.Sprint(*p.RequestRetry))
	}
	if p.MaxRetryInterval != nil {
		setScalar(root, "max-retry-interval", "!!int", fmt.Sprint(*p.MaxRetryInterval))
	}
	return encodeYAML(&yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}})
}

func setScalar(m *yaml.Node, key, tag, value string) {
	v := &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: value}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			// Keep the old value's comments with the new value.
			old := m.Content[i+1]
			v.LineComment, v.HeadComment, v.FootComment = old.LineComment, old.HeadComment, old.FootComment
			m.Content[i+1] = v
			return
		}
	}
	m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, v)
}

// documentRoot parses doc and returns its top-level mapping; an empty document is
// an empty mapping.
//
// A stream of more than one document is refused (forbidden, field "document"):
// upstream reads the first document only, so anything after it would be stored,
// served back by Get and silently ignored. So is a YAML merge key anywhere
// (forbidden, field "<<"): a merge can set a key the literal key check never sees.
func documentRoot(doc string) (*yaml.Node, error) {
	dec := yaml.NewDecoder(strings.NewReader(doc))
	var n yaml.Node
	if err := dec.Decode(&n); errors.Is(err, io.EOF) {
		return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}, nil
	} else if err != nil {
		return nil, invalid("yaml", err.Error())
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, forbidden("document")
	}
	if len(n.Content) != 1 || n.Content[0].Kind != yaml.MappingNode {
		return nil, invalid("yaml", "the document must be a mapping")
	}
	if hasMergeKey(n.Content[0]) {
		return nil, forbidden("<<")
	}
	return n.Content[0], nil
}

// hasMergeKey reports whether a mapping at or under n has a merge key. Aliases
// are not followed: the node they name is walked where it is defined.
func hasMergeKey(n *yaml.Node) bool {
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if k := n.Content[i]; k.Value == "<<" || k.ShortTag() == "!!merge" {
				return true
			}
		}
	}
	for _, c := range n.Content {
		if hasMergeKey(c) {
			return true
		}
	}
	return false
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
			return nil, forbidden(key)
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
		return nil, invalid("yaml", err.Error())
	}
	cfg, err := sdkconfig.ParseConfigBytes(data)
	if err != nil {
		return nil, invalid("yaml", err.Error())
	}
	if err := checkOwnedUnset(cfg); err != nil {
		return nil, err
	}
	if _, err := proxyutil.Parse(cfg.ProxyURL); err != nil {
		return nil, invalid("proxy-url", err.Error())
	}
	return cfg, nil
}

// editableDiff is the unified diff between the editable parts of two
// configurations, proxy credentials redacted.
func editableDiff(from, to *sdkconfig.Config) (string, error) {
	a, err := editableYAML(from)
	if err != nil {
		return "", err
	}
	b, err := editableYAML(to)
	if err != nil {
		return "", err
	}
	return difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A: difflib.SplitLines(a), B: difflib.SplitLines(b),
		FromFile: "running", ToFile: "proposed", Context: 3,
	})
}

// editableYAML renders cfg without its gateway-owned keys and with every secret
// redacted (redactSecrets). Only the rendering is redacted; cfg is not touched.
func editableYAML(cfg *sdkconfig.Config) (string, error) {
	var n yaml.Node
	if err := n.Encode(cfg); err != nil {
		return "", fmt.Errorf("app: render settings: %w", err)
	}
	redactSecrets(reflect.TypeFor[sdkconfig.Config](), &n)
	kept := n.Content[:0]
	for i := 0; i+1 < len(n.Content); i += 2 {
		if !isOwnedKey(n.Content[i].Value) {
			kept = append(kept, n.Content[i], n.Content[i+1])
		}
	}
	n.Content = kept
	return encodeYAML(&n)
}

func encodeYAML(n *yaml.Node) (string, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(n); err != nil {
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

// redactSecrets walks the rendering n of a value of type t, and redacts:
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
func redactSecrets(t reflect.Type, n *yaml.Node) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if n.Kind == yaml.DocumentNode {
		for _, c := range n.Content {
			redactSecrets(t, c)
		}
		return
	}
	switch {
	case t.Kind() == reflect.Struct && n.Kind == yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			f, ok := fieldByYAMLKey(t, n.Content[i].Value)
			if !ok {
				continue
			}
			v := n.Content[i+1]
			switch key, _, _ := strings.Cut(f.Tag.Get("yaml"), ","); {
			case key == "proxy-url" && v.Kind == yaml.ScalarNode:
				v.Value = proxyutil.Redact(v.Value)
			case f.Tag.Get("json") == "-" || slices.Contains(secretKeys, key):
				if v.Kind != yaml.ScalarNode || v.Value != "" {
					n.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: redacted}
				}
			default:
				redactSecrets(f.Type, v)
			}
		}
	case (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) && n.Kind == yaml.SequenceNode:
		for _, c := range n.Content {
			redactSecrets(t.Elem(), c)
		}
	case t.Kind() == reflect.Map && n.Kind == yaml.MappingNode:
		for i := 1; i < len(n.Content); i += 2 {
			redactSecrets(t.Elem(), n.Content[i])
		}
	}
}

// fieldByYAMLKey finds the field of struct t rendered under key, looking through
// inline fields.
func fieldByYAMLKey(t reflect.Type, key string) (reflect.StructField, bool) {
	for i := range t.NumField() {
		f := t.Field(i)
		name, opts, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if opts == "inline" {
			if inner, ok := fieldByYAMLKey(f.Type, key); ok {
				return inner, true
			}
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		if f.IsExported() && name == key {
			return f, true
		}
	}
	return reflect.StructField{}, false
}
