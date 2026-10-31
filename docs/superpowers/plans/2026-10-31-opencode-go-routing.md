# OpenCode Go Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prefer OpenCode Go for ordinary DeepSeek aliases, with the official DeepSeek API as the native CLIProxyAPI fallback, configurable through existing provider management.

**Architecture:** Extend compatible-provider credentials with priority and secret custom headers. Retain CLIProxyAPI v8.0.38's executor, cross-provider selection, cooldown, and session affinity. Expose write-only header updates and nonsecret header names in the existing API/editor.

**Tech Stack:** Go 1.27.3, CLIProxyAPI v8.0.38, Postgres, oapi-codegen v2.8.0, mockery v3.8.1; React 19.3.0, TypeScript 5.9.3, TanStack Query, Vitest 5.0.4, MSW 3.0.3, npm, Node >=22.22.0.

**Spec:** `docs/superpowers/specs/2026-10-31-opencode-go-routing-design.md` in the backend repository. The user approved its written version before this plan.

## Global Constraints

- Upstream remains read-only.
- No custom retry loop, selector, or inference proxy is added.
- Do not change session-affinity configuration or routing behavior for Claude, ChatGPT, or unrelated models.
- Treat every configured header value as a potential secret.
- Stored values must not appear in admin detail responses, audit payloads, logs, errors, or frontend persistent storage.
- Changing a provider base URL while retaining stored headers requires explicitly replacing or clearing those headers, just as a saved API key cannot silently follow an edited destination.
- A shared alias is admitted only when the user's policy covers every provider serving it.
- Do not silently map a requested model to another generation or tier simply because their names are similar.
- Do not hand-edit generated files.
- No layout redesign, new UI dependency, or dedicated OpenCode preset is included.
- Code comments, fixtures, and public examples use generic infrastructure and `example.com`; real deployment coordinates and keys belong only in private notes.
- Use existing test conventions: testify assertions, no parallel gateway tests, Postgres through `pgtest.NewTestPool(t)`, strict generated mocks, frontend contract-typed handlers. Do not add hand-written service fakes.
- Create execution worktrees/branches before implementation. Keep unrelated `.codegraph/` files untouched. No pushing, PRs, release tagging, or remote branch changes are authorized by this plan.
- Inspect symbols through LSP when available. The planning session found no configured language server; if still unavailable, enumerate all callers with targeted searches before changing exported signatures.
- Task commands below are to be run during execution, not claimed as already passed. Dependency generation is required when its inputs change; do not run full suites or formatters inside parallel implementation slices. The integration owner runs final gates once.

## File map and task boundaries

All paths below are relative to the named independent repository. There is no workspace-root Git repository.

| Task | Repository | Responsibility |
| --- | --- | --- |
| 1 | backend | App validation, sealed metadata, live/reloaded header and priority behavior |
| 2 | backend + frontend generated contract | Safe discovery and complete admin HTTP contract |
| 3 | backend | Real upstream failover, session, streaming, authorization, and attribution proof |
| 4 | frontend | Existing provider drawer controls and secret-safe editor behavior |
| 5 | both + private deployment | Actual surface smoke, live integration, documentation, final gates |

Tasks 1 and 2 are sequential because the HTTP layer must expose working runtime behavior, not accepted-but-ignored fields. Task 3 and Task 4 can proceed independently after Task 2, provided backend and frontend edits have separate owners. The integration owner retains Task 5 and final verification.

## Shared interfaces

Add these fields to the existing app types in `internal/app/ports.go`; do not introduce parallel provider types:

```go
// Add to CompatProvider.
Priority int32
Headers  map[string]string

// Add to CompatProviderUpdate. nil means preserve; a non-nil empty map clears.
Priority *int32
Headers  map[string]string

// Add to CompatDetails. Never include header values in this type.
Priority    int32
HeaderNames []string
```

Task 2 extends the existing discovery signatures, with one appended argument and a clean caller migration:

```go
DiscoverModels(ctx context.Context, baseURL, apiKey, accountID string,
    proxy *ProxyChoice, headers map[string]string) ([]string, error)
```

The corresponding provider service method keeps its existing arguments and appends `headers map[string]string` after `proxy`. In discovery, `nil` headers selects saved headers for the named account and its saved destination; an explicit empty map sends none; a nonempty map replaces saved headers for this request only.

The HTTP schema uses `priority`, `headers`, and `headerNames`. Generated optional maps may be pointers; translate omission to a nil app map and an explicit `{}` to an allocated empty map. Do not collapse them with a helper that loses the distinction.

---

### Task 1: Persist and enforce compatible-provider settings

**Files:**
- Modify: `backend/internal/app/ports.go`.
- Modify: `backend/internal/app/providers/compat.go`.
- Create: `backend/internal/app/providers/compat_headers.go` for focused header validation.
- Modify: `backend/internal/app/providers/compat_test.go`.
- Modify: `backend/internal/infra/gateway/compat.go`.
- Modify: `backend/internal/infra/gateway/compat_test.go`.

**Interfaces:**
- Consumes the existing `app.CompatProvider`, `app.CompatProviderUpdate`, `app.CompatDetails`, provider service, and sealed credential store.
- Produces the shared fields above and private `validCompatHeaders(map[string]string) (map[string]string, error)` in package `providers`.
- Produces runtime `priority` and `header:*` attributes from sealed metadata. No new app port or database migration.

- [ ] **Step 1: Add failing behavioral tests.** In the external provider test package, use the existing strict fixture to prove malicious header definitions never reach the account adapter:

```go
func TestCreateCompatRejectsUnsafeHeaders(t *testing.T) {
    cases := []map[string]string{
        {"X-Test": "safe\r\nX-Injected: bad"},
        {"Bad Header": "value"},
        {"X-Test": "one", "x-test": "two"},
        {"Authorization": "Bearer must-not-override"},
        {"Host": "elsewhere.example.com"},
        {"Content-Length": "7"},
    }
    for _, headers := range cases {
        fixture := newProvidersFixture(t)
        _, err := fixture.svc.CreateCompat(t.Context(), providerAdmin(), app.CompatProvider{
            Name: "acme", BaseURL: "https://api.example.com/v1",
            Models: []app.CompatModel{{Name: "m"}}, Headers: headers,
        })
        var invalid *app.InvalidInputError
        require.ErrorAs(t, err, &invalid)
        require.Equal(t, "headers", invalid.Field)
    }
}
```

Extend the existing gateway restart test to create a provider with priority `7` and a synthetic `X-Vendor-Token` secret. Before and after restart, call the model, inspect the vendor's received header, check returned header names, and call `assertNoKey` with the header secret too. Add update transitions: omission preserves, explicit `{}` removes, replacement removes old runtime `header:*` attributes, changing the URL without explicit header replacement is rejected before any request reaches the new target.

- [ ] **Step 2: Observe the failing tests.** Run in `backend`:

```bash
go test ./internal/app/providers -run 'TestCreateCompatRejectsUnsafeHeaders' -count=1
go test ./internal/infra/gateway -run 'TestCompatProvider.*(Headers|Priority|Restart)' -count=1
```

Initial compile failures for the missing public fields are expected. After adding only the types, require a behavioral failure before implementing the adapter changes; do not count a spelling/compilation error as the only regression proof.

- [ ] **Step 3: Implement the app boundary.** Normalize header names to lower case, preserve upstream-compatible value whitespace semantics, and reject invalid names, control characters other than horizontal tab, and case-insensitive duplicates. Return only `&app.InvalidInputError{Field: "headers"}` for invalid definitions, with no offending value. Reject exactly the dedicated credential and transport controls named in the spec. Keep the validator independent of HTTP libraries. Invoke it from create and update, preserving nil versus an explicit empty map. Audit priority and header names/change intent, never values. Existing unauthorized callers must still fail before validation or adapter calls.

Use a finite token-name regexp and a control-byte scan, not a permissive newline-only check:

```go
var compatHeaderName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9a-z-]+$")

func validCompatHeaderValue(value string) bool {
    for i := 0; i < len(value); i++ {
        b := value[i]
        if b == 127 || (b < 32 && b != '\t') {
            return false
        }
    }
    return true
}
```

Keep the full forbidden-name switch next to `validCompatHeaders`, including `authorization`, `proxy-authorization`, `host`, `content-length`, `transfer-encoding`, `connection`, `proxy-connection`, `keep-alive`, `te`, `trailer`, and `upgrade`. Reject empty normalized values because upstream otherwise silently omits them.

- [ ] **Step 4: Implement metadata and update behavior.** Store headers at metadata key `headers`, the representation already understood by `coreauth.ExtractCustomHeadersFromMetadata` and `coreauth.ApplyCustomHeadersFromMetadata`. Store priority in metadata key `priority` as its decimal string; this avoids the SDK helper's unsupported in-memory `int32` case and survives JSON persistence. Parse with `strconv.ParseInt(raw, 10, 32)`; absent/invalid metadata yields the neutral priority `0`, never a routing privilege increase.

Before applying headers, delete existing attribute keys beginning with `header:`; the upstream apply helper only adds and does not remove old keys. Set the `priority` attribute to the parsed decimal value. Derive `CompatDetails.HeaderNames` from the normalized stored map, sorted, returning an allocated empty slice. Set `compatEntry(...).Priority` from the same metadata. Do not set `compatEntry(...).Headers`: settings projections must not expose header values.

In `UpdateCompatProvider`, resolve preserved priority/headers from the held credential before rebuilding metadata. Check the saved-header URL boundary before saving; explicit replacement/clear authorizes the new destination. Preserve disabled state and per-account proxy exactly as today. Keep save-before-apply ordering and existing synchronization.

- [ ] **Step 5: Verify behavior and commit.** Run the targeted tests above and the complete provider/gateway package tests once this task's code is integrated. Ensure the real on-wire assertions prove behavior after restart, not just field equality. Commit only the Task 1 files:

```bash
git commit -m "feat: persist provider headers and priority"
```

### Task 2: Expose safe admin settings and discovery

**Files:**
- Modify: `backend/api/openapi.yaml`.
- Modify: `backend/internal/app/ports.go` discovery signature.
- Modify: `backend/internal/app/providers/compat.go`, `compat_test.go`, and `providers_test.go`.
- Modify: `backend/internal/infra/gateway/compat.go`, `compat_test.go`, and `proxy_test.go`.
- Modify: `backend/internal/iface/http/admin_providers.go` and `admin_compat_test.go`.
- Regenerate: `backend/internal/iface/http/api/api.gen.go` and `backend/internal/app/mocks/vendor_accounts.go` through `make generate`.
- Regenerate: `frontend/api/openapi.yaml` and `frontend/src/shared/api/schema.d.ts` through `npm run sync:contract`.

**Interfaces:**
- Consumes Task 1 fields, normalized header metadata, and validation.
- Produces working HTTP create/update/details/discovery and the appended discovery argument documented above.
- `CompatProviderDetails` requires `priority` and `headerNames`. Create/update accept optional write-only `headers`; discovery accepts optional write-only `headers`. Details never contain `headers`.

- [ ] **Step 1: Add the schema before generation.** Define the reusable input header-map schema, signed integer bounds, and explicit omission/empty-map behavior. Add the detail fields with required empty arrays for no header names. Example property fragments:

```yaml
priority:
  type: integer
  format: int32
  minimum: -2147483648
  maximum: 2147483647
headers:
  type: object
  writeOnly: true
  additionalProperties:
    type: string
headerNames:
  type: array
  items:
    type: string
```

Use the create description for default `0`; do not add a schema default to the update field if generation would erase the preserve-versus-set distinction. Document the account destination boundary in discovery and stable `invalid_input` field `headers`.

- [ ] **Step 2: Add failing security tests at the HTTP and discovery boundaries.** In `admin_compat_test.go`, send a header-injection create request through `env.do`, expect the existing 422 `invalid_input` response and field `headers`, and verify the secret is absent. Add a detail serialization test with `Priority: 7` and names only, checking decoded JSON has no `headers` property. Do not add a mock-echo-only field-forwarding test.

At the gateway boundary, use an HTTP model-list server that requires a static `X-Vendor-Token` to return `{"data":[{"id":"authorized-model"}]}`. Discover with supplied headers and then with the stored provider/account. A changed destination without a replacement map must return `invalid_input` on `headers` and the target must receive zero requests. Explicit `{}` must not send the old header. Cross-host redirects must not receive it either. Existing key/proxy tests must continue covering their previous boundary.

Example HTTP rejection assertion, using the existing helpers:

```go
func TestCreateCompatHeaderInjectionIsAFieldError(t *testing.T) {
    env := newEnv(t)
    rec := env.do(http.MethodPost, "/api/admin/providers/compat",
        `{"name":"acme","baseURL":"https://api.example.com/v1","models":[{"name":"m"}],"headers":{"X-Test":"secret-value\r\nInjected: bad"}}`,
        withCookie(env.signedIn(admin())))
    apiError(t, rec, http.StatusUnprocessableEntity, codeInvalidInput)
    require.NotContains(t, rec.Body.String(), "secret-value")
    require.Contains(t, rec.Body.String(), `"field":"headers"`)
}
```

- [ ] **Step 3: Regenerate and migrate every discovery caller.** Run `make generate` in backend after the schema and port changes. Use reference lookup if LSP is available; otherwise targeted search for `DiscoverModels(` and `DiscoverCompat(` across backend. Update all callers in the listed test files and handlers, with explicit nil for old no-header behavior. No old signature alias or forwarding shim remains.

- [ ] **Step 4: Implement handlers and safe discovery.** Map optional headers without losing `{}`. Return detail priority/header names only. Add `validCompatHeaders` to discovery input validation. Resolve saved maps with the same normalized full-base-URL comparison used for keys, independent of whether a key is present or newly supplied. A supplied key must not accidentally authorize moving a saved header secret.

Keep the existing `discoveryClient`: it enforces timeout, body-size, proxy, link-local, and redirect safety. Apply only static headers to this conversation-less request; omit values that begin with `$` or contain case-insensitive `$CPA-SESSION-ID`. This is omission of unresolved variables, not a new expansion/session engine. Inference still delegates all expansion to upstream. Return existing sanitized discovery errors; preserve manual model entry. Test static headers, omitted variables, and rejection paths explicitly.

- [ ] **Step 5: Verify and synchronize the contract.** Run in backend:

```bash
go test ./internal/app/providers ./internal/iface/http -run 'Compat|Discover' -count=1
go test ./internal/infra/gateway -run 'TestDiscoverModels|TestCompatProvider|TestCompat.*Headers' -count=1
```

Then in frontend run `npm run sync:contract`. Commit the generated contract update in the frontend worktree and the complete API/discovery change in backend. Do not run frontend code against stale generated types.

### Task 3: Prove native priority, failover, and session behavior

**Files:**
- Create: `backend/internal/infra/gateway/compat_routing_test.go`.
- Reuse, without new fake implementations: `backend/internal/infra/gateway/faketest/vendor.go` and `wire_test.go` helpers.
- Extend when needed: `backend/internal/infra/gateway/policy_gate_test.go` and `backend/internal/infra/gateway/usage/wire_test.go`.

**Interfaces:**
- Consumes the production `AddCompatProvider`/`UpdateCompatProvider` paths and Task 2 HTTP contracts.
- Produces regression proof using two real loopback vendor servers under one alias. Changes to production routing are not expected; any upstream mismatch must be investigated and reported rather than bypassed with a second selector.

- [ ] **Step 1: Add a failing on-wire priority test.** Build the gateway using `productionParamsFor(cfg)` and `startWith`, start two `compatVendor()` servers, add both with a unique shared alias, and set primary priority `1`, secondary priority `0`. Create `cfg := &cliproxyconfig.Config{AuthDir: t.TempDir()}` and explicitly set `cfg.Routing.SessionAffinity = true` so session tests do not accidentally exercise the upstream false default. Await both catalog registrations before sending requests. Send several independent session IDs, then assert every request reached primary and none reached secondary. Use unique provider/model names with the existing `compatName`/`compatModel` helpers.

Use the existing canonical identity function for precise header expectations rather than asserting only a nonempty string:

```go
sessionHeaders := http.Header{"X-Session-Id": {"priority-probe-session"}}
wantSession := coreauth.CanonicalSessionID(sessionHeaders, nil, nil)
require.Equal(t, wantSession, primary.Requests()[0].Header.Get("X-Opencode-Session"))
```

The primary provider is created with `Headers: map[string]string{"x-opencode-session": "$CPA-SESSION-ID"}`. Repeat with another explicit session and compare each exact canonical identity. Exercise both stream modes; for streaming, provide valid `faketest.Vendor.Chunks` with an actual assistant text delta.

- [ ] **Step 2: Add failure and partial-stream cases.** For each of 401, 402, 403, 429, and 503, configure primary `FailStatus` and a representative vendor error body before starting the request. A successful secondary must supply the only final assistant content. Assert both attempt paths, the final answer, and source attribution. For invalid client input, assert the secondary receives zero calls. For a canceled request and for primary with one flushed answer delta followed by `DieMidStream`, assert secondary receives zero calls and no replayed assistant text is delivered.

Do not mutate `faketest.Vendor` exported fields concurrently with a request; its request list is synchronized but configuration fields are not. Between requests, use gateway credential disable/enable or `coreAuth.MarkResult`/`Update` over a cloned auth to create deterministic availability changes.

- [ ] **Step 3: Prove recovery and authorization.** Bind a session to primary, make primary unavailable, and issue a second turn with the same explicit session. Restore primary availability without resetting the selector. The next turn in that session must still reach secondary; a different explicit session must reach primary. Restore availability deterministically through cloned auth/model state, not a long sleep. Test a user authorized for only one of the alias's serving providers: the gate must reject before either vendor receives a request. An allowed user covering both providers succeeds. Preserve existing built-in provider tests.

- [ ] **Step 4: Prove ledger identity through the existing usage harness.** Extend the existing fresh-process usage wire test with two accounts and successful fallback, preserving its queue-drain barrier. Assert the success row names the actual secondary provider/account and public alias; do not conflate failed attempts with the final success or assert a single total row if upstream records failed attempts separately. Check model/account identities, not just a request counter increase.

- [ ] **Step 5: Run the focused integration proof and commit.** Run:

```bash
go test ./internal/infra/gateway -run 'TestCompat.*(Priority|Session|Failover|Headers|Stream)' -count=1 -race
go test ./internal/infra/gateway/usage -run 'TestProxiedRequest|Compat.*Fallback' -count=1 -race
```

Expected: exact primary/secondary selection, distinct dynamic session headers, correct streaming/error behavior, and no secret exposure. Commit the real behavior regressions, not tests of upstream source text.

### Task 4: Add priority and secret-header editing to the existing drawer

**Files:**
- Modify: `frontend/src/features/compat-provider/CompatDrawer.tsx` and `CompatDrawer.test.tsx`.
- Create: `frontend/src/features/compat-provider/CompatHeaders.tsx`, `CompatHeaders.module.css`, and `CompatHeaders.test.tsx`.
- Create: `frontend/src/features/compat-provider/headers.ts` for the client draft type and pure input conversion used by the component and drawer.
- Modify: `frontend/src/shared/i18n/en.ts` and `ru.ts`.
- Modify: `frontend/src/mocks/browser.ts`.
- Update impacted fixtures: `frontend/src/pages/admin/providers/AdminProvidersPage.test.tsx` and `frontend/src/test/server.ts` where required by generated mandatory detail fields.

**Interfaces:**
- Consumes Task 2 generated `components` schemas; never hand-write API request/response types.
- Produces a controlled header editor and draft conversion; the parent owns the draft so save, discovery, dirty state, and destination warnings share one source.

Define client-only draft state as follows:

```ts
export type HeadersDraft =
  | { mode: "keep" }
  | { mode: "replace"; rows: { id: number; name: string; value: string }[] }
  | { mode: "clear" };
```

`headersInput(draft)` returns `components["schemas"]["CompatProviderUpdate"]["headers"]`. Keep returns `undefined`, clear returns `{}`, and replace returns the normalized complete map after rejecting blank/duplicate names and empty values. Validate duplicates before constructing the object, so duplicate rows cannot overwrite each other. The controlled `CompatHeaders` props are `draft`, `names: readonly string[]`, `onChange`, and an optional `error` string. Use existing own UI controls and a small CSS Module, no dependency additions.

- [ ] **Step 1: Add failing interaction tests.** Extend the drawer helper with optional compatible-detail overrides, defaulting `priority: 0` and `headerNames: []`. Test: editing priority preserves unknown saved header values; replace submits only the new full map; clear submits `{}`; cancel replacement discards typed values and preserves saved names. Changing base URL while keeping saved header names must explain the need to replace/remove and prevent save/discovery from sending preserved secrets.

Use stable translated labels defined in this task. Example behavioral test:

```tsx
it("removes saved headers without requiring their values", async () => {
  const { user, sent, onClose } = drawer([{ name: "model-a" }], { mode: "inherit" }, {
    priority: 1,
    headerNames: ["x-vendor-token"],
  });
  await user.click(advanced());
  await user.click(within(dialog()).getByRole("button", { name: en["compat.headersRemove"] }));
  await user.click(save());
  const body = await savedBody(sent, onClose);
  expect(body?.headers).toEqual({});
  expect(body?.apiKey).toBeUndefined();
});
```

Also verify typed secrets are absent from `cached(queryClient)` after the drawer closes, using the existing cache helper and mutation `gcTime: 0`. Check keyboard focus returns to the appropriate Replace/Remove button when editing is canceled.

- [ ] **Step 2: Observe failures.** Run in frontend:

```bash
npx vitest run src/features/compat-provider/CompatDrawer.test.tsx src/features/compat-provider/CompatHeaders.test.tsx
```

- [ ] **Step 3: Implement the controlled editor and priority input.** Display saved names with a stored-values hint, not masked value fields. Replace starts a fresh row list; clear has Undo; canceled replacement resets to keep and releases values. Use password inputs for values, autocomplete off, and no localStorage. Normalize field names to lower case and reject duplicates locally. Server remains authoritative for full header safety.

In the parent, use a string draft for priority so intermediate invalid edits are representable; validate `Number.isInteger(value)` and the signed int32 range before submission. Omit unchanged priority on update. Include header changes in discard protection and open Advanced for an error on `headers` or `priority`. Add exact field-label keys in both dictionaries: `compat.priority`, `compat.priorityHint`, `compat.headers`, `compat.headersStored`, `compat.headersReplace`, `compat.headersRemove`, `compat.headersUndo`, `compat.headersCancel`, `compat.headerName`, `compat.headerValue`, `compat.headerAdd`, `compat.headerRemove`, `compat.headersNeedsReplacement`, and validation copy keys.

Use the same header draft conversion for save and discover. For saved headers, set `accountId` even when no stored API key exists. Preserve existing proxy choice rules. Do not forward saved headers to a changed URL merely because a newly typed API key is present. Keep discovery failures from clearing selected/manual model rows, aliases, priority, or typed header values.

- [ ] **Step 4: Update browser mocks without leaking values.** Add priority/headerNames defaults to compatible accounts and update create/update mock responses from the submitted intent. The mock may retain the names it needs for UI state, not echo values in provider responses. Follow existing dev-only mock gates. Update fixtures to the generated contract; remove tests that only pin incidental request-object formatting instead of user behavior rather than repinning them around the new fields.

- [ ] **Step 5: Verify and commit.** Run the focused tests above, then the affected provider-page tests. Assert negative priority, zero, positive priority, invalid decimal/out-of-range input, duplicate headers, preserve/replace/clear, discovery failure, destination-change warnings, and closed-drawer cache secrecy. Commit only the frontend feature and affected fixture/generated contract changes, keeping backend edits separate.

### Task 5: Exercise the surface, verify real Go routing, and document the feature

**Files:**
- Modify after smoke proof: `backend/README.md` and `frontend/README.md`.
- Private deployment notes: the user-provided infrastructure document, outside the public repositories.
- No committed probe scripts or credentials.

**Interfaces:**
- Consumes the complete backend/frontend feature, matching contracts, existing local deployment procedure, and the user's permission to use the current omp OpenCode credential.
- Produces observed acceptance evidence, updated user documentation, and restored probe state.

- [ ] **Step 1: Smoke the actual editor against the real API.** Start the local application stack using existing compose/build tooling. Open the provider drawer in a real browser through the browser tool. Create a generic compatible test provider pointing at an isolated vendor, set priority and a header, save, reopen, and verify only the name is visible. Replace and clear, verify inference at the isolated vendor, and inspect an invalid header error and a failed discovery followed by manual entry. Close the browser tab after recording visual proof. Do not substitute Vitest alone for this surface check.

- [ ] **Step 2: Inspect live prerequisites without exposing credentials.** Read the private deployment instructions supplied by the user; identify current images, gateway/admin access, provider definitions, policies, and the actual model catalogs. Retrieve the OpenCode credential from the current omp storage into process memory only. Do not print credential rows, raw secret-bearing configuration, key prefixes, shell-expanded command lines, or upstream request headers. Confirm Go region eligibility if the vendor reports a regional restriction; report a genuine account prerequisite rather than silently using Zen or the paid official source.

Build the mapping from each client alias to the actual Go and official identifiers. Compare generations/tiers, not just strings. A model without an equivalent on both providers stays single-source and must be identified in the acceptance report. Do not alter the user's default model or subscription settings without necessity.

- [ ] **Step 3: Probe Go directly and check billing source.** Make one short non-streaming inference request using the documented Go OpenAI base URL, the existing key, and an isolated probe session header. The request body should use a catalog-confirmed model and a bounded answer:

```python
import json
import os

payload = json.dumps({
    "model": os.environ["GO_PROBE_MODEL"],
    "messages": [{"role": "user", "content": "Reply with exactly pong."}],
    "max_tokens": 64,
    "stream": False,
}).encode()
```

Set `GO_PROBE_MODEL` from the inspected Go catalog before preparing the request. Print only HTTP status, model identifier, answer, and `usage.opencode.billing_source`. Require the actual billing value `go`; a 200 alone is insufficient. If the provider needs a larger reasoning/output allowance to produce text, use its documented request shape instead of declaring an empty answer successful.

- [ ] **Step 4: Back up and deploy through the established rollback procedure.** Back up provider definitions, affected policies, and images/configuration using the private environment's existing tooling. Keep recoverable secret material in protected local/remote files, never public artifacts. Deploy both matching images, self-check the gateway and unaffected Claude/ChatGPT routes, then configure Go priority `1`, official priority `0`, the dynamic session header, and verified shared aliases. Preserve existing client-facing names and keys.

- [ ] **Step 5: Exercise both real clients and isolated failure behavior.** Send a short request through omp with its normal DeepSeek provider setup pointed at the gateway, and through LibreChat using its existing DeepSeek endpoint/spec. Read streaming output to completion. Check actual selected provider/account and usage attribution. Prove paid fallback with isolated probe providers/model aliases rather than corrupting the shared live Go key or exhausting its allowance. Verify a rebound probe session stays on official and a new session prefers recovered Go. Record only sanitized outcomes.

The smoke payloads for ordinary gateway requests retain their normal form:

```python
payload = json.dumps({
    "model": os.environ["GATEWAY_PROBE_ALIAS"],
    "messages": [{"role": "user", "content": "Reply with exactly pong."}],
    "max_tokens": 64,
    "stream": True,
}).encode()
```

Set `GATEWAY_PROBE_ALIAS` from the inspected current client configuration before preparing the request; never silently replace a requested generation/tier to make acceptance pass. Remove isolated probe providers and temporary test conversations through their normal APIs, restore temporary configuration, and retain genuine usage accounting according to deployment conventions.

- [ ] **Step 6: Update documentation after smoke proof.** Explain priority, lifetime-limited session binding, write-only header values, preserve/replace/clear semantics, destination protection, model discovery's unresolved-variable limitation, shared-alias policy requirements, and actual provider attribution. Include an OpenCode Go recipe with the vendor-documented Go endpoint and `x-opencode-session: $CPA-SESSION-ID`; distinguish Go from Zen. Public snippets contain no keys or private deployment information. Add the measured live deployment result only to private infrastructure notes.

- [ ] **Step 7: Run final gates once, from each repository.** Backend:

```bash
make build
go vet ./...
make test
make lint
scripts/check-readme-compose.sh
```

Frontend:

```bash
npm run build
npm test
```

Regeneration was already performed where inputs changed; verify the two OpenAPI copies with `cmp backend/api/openapi.yaml frontend/api/openapi.yaml` from the workspace root. Use `git diff --check` only if needed for the final patch hygiene gate, not repeated source re-audits. Report the exact exercised commands and any real prerequisites; never claim full acceptance from a partial suite.

- [ ] **Step 8: Commit feature documentation and hand over observed evidence.** Keep independent repository commits, do not push or change release image pins. Final report states the actual tested Go model/billing source, primary/fallback behavior, omp/LibreChat result, and any single-source models or missing live prerequisites. Do not call the integration complete if a named acceptance path remains unexercised.

## Plan self-review checklist

- [x] Every spec section maps to Tasks 1–5: runtime/persistence (1), API/discovery/secrecy (1–2), routing/access/accounting (3), UI/cache secrecy (4), real clients/rollback/docs (5).
- [x] Task 2 migrates every old discovery signature; generated output is regenerated, not edited.
- [x] Planned optional map semantics are consistent across app, API, drawer, mocks, and discovery.
- [x] Dynamic inference headers use upstream resolution; discovery omits unresolved conversation variables without a dummy shared session.
- [x] Planned priority recovery preserves the current binding; no global affinity change or own retry machinery is planned.
- [x] Live evidence is not represented as already collected, and private coordinates/keys are absent from public documents.
