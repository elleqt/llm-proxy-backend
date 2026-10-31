# Universal Account Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give every managed vendor account the same role-based routing controls and move the existing on-by-default sticky-session toggle to Providers.

**Architecture:** Store one shared integer priority in sealed account metadata, project it into native CLIProxyAPI routing, and expose it on the root account contract. Present Preferred/Normal/Reserve presets over values `1/0/-1`, preserving custom values. Reuse the settings API for one immediate sticky-session control; retain native selection and established bindings.

**Tech Stack:** Go 1.27.3, CLIProxyAPI v8.0.38, Postgres, mockery v3.8.1, oapi-codegen v2.8.0; React 19.3.0, TypeScript 5.9.3, TanStack Query, Vitest 5.0.4, MSW 3.0.3, npm, Node >=22.22.0.

**Spec:** `docs/superpowers/specs/2026-10-31-universal-account-routing-design.md`.

**Execution:** The user approved the written specification and explicitly chose sequential inline execution. Continue on the existing isolated `feat/opencode-go` worktrees, updating backend PR #47 and frontend PR #29. Do not ask the execution-style question again.

## Global Constraints

- Continue using CLIProxyAPI v8.0.38; do not build a second selector or retry system.
- Routing roles do not grant access, override spend limits, or represent monetary weights.
- Existing custom integer priorities must not be silently converted to a preset.
- The ordinary path shows roles, not numbers.
- Editing the role of a disabled or temporarily unavailable account is allowed and does not enable it.
- Keep custom HTTP headers under compatible connection Advanced settings.
- There is one ordinary UI control, not independent copies in Providers and the Settings typed form.
- Keep the existing on-by-default rule. Do not reset a deliberate false value during a deployment, restart, account change, or unrelated settings edit.
- No new role enum, role database column, schema migration, or new public model-route/group resource is introduced.
- Migrate all call sites and fixtures; do not hand-edit generated output or preserve the obsolete nested response field through a shim.
- Priority changes must preserve tokens, proxy mode/credentials, disabled state, model definitions, quota/cooldown state, and session-affinity bindings.
- Do not clone real OAuth grants to test refresh behavior.
- Use existing strict mocks, `pgtest.NewTestPool(t)`, and the permitted `faketest` vendor/executor. No parallel gateway tests or new hand-written service fakes.
- Keep all real credentials and deployment details out of public code, fixtures, logs, and documents. Use `example.com`; retrieve permitted test keys into process memory only.
- Existing worktrees: backend and frontend are siblings under `.worktrees/opencode-go/`. Keep the ignored visual-companion artifacts out of commits.
- Pushing updates to the existing feature PRs is authorized. Merging and release-image pin changes are not authorized.

## Files and responsibility map

| Unit | Files | Responsibility |
| --- | --- | --- |
| Shared account routing | backend `internal/infra/gateway/priority.go`, existing account/credential adapters | Metadata representation, effective priority, mutation, reload/relogin preservation |
| Account use case and API | backend app ports/providers, OpenAPI, HTTP handlers, generated mocks/types | Shared account priority contract and administrator-only updates |
| Role presentation | frontend `src/entities/provider/routing.ts`, `RoutingRoleSelect.tsx`, `AccountRoutingFields.tsx` | Presets/custom values and controlled form presentation without API side effects |
| Inline routing actions | frontend `src/features/provider-routing/AccountUsageControl.tsx`, `SessionAffinityControl.tsx` | Immediate account/settings mutations, pending/error state and cache updates |
| Existing page/editors | provider page/CSS, both account drawers, Settings form | Integrate roles, retain existing capabilities, remove duplicate sticky ownership |
| Proof and delivery | existing/new behavioral tests, READMEs, real browser smoke | Lifecycle, native routing, API/UI boundaries, docs and PR updates |

## Shared interfaces

Backend:

```go
// Add to app.VendorAccount, and remove from app.CompatDetails in Task 2.
Priority int32

// Add to app.VendorAccounts.
SetAccountPriority(ctx context.Context, id string, priority int32) error

// Add to providers.AccountChange.
Priority *int32
```

Retain `app.CompatProvider.Priority` and `app.CompatProviderUpdate.Priority` as their existing compound creation/update inputs. Both consume the same metadata/runtime helpers. The root `ProviderAccount.priority` becomes required; `CompatProviderDetails.priority` is removed.

Use shared gateway helpers with these names and contracts:

```go
func accountPriority(auth *coreauth.Auth) int32
func priorityFromMetadata(metadata map[string]any) int32
func applyAccountPriority(auth *coreauth.Auth)
func setAccountPriority(auth *coreauth.Auth, priority int32)
```

`accountPriority` describes the effective runtime attribute, falling back to metadata when no attribute exists. `priorityFromMetadata` accepts the existing decimal string and integral JSON numeric values within int32 bounds; absent/invalid values are neutral. `applyAccountPriority` restores runtime state without inventing another role field. `setAccountPriority` writes the canonical decimal metadata value and runtime attribute together. Avoid duplicate parsing/applications in the compatible-only path.

Frontend client-only helpers:

```ts
export const ROLE_PRIORITIES = { preferred: 1, normal: 0, reserve: -1 } as const;
export type RoutingRole = keyof typeof ROLE_PRIORITIES | "custom";
export function routingRole(priority: number): RoutingRole;
export function priorityValue(input: string): number | undefined;
```

`priorityValue` validates a nonblank whole number in the int32 range. These are UI/domain helpers, not hand-written API types. API types still come only from generated schemas.

`RoutingRoleSelect` is controlled by `priority: number`, `onChange: (priority: number) => void`, a translated accessible `label`, and optional `disabled`. It lists the three presets and a disabled current custom-value option when needed. It does not silently replace a custom value.

`AccountRoutingFields` is a controlled editor with string `value`, string `onChange`, and an optional translated error. Its normal view uses the presets; an advanced disclosure permits a custom integer. Both existing drawers own whether the draft was actually touched.

---

### Task 1: Generalize sealed account priority and lifecycle

**Files:**
- Create: `backend/internal/infra/gateway/priority.go` and `priority_test.go`.
- Modify: `backend/internal/app/ports.go`.
- Modify: `backend/internal/app/providers/providers.go` and `providers_test.go`.
- Modify: `backend/internal/infra/gateway/credential_store.go`, `credential_store_test.go`, `service.go`, and `compat.go`.
- Modify impacted lifecycle tests: `backend/internal/infra/gateway/compat_headers_test.go` and `proxy_test.go` only where shared priority behavior is exercised.
- Regenerate: `backend/internal/app/mocks/vendor_accounts.go` with the pinned generator.

**Consumes:** Existing sealed store, account locking, `Auth.Clone`, proxy/relogin preservation, and compatible metadata.
**Produces:** Shared priority port, helpers, generic update use case, and persistence across all managed stored account kinds. Keep the old nested response field temporarily until the coordinated contract cutover in Task 2; do not publish this intermediate state separately.

- [ ] **Step 1: Establish the failing lifecycle proof.** Add tests for Claude and Codex metadata and retain the compatible restart test. Use synthetic access tokens and a far-future expiry, never real OAuth grants. Reuse `claudeGrant`, `startProduction`, `startCompat`, and the existing sealed-store helpers.

A concrete reauthentication regression, in gateway package:

```go
func TestReSignInKeepsTheAccountsPriority(t *testing.T) {
    srv, manager := startProduction(t)
    grant := claudeGrant(t)
    _, err := srv.gateway.AddAccount(t.Context(), grant)
    require.NoError(t, err)
    require.NoError(t, srv.gateway.SetAccountPriority(t.Context(), grant.ID, -1))

    again := claudeGrant(t)
    again.Metadata["access_token"] = "fresh-synthetic-access-token"
    _, err = srv.gateway.AddAccount(t.Context(), again)
    require.NoError(t, err)
    held, ok := manager.GetByID(grant.ID)
    require.True(t, ok)
    require.Equal(t, "-1", held.Attributes["priority"])
    require.Equal(t, "fresh-synthetic-access-token", held.Metadata["access_token"])
}
```

Also exercise explicit zero after a custom value, role editing while disabled, proxy/disabled preservation, persistence/reload for Codex and Claude, and a refresh-like token metadata update without dropping priority. Add read cases for absent, decimal string, integral numeric, invalid and out-of-range metadata; verify real reconstructed accounts, not only parsing function outputs.

- [ ] **Step 2: Observe the failure.** Run:

```bash
go test ./internal/infra/gateway -run 'Test.*Priority|TestReSignInKeepsTheAccountsPriority' -count=1
```

Missing fields/methods are expected first; after adding types/generation, observe a behavioral failure before implementing the lifecycle fix.

- [ ] **Step 3: Implement one shared representation.** Move the priority metadata key/parsing out of the compatible-only path. Use the canonical `priority` key and decimal string on writes. Runtime selection reads the same `priority` attribute. Restore it for every credential in `authFromRow`; keep headers, Codex plan extraction, and compatible attributes intact. Remove redundant compatible-only priority application so one load does not parse/apply the same setting twice.

Critical setter content:

```go
func setAccountPriority(auth *coreauth.Auth, priority int32) {
    value := strconv.FormatInt(int64(priority), 10)
    if auth.Metadata == nil {
        auth.Metadata = make(map[string]any)
    }
    if auth.Attributes == nil {
        auth.Attributes = make(map[string]string)
    }
    auth.Metadata[metadataPriority] = value
    auth.Attributes[metadataPriority] = value
}
```

`applyAccountPriority` restores the runtime attribute when priority metadata exists, without forcing a new stored key merely because an old record was read. If no priority was ever assigned, use upstream's neutral default rather than allocating a redundant attribute. `accountPriority` reports the attribute actually used by the selector. Keep compatible registration entries projected from the same value.

- [ ] **Step 4: Implement administrator updates without replacing account state.** `SetAccountPriority` follows the existing gateway locking/account lookup pattern, clones the held auth, writes only routing priority, saves through the sealed store, and updates the manager. Keep error ordering truthful, and refresh compatible registration configuration where required without resetting the selector/bindings or unrelated model state. Do not route a role update through an account enable/disable operation.

Extend `providers.Service.Update`: an optional priority makes the patch nonempty, is applied through the shared port, and is audited as `provider.account_priority` with account id, policy provider, and numeric priority only. Validate the complete request before touching anything. Omission does not write a default.

Preserve the existing administrator-assigned priority when the same stored credential is reauthenticated. Extend the current same-key preservation loop in `addLocked`, not the public login wizard. A truly new OAuth identity remains neutral.

- [ ] **Step 5: Verify and commit.** Regenerate mocks through `make generate` after the port change; do not edit generated mock code. Run focused provider/lifecycle tests and the affected package tests. Keep the feature buildable and commit the shared lifecycle implementation after its tests pass.

### Task 2: Cut over account API responses and prove native subscription selection

**Files:**
- Modify: `backend/api/openapi.yaml`.
- Modify: `backend/internal/app/ports.go`, `providers/compat.go`.
- Modify: `backend/internal/iface/http/admin_providers.go`, `admin_providers_test.go`, `admin_compat_headers_test.go`, and `admin_compat_test.go` where response assertions change.
- Modify: `backend/internal/infra/gateway/service.go`, `compat.go`, and `compat_headers_test.go`.
- Extend: `backend/internal/infra/gateway/priority_test.go`.
- Regenerate: backend API output/mocks and frontend OpenAPI/types through their existing commands.

**Consumes:** Task 1 shared account priority.
**Produces:** Root required `ProviderAccount.priority`, generic optional patch input, no nested duplicate response property, and evidence of native selection for two Codex identities.

- [ ] **Step 1: Write contract/security regressions.** Check that an account-list response includes priority for a subscription account and a compatible account; compatible details must not contain the old nested property or header values. Test a priority-only patch with explicit zero, denied/non-admin access, and a patch omitting priority while changing another setting. These must protect behavior or boundaries, not merely echo mock arguments.

Schema additions:

```yaml
# ProviderAccount.properties, and add priority to its required list.
priority:
  type: integer
  format: int32
  readOnly: true

# Existing generic provider PATCH properties.
priority:
  type: integer
  format: int32
  minimum: -2147483648
  maximum: 2147483647
  description: Omission preserves the current account priority.
```

Delete `priority` from the nested compatible detail schema and its required list. Retain the existing compatible create/update inputs.

- [ ] **Step 2: Implement and migrate consumers.** Set root API priority from `app.VendorAccount.Priority`. Remove `app.CompatDetails.Priority`, its mapping, and compatible audit reads of that removed location; audit reads the shared account field instead. Update lifecycle assertions to the root field. Do not retain a re-export, response alias, or duplicate setting.

- [ ] **Step 3: Exercise the real manager's choice for two ChatGPT identities.** Use the existing `faketest.Executor` with provider `codex`, plus the `registerClient` helper. Synthetic Codex accounts support the same unique model; no actual OAuth network request is made. Register the fake executor after account setup if the service initially registered its native executor.

Use SDK-selected metadata rather than inventing a new recording fake:

```go
manager.RegisterExecutor(&faketest.Executor{Provider: "codex", Payload: []byte(`{"ok":true}`)})
metadata := map[string]any{}
_, err := manager.Execute(t.Context(), []string{"codex"},
    cliproxyexecutor.Request{Model: model},
    cliproxyexecutor.Options{Metadata: metadata})
require.NoError(t, err)
selected := metadata[cliproxyexecutor.SelectedAuthMetadataKey]
```

Assert two equal neutral accounts are both selected under default round-robin for independent sessions. Set one preferred through the actual gateway setter and assert cold selections choose it; make it unavailable and assert the other is selected. With session affinity enabled, change priority without resetting the manager and prove an existing available binding stays put while a new session honors the new priority. Keep existing access/model-eligibility regressions in the gate suite.

- [ ] **Step 4: Generate and verify.** Run in backend:

```bash
make generate
go test ./internal/app/providers ./internal/iface/http -run 'Provider|Compat' -count=1
go test ./internal/infra/gateway -run 'Priority|ReSignIn|CompatProviderHeaders' -count=1 -race
```

Then run `npm run sync:contract` in the sibling frontend. Update its root fixture factory with neutral priority and migrate nested detail literals. Move existing compatible form and mock reads of saved priority to `account.priority` now, before replacing the numeric editor with roles in Task 3, so this cutover stays type-safe. Do not keep two response shapes. Commit the backend cutover and the paired generated frontend/read-site changes as independent repository commits.

### Task 3: Build shared role presentation and integrate both drawers

**Files:**
- Create: `frontend/src/entities/provider/routing.ts`, `RoutingRoleSelect.tsx`, `AccountRoutingFields.tsx`, and `AccountRoutingFields.module.css`.
- Modify: `frontend/src/features/account-proxy/AccountDrawer.tsx` and `AccountDrawer.test.tsx`.
- Modify: `frontend/src/features/compat-provider/CompatDrawer.tsx` and `CompatDrawer.test.tsx`.
- Modify: `frontend/src/shared/i18n/en.ts`, `ru.ts`.
- Update required account fields in `frontend/src/test/server.ts`, `src/mocks/browser.ts`, `src/entities/provider/StatusDot.test.tsx`, and provider-page fixtures.

**Consumes:** Task 2 root account contract and existing compound compatible inputs.
**Produces:** The shared frontend helper/component interfaces defined above and drawer role editing without stale writes or header/proxy loss.

- [ ] **Step 1: Write failing interaction regressions.** Extend the existing drawer fixture with root account overrides, default `priority: 0`. Select Reserve for a subscription and save, expecting a priority update without supplying/replacing the saved proxy. Open a custom-priority account, edit only its proxy, and verify priority is omitted. Exercise the equivalent compatible form while saved headers remain preserved.

Example scenario for the subscription drawer, using the generated contract-typed server:

```tsx
import type { operations } from "../../shared/api/schema";

type AccountPatch = operations["updateProviderAccount"]["requestBody"]["content"]["application/json"];

it("changes an account role without replacing its stored proxy", async () => {
  const { user, onClose } = drawer();
  const sent: AccountPatch[] = [];
  server.use(http.patch("/api/admin/providers/{accountId}", async ({ request, response }) => {
    const body = await request.json();
    sent.push(body);
    return response(200).json(fixtures.providerAccount({ priority: body.priority ?? 0 }));
  }));
  await user.selectOptions(screen.getByRole("combobox", { name: en["routing.usage"] }), "-1");
  await user.click(save());
  await vi.waitFor(() => expect(onClose).toHaveBeenCalledOnce());
  expect(sent[0]).toMatchObject({ priority: -1 });
  expect(sent[0]).not.toHaveProperty("proxy");
});
```

Use the generated operation-derived alias above, not a hand-written API request type. Add tests for dirty/discard, custom integer preservation, invalid custom input, and a role selected after typing another field.

- [ ] **Step 2: Observe failure and implement preset mapping.** Add exactly the three roles and the custom presentation state. The parser content is:

```ts
export function priorityValue(input: string): number | undefined {
  const value = Number(input);
  return input.trim() !== "" && Number.isInteger(value) &&
    value >= -2147483648 && value <= 2147483647 ? value : undefined;
}
```

Keep API types imported from the generated schema. Use the existing `Select`, `TextField`, and CSS Module conventions. The basic control hides numbers behind translated role labels. A custom value remains labeled custom and is editable only in an explicit advanced disclosure in a drawer; selecting a preset is deliberate replacement.

- [ ] **Step 3: Integrate one shared controlled editor.** In each drawer, use a touched draft (`string | null`, where null means untouched) rather than always copying the current root priority into every Save. Compute the effective display from the current account while untouched. Save priority only after a real user edit and a successful range check. Do not submit an unchanged proxy merely because a role changed. Preserve the current compatible creation/update operation so one Save stays one compound operation.

Remove the raw priority field from compatible connection Advanced. Keep `CompatHeaders` there, with all its preserve/replace/clear, destination, removed-key/discovery, and cache-secrecy behaviors. Move priority-related translations into a shared `routing.*` namespace and remove obsolete compatible-only numeric UI strings after callers migrate.

- [ ] **Step 4: Verify and commit.** Run:

```bash
npx vitest run src/features/account-proxy/AccountDrawer.test.tsx src/features/compat-provider/CompatDrawer.test.tsx
npx tsc -b
```

Do not repin wording-only tests to new copy. Preserve security and user-behavior regressions while changing their interaction from a numeric field to roles. Commit the shared presentation and working drawer integrations.

### Task 4: Add inline role controls and move the existing sticky setting

**Files:**
- Create: `frontend/src/features/provider-routing/AccountUsageControl.tsx`, `SessionAffinityControl.tsx`, and a focused CSS Module if needed for the routing panel/control layout.
- Modify: `frontend/src/pages/admin/providers/AdminProvidersPage.tsx`, its CSS Module, and tests.
- Modify: `frontend/src/pages/admin/settings/AdminSettingsPage.tsx` and tests.
- Extend focused action tests under `frontend/src/features/provider-routing/`.
- Reuse: `src/entities/provider/providers.ts`, `src/entities/settings/settings.ts`, existing query client and shared UI.

**Consumes:** Shared controlled role selector, root priority, generic account PATCH, `settingsQuery`, and the existing settings update response.
**Produces:** Visible routing roles for every row/card and exactly one ordinary sticky-session control on Providers.

- [ ] **Step 1: Write failing page regressions.** Render Providers with two ChatGPT accounts, a Claude account, and a compatible source; select a role on each kind and check the resulting server-backed UI state. Cover an intentionally delayed response (only its control disabled), a failed save with visible stable error, and role editing on a disabled account without enabling it. Ensure row events do not accidentally open a drawer when using the role control.

Add a sticky test with saved `sessionAffinity: false`, toggle it on, and require that the request body is only the intended field patch:

```ts
expect(requestBody).toEqual({ fields: { sessionAffinity: true }, dryRun: false });
```

Check the authoritative returned state, not just the request. In Settings tests, save a changed retry count and assert `fields` does not include `sessionAffinity`, even when the loaded document contained it. Retain advanced YAML editing and check/apply behavior for the other settings.

- [ ] **Step 2: Implement immediate account actions.** `AccountUsageControl` PATCHes only `{ priority }`. On success update the matching account by id in `providerAccountsQuery` or invalidate/refetch it. On failure show `useErrorMessage()` output and invalidate uncertain state. Do not optimistically mutate other rows, disable the account, clear quota state, or store anything in localStorage.

Integrate into `AccountRow` with a translated account-specific accessible label. Add the corresponding visual header column in both `Group` calls. Preserve `ProxyCell`, `QuotaMeters`, `ModelTags`, enabled/edit/remove controls, and responsive cards. If the existing 60rem cap no longer fits, increase this page's cap and adapt its grid deliberately; do not hide existing capability columns to fit the mockup.

- [ ] **Step 3: Reuse the settings API for one immediate control.** `SessionAffinityControl` queries `settingsQuery`, renders pending/error state, and uses:

```ts
client.PUT("/api/admin/settings", {
  body: { fields: { sessionAffinity: on }, dryRun: false },
});
```

On success set `settingsQuery` data to `result.settings`. Render the toggle from server data and disable it during save, following `CostsVisibility`'s established pattern. Invalidate state when a result is uncertain. Explain that the setting is global, defaults on, and retains available same-model bindings; avoid promising a specific balancing algorithm for a non-default strategy.

- [ ] **Step 4: Remove duplicate Settings ownership.** Delete its sticky draft, old toggle/hint block, success-reset setter, and typed form submission of `sessionAffinity`. Do not change the backend default or YAML key. Remove its now-unused `Toggle` import only if no remaining component in that file uses it. Keep the same API/query entity for both pages so YAML changes refresh the provider toggle.

- [ ] **Step 5: Verify and commit.** Run focused action/page/drawer/Settings tests and TypeScript. Check desktop and narrow CSS layouts in the browser later in Task 5. Commit the complete visible provider routing UX and Settings cutover together, not an orphan toggle that leaves stale form writes behind.

### Task 5: Actual-surface proof, documentation, review and PR updates

**Files:**
- Modify: backend/frontend READMEs and the new design/plan execution receipts.
- Private infrastructure notes only if a new live-stack verification is performed.
- No committed probe code, mockup server content, private coordinates or credentials.

**Consumes:** Complete working shared contract, lifecycle behavior, and role-based UI.
**Produces:** Exercised acceptance, updated documentation and updates to the existing PRs, without merge or production changes.

- [ ] **Step 1: Exercise the actual surface.** Run the built frontend against the real updated API in an isolated environment. Use synthetic subscription identities, not copied OAuth grants. At desktop and narrow widths, change roles in the list and both editors; save a custom value without changing it during another edit; toggle sticky sessions; fail a save and observe recovery; confirm quotas/proxies/model summaries/actions remain usable. A static mockup or Vitest alone is not acceptance. Observe and capture the actual UI, then close owned tabs and services.

- [ ] **Step 2: Prove routing behavior without live subscription duplication.** The permanent native-manager tests cover two ChatGPT identities and priority changes. Keep the existing OpenCode Go on-wire and failover regressions passing after shared-priority extraction. If repeating real Go/DeepSeek probes, retrieve permitted keys programmatically into process memory, never through a raw secret-bearing file read. Keep the production stack unchanged and remove owned probe containers, volumes, temporary keys and files after proof.

- [ ] **Step 3: Update documentation after smoke proof.** Describe universal role controls, the `1/0/-1` API mapping, preserved custom priorities, root response shape, the single provider-page sticky switch, preserved explicit false/default true behavior, default round-robin versus custom strategies, and same-model eligibility. Update the Go recipe so a visually Reserve official source uses `-1`; do not silently rewrite existing saved priorities. Mark the older compatible-only design as superseded where necessary.

- [ ] **Step 4: Request read-only review and fix confirmed findings.** Backend and frontend are independent review domains; coding remains sequential as the user requested. Review mutation/persistence ordering, refresh/relogin, nil/zero semantics, session retention, generic versus compound update consistency, custom draft intent, removal of stale sticky form writes, and responsive/accessibility behavior. Reviewers skip builds, tests, lint and edits; the integration owner runs proof once after corrections.

- [ ] **Step 5: Run final gates.** In backend:

```bash
make generate
make build
go vet ./...
make test
make lint
scripts/check-readme-compose.sh
```

In frontend:

```bash
npm run sync:contract
npm run build
npm test
```

Compare the OpenAPI copies from the sibling worktree parent with `cmp backend/api/openapi.yaml frontend/api/openapi.yaml`. Check generated-output stability and staged changes for real secrets before committing/pushing. Do not claim CI success from these local commands; observe the PR checks separately.

- [ ] **Step 6: Commit, push existing branches, and report links.** Keep independent commits in the two repositories, push `feat/opencode-go`, and update PR #47/#29 descriptions with the new generic roles and actual verification. Do not force-push, merge or bump release pins. Confirm PR state/checks and report the two actual URLs, exercised smoke, and any material verification limitation. Preserve worktrees for review feedback.

## Plan self-review

- [x] Spec coverage: shared metadata/lifecycle (1), clean API cutover/native selection (2), reusable presets/custom drafts (3), page/global switch/stale-write prevention (4), real surface/docs/review/delivery (5).
- [x] Shared fields, helper signatures, role values and response locations are consistent across tasks.
- [x] No new selector, role storage column, API role enum or duplicate toggle is planned.
- [x] Header security, explicit sticky false, model eligibility and established bindings remain explicit acceptance requirements.
- [x] Real subscription duplication and secret-bearing transcript reads are prohibited; mockup content stays ignored.
