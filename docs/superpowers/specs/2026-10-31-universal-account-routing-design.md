# Universal account routing and role-based provider management

Date: 2026-10-31
Status: Written specification approved by the user; sequential implementation authorized.

## Goal and scope

Extend the OpenCode Go work in backend PR #47 and frontend PR #29 so routing priority is a shared account capability, not an OpenAI-compatible-only setting. Make selection understandable through routing roles for ChatGPT, Claude, and every account type the admin interface manages.

The user selected visual option A: understandable roles instead of numeric priority. The selected mockup is a design artifact, not a running implementation. This specification supersedes the compatible-only priority response shape and Advanced numeric-priority UI in `2026-10-31-opencode-go-routing-design.md`. Its secret-header security boundary and native failover requirements remain in force.

## Existing behavior to preserve

- The app already enables session affinity when the stored document does not explicitly set it. An explicit `routing.session-affinity: false` remains false.
- The existing settings page already exposes a Sticky sessions toggle, with an English/Russian label. Do not add another defaulting mechanism or force-enable a setting explicitly disabled by an administrator.
- CLIProxyAPI v8.0.38 already implements account priority, eligible-model filtering, routing strategy, cooldown, failover, and session affinity. Continue using it; do not build a second selector or retry system.
- A bound session/model continues on its available account even if a higher-priority source becomes available. Priority applies when choosing a new account, not as a command to interrupt an existing conversation.
- Shared aliases still require the user's policy to cover every serving provider. Routing roles do not grant access, override spend limits, or represent monetary weights.

## Routing roles

Use UI presets over the existing integer priority, without a second persisted role field:

| UI role | Stored priority | Selection meaning |
| --- | --- | --- |
| Preferred / Предпочтительный | `1` | Chosen before lower-priority eligible accounts. |
| Normal / Обычный | `0` | Default for a newly added account. Equal-priority accounts use the configured selection strategy. |
| Reserve / Резервный | `-1` | Chosen when no higher-priority eligible source can serve the request. |

The comparison is always among sources that support the requested model/alias and pass existing availability checks. A reserve account still serves a model when it is the only eligible source. Several preferred accounts can share traffic just as several normal accounts can.

The default round-robin strategy distributes new selections across equal-priority accounts; with sticky sessions enabled, continuation requests remain bound. Do not promise a 50/50 token or quota split. Preserve non-default strategies such as fill-first or weighted-round-robin, and phrase UI guidance so it does not promise round-robin when a different strategy is configured.

Existing custom integer priorities must not be silently converted to a preset. Display a Custom priority / Свой приоритет state for non-preset values, with the existing integer available in the account's advanced routing editor. Changing another account field preserves that value. Choosing a preset explicitly replaces it. The ordinary path shows roles, not numbers.

## Interface: provider page

Keep the existing provider page and its subscription/compatible groups. Retain account status, quota information, proxy information, model summaries, enabled state, editing, and removal. Adjust responsive layout as needed; the role control must not silently replace existing capabilities.

Add the same Usage / Использование role selector to every account row/card, including subscription accounts. The selector's accessible name identifies the account. It also appears in both account editors, outside connection-header Advanced settings. New compatible providers can select a role during creation; OAuth sign-in keeps its existing wizard and creates a normal account, whose role can then be edited.

Inline changes save immediately through the generic account update endpoint. Disable only the affected control while its request is pending. Make failure visible and refresh authoritative server state when the result is uncertain; do not show a failed save as successful. Editing the role of a disabled or temporarily unavailable account is allowed and does not enable it.

In account drawers, role edits participate in the existing Save and unsaved-change behavior. Submit priority only when the user actually edits it; changing a proxy, model, or header must not resubmit a stale role unintentionally. Preserve query-client secret handling and mutation cleanup from the existing forms.

Keep custom HTTP headers under compatible connection Advanced settings. Do not present headers as general ChatGPT/Claude sign-in settings, expose their stored values, or intermingle them with routing roles.

## Interface: sticky-session control

Move the existing typed Sticky sessions control to a compact panel at the top of Providers. Use the user-facing label Keep a conversation on one account / Закреплять диалог за аккаунтом, with supporting text about the same model, account availability, and fallback.

- There is one ordinary UI control, not independent copies in Providers and the Settings typed form.
- Reuse the existing settings API, stored configuration key, default, and TanStack Query state. Do not add a new endpoint or independent localStorage setting.
- Save immediately using a field patch that names only `sessionAffinity`. Follow the app's existing immediate global-toggle pattern: pending state, stable translated errors, and authoritative state on completion.
- Remove the old control, sticky draft, and implicit `sessionAffinity` submission from the Settings typed form. Saving unrelated settings must not write an old sticky value over a change made on Providers.
- The advanced YAML editor remains available and reflects the same setting. Changing YAML must update the provider-page control when its settings query is refreshed.
- Keep the existing on-by-default rule. Do not reset a deliberate false value during a deployment, restart, account change, or unrelated settings edit.

No extra Check/Apply sequence is introduced for the provider-page toggle; no model-traffic operation is required to save it.

## Backend and API contract

Make effective priority part of `app.VendorAccount` and the root `ProviderAccount` response, with required signed-int32 `priority` and neutral default `0`. Remove the duplicate priority field from `CompatDetails` / `CompatProviderDetails` and migrate every response consumer. Header names remain inside compatible-provider details because they are connection-specific.

Extend the existing generic account patch with optional signed-int32 `priority`, alongside optional disabled/proxy changes. Omission preserves it. Expose a matching shared account port/adapter operation; no provider-specific switch is needed to decide whether a stored subscription account has a routing role.

Retain optional priority in compatible creation and compound compatible updates: these forms must save their edited connection/model settings and role through their existing operation rather than splitting one Save into unrelated requests. Both paths use the same metadata representation, validation, and runtime application. This is one setting with two necessary write contexts, not a compatibility alias or duplicate source of truth.

Keep the accepted range `-2147483648` through `2147483647`, including explicit zero and negative values. UI presets are not a restriction on the integer API. No new role enum, role database column, schema migration, or new public model-route/group resource is introduced.

Edit backend OpenAPI first, regenerate pinned backend types/mocks, then synchronize and regenerate the frontend contract. Migrate all call sites and fixtures; do not hand-edit generated output or preserve the obsolete nested response field through a shim.

## Persistence and runtime lifecycle

Persist the one account priority in the existing sealed credential metadata and apply its runtime routing attribute for every managed account kind. Generalize the compatible-only priority helper to the shared account path. Keep compatible model-registration configuration consistent with the same effective value.

Priority changes must preserve tokens, proxy mode/credentials, disabled state, model definitions, quota/cooldown state, and session-affinity bindings. Do not replace an account wholesale with a minimal object containing only the role. Serialize updates through the existing gateway synchronization and preserve truthful error handling if persistence/runtime application fails.

The chosen role survives:

- saving a different account setting;
- an OAuth token refresh or supported credential serialization;
- reauthentication of the same stored account;
- a gateway restart and credential reload.

A genuinely new account starts normal. Reauthentication must not silently restore the login wizard's default over an existing administrator-assigned role. Do not clone real OAuth grants to test refresh behavior.

Role changes do not disable/enable accounts, clear cooldowns, force new sessions, or bypass model/access eligibility. Keep upstream priority/session semantics intact.

## Data flow and responsibility

- The app account response and generic update use case own the shared priority contract and administrator authorization.
- The gateway account adapter and credential loader own sealed persistence and runtime attributes.
- CLIProxyAPI owns actual source selection, cooldown, failover, and session bindings.
- Frontend provider-entity presentation helpers translate integer values into preset/custom labels. A shared controlled selector is reused by row controls and account drawers.
- Provider-routing actions own inline mutations and the provider-page global toggle. Reuse existing query options and own UI controls; introduce no UI kit, form library, drag-and-drop dependency, or parallel client-state store.

Use a focused shared routing unit rather than copying role conversion/validation into each provider editor. Follow existing feature-sliced imports. Preserve responsive cards, keyboard operation, and pending/error behavior in English and Russian.

## Verification and acceptance

Permanent regressions must cover consumer-visible behavior, not serialized field echoes or source-text assertions:

1. Roles can be set on ChatGPT/Codex, Claude, and compatible stored accounts; explicit zero/negative values work and omitted priority preserves the saved value.
2. The assigned priority survives credential reload, token metadata updates, reauthentication of the same stored identity, and unrelated account changes without losing other metadata/secrets.
3. Two ChatGPT accounts at the same default priority remain eligible for default round-robin; preferred/normal/reserve selection and unavailable-source fallback use native upstream behavior.
4. A priority edit does not break an established available session binding, clear cooldowns, or route a model to an unsupported account. Existing access restrictions remain enforced.
5. The provider page and both editor kinds use the same preset/custom interpretation. Changing another field preserves a custom numeric priority; selecting a role replaces it intentionally.
6. Inline and drawer edits handle pending/failure states, disabled accounts, keyboard selection, and unsaved changes. Existing header secrecy and cache cleanup regressions remain valid.
7. Sticky sessions still default on when unset and remain off when explicitly disabled. Its single ordinary UI control persists through the existing API; unrelated typed Settings saves do not overwrite it, and YAML changes are reflected after refresh.
8. The actual browser surface is exercised at desktop and narrow widths, including immediate role/toggle changes, a failed save, and both account editor types. Mockup images alone are not acceptance.

Use the repository's existing strict mocks, real Postgres test helpers, and permitted vendor fake. Test two subscription identities with synthetic credentials, never duplicated real OAuth grants. Where the real Go/DeepSeek smoke is repeated, retrieve the already authorized credential only into process memory, never print it or read a secret-bearing configuration into the transcript. Keep the existing production stack unchanged and clean up owned probe resources.

Run backend build, vet, race tests, pinned lint, generation checks and README/compose consistency; run frontend build, tests, contract synchronization and actual-surface smoke. Verify both OpenAPI copies match. Review the completed change before updating the two existing PRs. Do not merge or change release image pins.

## Non-goals

No new routing engine, automatic quota equalization, guaranteed usage split, weighted role semantics, per-user preferred vendor, model substitution, model-route configuration subsystem, new credential import workflow, header editor for OAuth accounts, or unrelated provider-page redesign. Do not add an always-on sticky override or a second independently stored toggle.
