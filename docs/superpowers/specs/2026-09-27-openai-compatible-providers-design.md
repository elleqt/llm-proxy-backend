# OpenAI-compatible providers — design

Status: approved in brainstorming, 2026-09-27. Spans `backend` and `frontend`.

## Goal

An administrator adds, edits, disables and removes any number of
OpenAI-compatible providers (any vendor exposing the OpenAI API: a hosted
vendor, a local Ollama, a router) from the admin panel. Changes take effect
live, without a restart. Nothing in code names a particular vendor.

Also: a "sticky sessions" toggle in the admin settings, on by default.

## Decisions

| Topic | Decision |
|---|---|
| Where configured | Admin panel, applied live. |
| Number of providers | Unlimited; each is its own entry with a unique name. |
| API keys per provider | 0 or 1. Empty = keyless (local vendors). |
| Model list | Discovered from `{baseURL}/models`, admin picks a subset and optional aliases; manual entry when a vendor has no `/models`; stored, re-discovered on demand. No auto-sync. |
| Storage | Reuse `vendor_credentials`; no migration, no second store. |
| Same model name on several providers | Allowed: upstream load-balances across them. The UI warns that access then needs grants on every provider serving the model (the policy rule is unchanged and stays fail-closed). A `prefix` or per-model alias keeps providers apart when wanted. |
| Sticky sessions | Typed settings field `sessionAffinity` over upstream `routing.session-affinity`; default on; global across all providers. TTL stays upstream's default (1h). |

## Background: why live add needs gateway work

Upstream builds `openai-compatibility` credentials from configuration only on
`Run` (`sdk/cliproxy/service_lifecycle.go` → `registerConfigAPIKeyAuths`). The
reload callback the gateway drives through `PushConfig` is
`applyWatcherConfigUpdate`, which passes `synthesizeConfigAuths=false`
(`sdk/cliproxy/service_config.go`). Today the list is boot-only
(`boot.Options.Compatibility` → `ownedConfig`), and the settings document
refuses the key (`internal/app/settings/settings.go` `ownedKeys`).

Upstream needs two things to serve a compat provider:

1. A `cfg.OpenAICompatibility` entry: model registration
   (`sdk/cliproxy/service_models.go`) and the executor
   (`resolveOpenAICompatConfigForAuth`) find it by `compat_name`. The
   `config_index` lookup applies only to config-sourced auths; ours are
   Postgres-sourced, so the name lookup applies and removing one entry does not
   shift the others.
2. A `coreauth.Auth` whose `Attributes` carry `compat_name`, `provider_key`,
   `base_url` and (optionally) `api_key`. The executor reads `base_url` and
   `api_key` from `Attributes` only.

## Storage

One `vendor_credentials` row per provider:

| column | value |
|---|---|
| `id` | `openai-compatible-<name>` (name lower-cased). The primary key makes a duplicate name `app.ErrConflict`. |
| `provider` | `openai-compatibility` |
| `sealed` | `credentials.Sealer` over the canonical JSON below; AAD is the row id, as for every row. |

Sealed JSON:

```json
{
  "type": "openai-compatibility",
  "compat_name": "acme",
  "base_url": "https://api.example.com/v1",
  "api_key": "…",
  "prefix": "team2",
  "models": [{"name": "model-a", "alias": "a"}],
  "disabled": false
}
```

`api_key` and `prefix` are omitted when empty. The row is the single source of
truth: the pushed `OpenAICompatibility` entry and the Auth attributes are both
derived from it.

Name rules: `^[a-z0-9][a-z0-9._-]{0,62}$`, immutable after creation (it is the
policy name; a rename would silently re-point grants). Reserved names are
refused by the existing `compatNameRefused` / `ErrCompatName`; the service
checks before saving so the admin gets `invalid_input` on `name`, not a failed
push.

Base URL: `http` or `https`, absolute, no userinfo, no query or fragment.
Loopback and private addresses are allowed (local vendors are a real case; the
endpoint is admin-only).

## Gateway

- `authFromRow`: when the row's provider is `openai-compatibility`, rebuild
  `Attributes` `compat_name`, `provider_key` (`openai-compatible-<name>`),
  `base_url`, `api_key` (when set) and `Prefix` from the sealed metadata, on
  every load. `Save` persists `Metadata` only, so without this a restart loses
  them.
- OAuth-only paths skip these rows: quota signals, email/label derivation,
  refresh, `carriesToken` (only reached when `Storage != nil`; compat auths
  have none).
- `compatEntries(accounts)` builds `[]OpenAICompatibility` from the held
  compat accounts (disabled ones excluded; no `APIKeyEntries`, the key is on
  the Auth). Every configuration the gateway applies — boot, `PushConfig`,
  `reapplyLocked` — carries these entries as a gateway-owned part, the way
  `overlayOwned` carries `auth-dir` today. The settings document keeps
  refusing `openai-compatibility`, and the diff keeps hiding it.
- Create / edit / disable / remove go through the existing account path
  (`AddAccount`, the update path with reseal, `SetDisabled`, `removeLocked`),
  each followed by `reapplyLocked`, which registers or unregisters models live.
- `admit` already refuses reserved compat names; it now sees the derived
  entries too.
- `boot.Options.Compatibility` stays for e2e fakes; derived entries are
  appended to it.

## App layer

New `app/compatproviders` service (admin-only, audited like `providers`):

- `Create(actor, CompatProvider)` → `VendorAccount`
- `Update(actor, id, CompatProviderUpdate)` → `VendorAccount`; `apiKey`
  absent keeps the stored key, `clearApiKey: true` removes it.
- `Discover(actor, baseURL, apiKey?)` → `{models []string, conflicts map[model][]provider}`;
  saves nothing. `conflicts` comes from `ModelCatalog.Models()`.

Disable and remove reuse `providers.Service`. Audit records never carry the
key.

New port `app.ModelDiscoverer` (implemented in `infra/gateway` or a small
`infra/compatdiscovery`), guardrails:

- 10 s timeout, response body capped at 1 MiB, JSON `{"data":[{"id":…}]}`.
- Redirects followed only to the same scheme+host; otherwise refused.
- Uses the running configuration's `proxy-url`, the same route traffic takes.
- The vendor's error body and the request URL are never returned or logged.
  Failures map to stable codes in `appRefusals`: `provider_unreachable`
  (network, timeout, non-JSON, oversize, 5xx), `provider_auth_failed`
  (401/403).

## Web API (spec-first)

`api/openapi.yaml`:

- `POST /api/admin/providers/compat` — body `CompatProviderRequest{name, baseURL, apiKey?, prefix?, models[]}` → 201 `ProviderAccount`. 409 `conflict` on a taken name.
- `PUT /api/admin/providers/compat/{accountId}` — body `CompatProviderUpdate{baseURL, apiKey?, clearApiKey?, prefix?, models[]}` → 200 `ProviderAccount`. 404 for a non-compat or unknown id.
- `POST /api/admin/providers/compat/discover` — body `CompatDiscoverRequest{baseURL, apiKey?}` → 200 `CompatDiscoverResult{models[], conflicts{}}`.
- `ProviderAccount.compat?` = `{name, baseURL, prefix?, hasApiKey, models[{name, alias?}]}`. The key itself is never in any response.
- `SettingsFields.sessionAffinity: boolean`.
- Error codes `provider_unreachable`, `provider_auth_failed`.

Routes go into `registerAdminProviders` and the `adminOnly` table.

## Sticky sessions

- `settings.Patch.SessionAffinity *bool` writes `routing.session-affinity`
  into the stored document at the YAML node level (the upstream field is
  `bool,omitempty`, so a struct round-trip would drop `false`).
- Default on: a boot-time upgrade step writes `routing.session-affinity: true`
  into a stored document that has no such key, once. From then on the stored
  value is read literally. A fresh install's seeded document gets the key too.
- Global: it changes routing for Claude and ChatGPT accounts as well.

## Frontend

- `entities/provider/providers.ts`: `ProviderAccount.compat`; `accountName`
  shows `compat.name`.
- `features/compat-provider/CompatProviderForm.tsx` (new): name (read-only on
  edit), base URL (placeholder `https://api.example.com/v1`), API key (password
  input; on edit empty = keep, checkbox "remove key"), prefix; "Discover
  models" → checklist with alias inputs and a per-model conflict warning;
  manual model add.
- `AdminProvidersPage`: "Add OpenAI-compatible" next to the OAuth wizard;
  "Edit" on compat rows; disable/remove unchanged; empty quota cell.
- `AdminSettingsPage`: "Sticky sessions" toggle → `fields.sessionAffinity`.
- i18n keys in `en.ts` and `ru.ts`; MSW handlers for the new endpoints.

## Testing

Automated tests use `faketest.Vendor` / `httptest`; no real vendor, no real
key, sample URLs on `example.com`.

Gateway (first, before anything else, to prove the upstream assumptions):

- Two compat providers serving one model name both receive requests.
- A Postgres-sourced compat Auth registers its models and routes.

Then:

- Create → model served live; edit models → old gone, new served; disable and
  remove → refused; restart → attributes rebuilt, request served.
- Access to a pooled model needs grants on every provider serving it.
- Reserved name refused with `invalid_input`; duplicate name → 409.
- The key never appears in any response body or log line.
- Discover: timeout, oversize body, cross-host redirect, 401 →
  `provider_auth_failed`, vendor error body not echoed.
- Settings: sticky off → save → restart → still off; the upgrade step sets
  `true` once and never again.
- e2e: create a provider via `/api`, call it with an `sk-` key, usage row
  carries the provider's `vendor_account_id`.

Frontend (Vitest + MSW): discover → checklist → submit body; conflict warning;
edit keeps key when the field is empty; sticky toggle.

Manual smoke only: a real vendor through an environment variable, skipped when
unset; nothing about it is committed.

## Out of scope

Several keys per provider, custom headers, per-provider routing strategy,
automatic model sync, per-provider sticky settings, editable TTL.
