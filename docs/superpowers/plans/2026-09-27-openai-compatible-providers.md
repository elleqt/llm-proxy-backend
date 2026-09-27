# OpenAI-compatible providers Implementation Plan

> **For agentic workers:** executed inline in the brainstorming session (the user asked for a PR at the end). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Admin-managed, live OpenAI-compatible providers stored in `vendor_credentials`, plus a sticky-sessions toggle on by default.

**Architecture:** A compat provider is a Postgres-held `coreauth.Auth` (provider `openai-compatibility`, attributes rebuilt from sealed metadata on load). The gateway derives one `OpenAICompatibility` entry per held compat account and merges it into every configuration it applies; at boot it drops the keyless duplicates upstream synthesises from those entries. Spike (throwaway, `zz_compat_spike_test.go`) proved live registration and pooling.

**Tech Stack:** Go (CLIProxyAPI v7 sdk, pgx, testify, mockery, oapi-codegen), React/TS (TanStack Query, MSW, Vitest).

**Spec:** `docs/superpowers/specs/2026-09-27-openai-compatible-providers-design.md`

## Global Constraints

- The key never appears in a response, log line, audit detail, test fixture or commit; tests use `faketest`/`httptest`, sample URLs use `example.com`.
- Web API changes are spec-first: `api/openapi.yaml` → `make generate` → handler → `npm run sync:contract` in `../frontend`.
- testify only; strict mockery mocks; no `t.Parallel()` in `internal/infra/gateway`.
- Error text is mapped only in `appRefusals`; new codes `provider_unreachable`, `provider_auth_failed`.
- Name rule `^[a-z0-9][a-z0-9._-]{0,62}$`, immutable; row id `openai-compatible-<name>`.

---

### Task 1: Gateway — compat accounts

**Files:** Create `internal/infra/gateway/compat.go`, `compat_test.go`. Modify `credential_store.go` (`authFromRow`), `service.go` (`New`, `PushConfig`, `reapplyLocked`, `OnBeforeStart`, `VendorAccount`, `Params`).

**Interfaces (produces):**
- `const CompatProviderType = "openai-compatibility"` (the row provider and metadata `type`).
- `func (g *Gateway) AddCompatProvider(ctx, app.CompatProvider) (app.VendorAccount, error)` — `ErrConflict` on a held name, `*app.InvalidInputError` on bad name/URL/models.
- `func (g *Gateway) UpdateCompatProvider(ctx, id string, app.CompatProviderUpdate) (app.VendorAccount, error)`.
- `func (g *Gateway) DiscoverModels(ctx, baseURL, apiKey, accountID string) ([]string, error)`.
- `VendorAccount(auth)` fills `Compat *app.CompatDetails` and names the provider by its compat name.
- `Params.Stored []*coreauth.Auth` — what boot listed; `New` derives boot entries from it.

Steps:
- [ ] Tests: create → served live with the key; update models/base URL/key → new served, old gone; `SetAccountDisabled` → model gone; remove → gone; restart on the same store → attributes rebuilt and served, no keyless duplicate held; pooled model rotates; reserved and duplicate names refused; `Accounts()` never carries the key.
- [ ] Implement, run `go test ./internal/infra/gateway -run Compat -race`.

### Task 2: App — ports and providers service

**Files:** Modify `internal/app/ports.go`, `internal/app/providers/providers.go` (+ tests), `.mockery.yaml` if a new interface.

- `app.CompatProvider{Name, BaseURL, APIKey, Prefix string; Models []CompatModel}`, `app.CompatModel{Name, Alias string}`, `app.CompatProviderUpdate{BaseURL, Prefix string; Models []CompatModel; APIKey *string}` (nil keep, "" remove), `app.CompatDetails{Name, BaseURL, Prefix string; HasAPIKey bool; Models []CompatModel}` on `VendorAccount.Compat`.
- `app.VendorAccounts` gains `AddCompatProvider`, `UpdateCompatProvider`, `DiscoverModels`.
- Sentinels `app.ErrProviderUnreachable`, `app.ErrProviderAuthFailed`.
- `providers.Service`: `CreateCompat`, `UpdateCompat` (audited; failed audit on create withdraws), `DiscoverCompat` → `CompatDiscovery{Models []string; Conflicts map[string][]string}` using `app.ModelCatalog.Models()`.

### Task 3: Contract and web handlers

**Files:** `api/openapi.yaml`, generated `api.gen.go`, `internal/iface/http/admin_providers.go` (+ tests), `errors.go`.

- `POST /api/admin/providers/compat`, `PUT /api/admin/providers/compat/{accountId}`, `POST /api/admin/providers/compat/discover`; `ProviderAccount.compat`; `Settings.fields.sessionAffinity`; request `fields.sessionAffinity`.

### Task 4: Sticky sessions

**Files:** `internal/app/settings/settings.go` (+ tests), `admin_settings.go`.

- `parseDocument`: absent `routing.session-affinity` node → `cfg.Routing.SessionAffinity = true`.
- `Fields.SessionAffinity`, `Patch.SessionAffinity *bool` → nested node write `routing.session-affinity`.
- Test: off → saved → reparsed stays off; absent → on.

### Task 5: Boot wiring, e2e, README

**Files:** `internal/boot/boot.go`, `test/e2e/*`, `README.md`.

- Pass the boot listing as `Params.Stored`; wire `providers.New` with the catalog.
- e2e: create a provider through `/api`, call it with an `sk-` key, usage row carries its account id.

### Task 6: Frontend

**Files:** `frontend/api/openapi.yaml`, `src/shared/api/schema.d.ts` (generated), `src/entities/provider/providers.ts`, `src/features/compat-provider/*`, `src/pages/admin/providers/AdminProvidersPage.tsx` (+ test), `src/pages/admin/settings/AdminSettingsPage.tsx` (+ test), i18n, MSW mocks.

### Task 7: Verification and PRs

- `make generate && git diff --exit-code`, `go vet ./...`, `make lint`, `make test`; frontend `npm run build`, `npm test`.
- Live smoke against a real vendor through a locally built stack, the key passed only through the admin API at runtime.
- Two PRs (backend, frontend), Conventional Commits titles.
