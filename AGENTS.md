# Repository Guidelines

## Project Overview

`github.com/elleqt/llm-proxy-backend` is a self-hosted LLM gateway that lets a team share Claude/ChatGPT subscriptions through personal API keys. It embeds CLIProxyAPI (`github.com/router-for-me/CLIProxyAPI/v7`; the version in `go.mod` is authoritative) as a library and adds:

- users with local or OIDC sign-in
- `sk-` API tokens
- a per-user model allow-list policy
- a Postgres usage/cost ledger
- Prometheus metrics
- the `/api/*` JSON API used by the sibling `../frontend` UI

## Architecture & Data Flow

One process runs three listeners (defaults are in `internal/config/config.go`):

- **Gateway** (`LLMPROXY_LISTEN_ADDR`): the proxied LLM API (`/v1/...`) on upstream's gin engine, authenticated by API key.
- **Web API** (`LLMPROXY_WEB_ADDR`, `off` disables): `/api/*`, authenticated by the `llmproxy_session` cookie.
- **Metrics** (`LLMPROXY_METRICS_ADDR`): `/metrics`.

**Layering:** imports point inward only.

- `internal/domain` imports nothing internal and does no I/O.
- `internal/app` imports only `domain`, plus CLIProxyAPI `sdk/config` types. `internal/app/ports.go` declares every interface services depend on: repos, sinks, `Clock`, `Logger`, `ConfigPusher`.
- `internal/infra/*` and `internal/iface/http` import `app` and implement its ports. Each implementation carries an assertion like `var _ app.UsageRepo = (*UsageRepo)(nil)`.
- `internal/boot/boot.go` is the composition root. `build()` wires `New*` constructors by hand; there is no DI container. Constructors validate their dependencies and return an error.

**Proxied request** (`internal/infra/gateway`):

1. `policyGate` (`policy_gate.go`) runs first and denies by default. `classify` looks the route up in the static `routes` table (`routes.go`); a route that is not listed gets a 404.
2. The Content-Encoding gate runs next, then `authenticate` (`access_provider.go`) resolves the key through `app.TokenResolver`. The principal is cached on the context so upstream's `AccessProvider.Authenticate` does not hit the DB again.
3. On model routes, the body is buffered under the process-wide `bodyBudget` (`body_budget.go`). `model_extract.go` finds the model, then `access.Routed` and `Policy.Covers` enforce the allow-list.
4. `c.Next()` hands off to upstream, which calls the vendor. When the call finishes, upstream calls `UsageSink.HandleUsage`, which puts the record on a channel. A single worker prices it, batch-inserts it into Postgres and updates metrics.

**Web request** (`internal/iface/http/router.go`): stdlib `http.ServeMux` with hand-written handlers. Middleware order: `recoverPanics` → `limitBody` → `requireJSON` → `loadSession` → per-route rate limit, then session and admin guards. Route access comes from the `anonymous`, `restrictedAllowed`, `signInLimited` and `adminOnly` tables, so a new endpoint goes into `routes()` and into the right table.

**Boot and shutdown** (`boot.Run`):

- Startup: `config.Load()` → goose migrations (on every boot) → pgx pool → `build()` → `serve()`.
- `build()` also bootstraps the first admin and loads the upstream config document from the `settings` table.
- Shutdown order: listeners → gateway drain → usage sink drain → pool.
- Admin settings changes reach the live gateway through `app.ConfigPusher`.

## Key Directories

- `cmd/gateway/`: entry point. `gateway` serves; `gateway reset-password <email> [--unblock]` recovers an account offline.
- `internal/domain/{access,identity,credentials}`: policy rules, argon2id hashes, `sk-` token generation and hashing.
- `internal/app/`: services and ports. `mocks/` is generated.
- `internal/infra/gateway/`: the CLIProxyAPI embedding. `faketest/` holds behavioural vendor fakes.
- `internal/infra/postgres/`: repos, `migrations/`, and the `pgtest/` container helper.
- `internal/iface/http/`: web API handlers. `api/api.gen.go` is generated.
- `api/openapi.yaml`: web API contract and source of truth. It covers `/api/*` only, not the proxied API.
- `test/e2e/`: full-process tests across all listeners.
- `../upstream/` (optional sibling): a CLIProxyAPI source clone, for reference only. It is not wired in through `replace` or `go.work`.

## Development Commands

```sh
make build                              # go build ./...
make test                               # go test ./... -race (needs a Docker daemon)
make generate                           # pinned mockery + oapi-codegen via go run
go vet ./...                            # CI gate
make lint                               # pinned golangci-lint in ./bin, full repo; `make lint fix=1` autofixes
go test ./internal/app/... -race -run TestName -v
go test ./test/e2e/... -race -short     # -short skips the slow drain check
make generate && git diff --exit-code   # CI codegen drift gate
scripts/check-readme-compose.sh         # README block must equal docker-compose.minimal.yml
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build  # from source; needs ../frontend
```

To run locally:

- Set `LLMPROXY_DATABASE_URL`.
- Set either `LLMPROXY_PUBLIC_API_URL` or `LLMPROXY_WEB_ADDR=off`.
- Point `LLMPROXY_RUNTIME_DIR` and `LLMPROXY_AUTH_DIR` at writable directories.
- Go does not read `.env`.

The full variable reference is in `internal/config/config.go` and the README.

## Code Conventions & Common Patterns

- **Error messages** are prefixed with the package name: `errors.New("app: not found")`, `"web: ..."`, `"config: ..."`. Wrap errors with `%w`.
- **Sentinel errors** live in `internal/app/ports.go`. Typed errors such as `*app.InvalidInputError` carry the field name.
- **HTTP error mapping** happens only in the `appRefusals` table in `internal/iface/http/errors.go`, matched with `errors.Is`. Unmatched errors become a 500.
- **Web error body:** every web error is JSON `api.Error{code,message,field?}` written by `writeError`. Clients key on `code`, so treat codes as contract.
- **SQL:** raw SQL in documented string constants; no ORM or sqlc. Multi-row writes use `pgx.Batch`. Multi-row reads scan into a postgres-local row struct tagged `db:"<column>"` with `pgx.RowToStructByName` and convert to the app/domain type (which stay tag-free); hand-written `pgx.CollectableRow` scan closures are rejected by lint (`forbidigo`).
- **Unique violations** become `app.ErrConflict` through `asConflict()`, so callers never import pgx.
- **Time** always goes through `app.Clock`. The app layer logs through `app.Logger`, which takes `slog.Attr` values only (`slog.Any("err", err)`), never loose key/value pairs. Boot bridges upstream's logrus into the same slog handler (`internal/boot/logging.go`); logrus is there only for upstream.
- **Config** is env-only with the `LLMPROXY_` prefix and fails fast in `config.Load()`. Errors name the variable and never echo its value. Secrets use the self-redacting `config.Secret`.
- **Comments:** every package has a doc comment. Comments are full sentences that explain invariants and reasons; match that style.
- **Goroutines** belong to `serve()` in boot. Don't start unmanaged background work.

## Hard Rules

- **Generated code:** never hand-edit `internal/iface/http/api/api.gen.go` or `internal/app/mocks/*`. Run `make generate` and commit the result.
- **Mocks:** a new `internal/app` interface that needs a mock goes into the `.mockery.yaml` allowlist (`all: false`). Mocks come only from mockery. The only hand-written doubles are `faketest.Vendor` and `faketest.Executor`.
- **Web API changes** follow the spec-first order: edit `api/openapi.yaml`, run `make generate`, write the handler, then run `scripts/sync-contract.sh` in `../frontend`.
- **Upstream imports:** import only CLIProxyAPI's `sdk/...` packages, never `internal/...`. Upstream's `docs/sdk-*.md` are stale (they say `/v6`), so verify behaviour against the upstream source.
- **Upstream route table:** `routes.go` must list exactly the routes upstream registers (`TestEveryUpstreamRouteIsClassified`).
- **Upstream version bumps:** re-check that the Claude prefix handling in `model_extract.go` matches upstream's `ResolveClaudeModelIDPrefix`.
- **Management API:** never enable `/v0/management`. Keep `RemoteManagement.SecretKey` empty and set no management password or secret.
- **Access policy** is allow-list only and fails closed. Restrictions bind to the user, never to the token.
- **Secrets** are never logged or returned, apart from the one display at creation. Tokens are stored only as SHA-256 hashes and sessions only as `IDHash`.
- **Password hashes** use argon2id PHC, and cost parameters are read back from the stored hash. Don't change the encoding.
- **Body budget:** only the policy gate charges or releases it.
- **No deployment-specific names:** no hostnames, domains, groups, IPs or paths in code, tests, comments or examples. Use `example.com`.
- **Migrations:** add a new `internal/infra/postgres/migrations/000N_snake_name.sql` with `-- +goose Up` and `-- +goose Down` sections. Never edit a migration that has already been applied.
- **README sync:** the README block after `<!-- readme-sync: docker-compose.minimal.yml -->` must match `docker-compose.minimal.yml` byte for byte.
- **Startup error message:** keep `gateway: config: LLMPROXY_DATABASE_URL is required` stable. The CI image smoke test checks for it.

## Important Files

- `internal/boot/boot.go`: wiring, `Run`, `serve`, and shutdown order.
- `internal/config/config.go`: every `LLMPROXY_*` variable, its default and its validation.
- `internal/app/ports.go`: interfaces and sentinel errors.
- `internal/infra/gateway/{policy_gate,routes,access_provider,usage_sink,body_budget,model_extract}.go`: the proxy control plane.
- `internal/iface/http/{router,errors}.go`: web routing, access tables and error mapping.
- `internal/infra/postgres/migrate.go`: embedded goose migrations and `asConflict`.
- Codegen config: `api/openapi.yaml`, `internal/iface/http/api/codegen.yaml` (models only) and `.mockery.yaml`.
- `.github/workflows/ci.yml`, `Makefile`, `Dockerfile`, `docker-compose{,.minimal,.build}.yml`, `RELEASING.md`.

## Runtime/Tooling Preferences

- Go version comes from `go.mod`. There is no `go.work` or Nix shell.
- Lint is golangci-lint, version pinned in the `Makefile` and installed into the git-ignored `./bin` by `make lint`; config in `.golangci.yaml` (generated code excluded). The whole tree is clean: keep it so. A `//nolint` is always linter-scoped with a reason (`//nolint:<linter> // <why>`). CI lints only what a change introduces (`--new-from-rev`), so a config or version bump never blocks on old code.
- Code generators run through `go run pkg@version`, with versions pinned in the `Makefile`. Don't install them globally.
- A Docker daemon is required for tests.
- The image is a static `CGO_ENABLED=0` build; the version is injected with `-X main.version=...`.
- Releases follow `RELEASING.md`: tag backend and frontend together as `vX.Y.Z`. Bump image pins only after the images are published.
- `main` accepts only squash-merged pull requests with green CI (`test`, `image-check`, `pr-title`); direct and force pushes are refused. Work on a branch and open a PR titled as a Conventional Commits subject, `type(scope)!: summary` with type one of `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`: the title becomes the commit on `main`, and the required `pr-title` check refuses any other form.

## Testing & QA

- **Assertions:** testify only. `require` where the test cannot go on (the old `t.Fatal`), `assert` where it should report and continue (the old `t.Error`); inside goroutines, HTTP handlers and mock callbacks always `assert`. Expected value first (`require.Equal(t, want, got)`), and the specific assertion over `True` (`NoError`, `ErrorIs`, `Len`, `Contains`, …). An identity check on a sentinel, where a wrapped error must fail, is `require.Same`. Lint rejects `t.Fatal*`, `t.Error*`, `t.Fail*` (`forbidigo`) and checks testify usage (`testifylint`).
- **Mocks:** strict mockery testify mocks: `users := mocks.NewUserRepo(t); users.EXPECT().ByID(mock.Anything, id).Return(u, nil)`. An unexpected call fails the test, so a test of a refused path sets no expectations. Tests use table-driven `t.Run` for pure logic.
- **Test packages:**
  - `internal/app` tests use `package app_test`, because the mocks import `app`; shared doubles live in `helpers_test.go`.
  - Postgres tests are black-box (`postgres_test`), with `export_test.go` exposing test-only hooks.
  - `gateway` and `http` tests are white-box.
- **Database tests:** `pgtest.NewTestPool(t)` starts a fresh migrated `postgres:17-alpine` container on every call. There is no DSN override and no skip path.
- **`internal/infra/gateway`:** never call `t.Parallel()`, because tests mutate process-global state.
- **e2e:** every test starts with `if !inFreshProcess(t) { return }` and then calls `startProcess(...)`. Upstream registries are process-global, so each boot needs its own process.
- **Timestamps:** use a frozen `mocks.NewClock(t)` for exact timestamps.
- **Coverage expectations:** every behaviour needs an automated test; checking by hand with curl isn't acceptance. There is no coverage threshold.
- **CI** runs `go vet`, `go test -race`, the codegen drift check, the README/compose sync check, `docker compose config -q` for every compose combination, and a multi-arch image build with a smoke test. The `lint` job runs golangci-lint on new issues only (pull requests and pushes to `main`).
