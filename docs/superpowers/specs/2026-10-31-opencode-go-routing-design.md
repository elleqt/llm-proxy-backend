# OpenCode Go and prioritized DeepSeek routing

Date: 2026-10-31
Status: Written specification approved; implementation verified by automated suites and isolated live client checks.

## Goal

Support OpenCode Go subscriptions through the existing OpenAI-compatible provider flow. Prefer Go for DeepSeek requests and use the official DeepSeek API as a paid fallback. Clients, including omp and LibreChat, use the gateway with their ordinary DeepSeek model names and gateway keys; they do not implement fallback or receive vendor credentials.

The user approved general provider settings rather than an OpenCode preset or a separate provider implementation. The user also approved native CLIProxyAPI error handling and session binding.

## Existing capabilities and integration gap

The backend pins CLIProxyAPI v8.0.38. Its OpenAI-compatible configuration already supports provider priority, custom headers, and model aliases. Its execution manager selects credentials across providers, fails over between eligible credentials, and maintains cooldowns. The OpenAI-compatible executor applies `header:*` credential attributes to both streaming and non-streaming requests.

Upstream custom headers support `$CPA-SESSION-ID`, including substitution inside a value. This resolves the session identity used by CLIProxyAPI. There is no need to build a second session resolver or a dedicated OpenCode executor.

Relevant reference sources:

- `upstream/internal/config/config_types.go`: `OpenAICompatibility`.
- `upstream/internal/util/header_helpers.go`: custom header expansion.
- `upstream/sdk/cliproxy/auth/conductor_selection.go` and `scheduler.go`: cross-provider selection and priority.
- `upstream/sdk/cliproxy/auth/conductor_execution.go` and `conductor_stream.go`: execution and failover.
- `upstream/sdk/cliproxy/auth/session_affinity_priority_test.go`: binding takes precedence over recovered priority.

Our `app.CompatProvider`, credential metadata conversion, admin API, and frontend editor currently do not expose headers or priority. Those are the integration points to extend. Upstream remains read-only.

## Architecture and routing behavior

Use the existing OpenAI-compatible provider accounts:

1. OpenCode Go uses the vendor's documented Go OpenAI-compatible base URL, not the Zen/pay-as-you-go endpoint. Configure `x-opencode-session: $CPA-SESSION-ID` and priority `1`.
2. The official DeepSeek provider retains its own base URL and key and uses priority `0`.
3. Matching models on both providers use the same client-facing alias without a provider prefix. Each provider retains its actual upstream model identifier.
4. CLIProxyAPI owns selection, failover, cooldown, and session affinity. No custom retry loop, selector, or inference proxy is added.

A new session prefers an available Go credential. If Go becomes unavailable, the request can use the official provider according to upstream rules. The rebound conversation remains on its selected credential for the lifetime of its upstream binding, even if a higher-priority credential recovers. A new session prefers Go again when Go is eligible. Do not describe this as permanent binding to a conversation: the configured binding TTL still applies.

Use native handling for authentication/access failures, exhausted allowance, rate limiting, transient upstream failures, and transport failures. In particular, a Go 401/402/403 can cause paid fallback. Invalid client requests remain errors rather than being concealed through a new retry policy. Request cancellation is not a reason to continue spending on another provider. Failover must not replay or concatenate a partially delivered answer.

Do not change session-affinity configuration or routing behavior for Claude, ChatGPT, or unrelated models.

## Backend and API contract

Extend existing compatible-provider create, update, detail, and discovery flows; retain current names and conventions.

- `priority`: signed 32-bit integer. Creation defaults to `0`; omission in an update preserves the saved priority. Details return the effective value. Old credentials without metadata behave as priority `0`.
- `headers`: optional, write-only map of HTTP header names to string values. Creation defaults to no custom headers. Omission in an update preserves the saved map; an explicit empty map clears it; a supplied nonempty map replaces it completely.
- `headerNames`: read-only list of stored custom header names in provider details. Return names in deterministic order, never stored values.

Store these settings inside the existing sealed credential metadata. Rebuild `priority` and `header:*` attributes on creation, update, and load. Project priority consistently into derived upstream configuration. Keep secret header values in sealed metadata and runtime credential attributes, not in settings projections readable through the admin API. Do not introduce a second source of truth or leave obsolete header attributes after replacement/removal.

Update `backend/api/openapi.yaml` first, regenerate backend output and mocks where necessary, then synchronize the frontend contract and generated types. Do not hand-edit generated files.

### Header safety and discovery

Treat every configured header value as a potential secret. Stored values must not appear in admin detail responses, audit payloads, logs, errors, or frontend persistent storage. Audit may identify names and the priority change, not header values. The user's existing OpenCode key may be used for live checks without printing or committing it.

Validate HTTP header names and values, reject case-insensitive duplicate names, and reject CR/LF injection. Do not allow custom headers to override the dedicated Authorization credential or HTTP transport/framing controls such as Host, Content-Length, Transfer-Encoding, Connection, Proxy-Connection, Keep-Alive, TE, Trailer, and Upgrade. Other vendor credential headers remain supported and secret.

Preserve the current secret-to-destination boundary. Changing a provider base URL while retaining stored headers requires explicitly replacing or clearing those headers, just as a saved API key cannot silently follow an edited destination. Discovery may use saved headers only for that account's saved destination. Never forward saved secrets to a different host through redirects.

Static custom headers apply to model discovery as well as inference. Dynamic header values follow upstream expansion semantics rather than a second implementation. A conversation-derived variable has no guaranteed value in a discovery request; if absent, it is omitted rather than replaced with a shared dummy conversation. If a vendor's listing endpoint cannot work under those semantics, display the existing discovery error and retain manual model entry. Do not claim that inference success implies model discovery support.

## Frontend

Extend the existing compatible-provider drawer rather than creating another provider type or wizard. Add priority and a header editor under advanced settings. Existing stored header names are visible, values are not. Offer explicit preserve, replace-all, and remove-all behavior; never submit masked placeholders as real values. Replacement values stay in component memory only and are discarded when the drawer closes.

Keep the current manual model and alias editor. Preserve unsaved fields when model discovery fails. Use generated API types, existing UI components, and English/Russian translation dictionaries. Surface validation through stable error codes and field paths, not raw server messages.

No layout redesign, new UI dependency, or dedicated OpenCode preset is included.

## Model identity, access, and accounting

Before configuring the deployment, inspect the actual Go and official DeepSeek catalogs and the model names currently used by both clients. Preserve existing public aliases where the requested underlying model is available. Do not silently map a requested model to another generation or tier simply because their names are similar. A model available from only one source stays single-source; document its lack of fallback.

Keep existing provider-based authorization unchanged. A shared alias is admitted only when the user's policy covers every provider serving it. Configure the intended users/service accounts accordingly; do not bypass policy or grant unrelated OpenCode models to make the shared alias work.

Retain attribution to the actual serving provider/account in usage and metrics. Do not rewrite the official provider's accounting identity to Go or imply that estimated model cost equals subscription billing. A real Go success must be verified through the vendor's `usage.opencode.billing_source` value `go`, not just an HTTP 200 or the provider's display name.

## Verification and acceptance

Automated checks must exercise observable behavior through existing test infrastructure:

1. Header and priority settings survive credential persistence/reload, update, replacement, and removal; old credentials still work.
2. Header values stay out of detail responses, audit records, and errors. Invalid headers and unsafe destination reuse are rejected before dispatch.
3. The real upstream OpenAI-compatible path sends configured headers, expands session identity for inference, and keeps distinct sessions distinct. Test both streaming and non-streaming requests.
4. The common alias selects Go when both providers are healthy; representative 401, 402, 403, 429, and transient failures reach the official fallback according to upstream behavior. No failover occurs after answer content has been delivered or after request cancellation.
5. A rebound session retains the official provider after Go recovers; a new session selects available Go. Exercise existing access checks for shared aliases and denied users.
6. Frontend behavior covers priority editing, secret-header preservation/replacement/removal, failed discovery with manual entry, and stable error presentation.

Use existing gateway vendor fakes and test conventions. Do not add tests that merely copy fields, inspect implementation text, or echo mocks. The final verification includes a smoke run of the changed surface, not only compilation and unit tests.

Live acceptance uses the user's permitted local deployment and existing OpenCode credential:

- A small direct Go request establishes that the key, subscription, region setting, and selected model work and reports billing source `go`.
- Through the updated gateway, the ordinary DeepSeek alias works in non-streaming and streaming modes and uses Go first.
- Controlled failure in an isolated probe configuration demonstrates the official fallback without deliberately breaking the working provider for other users.
- omp and LibreChat can use their usual DeepSeek setup against the gateway; verify an actual request from each client and the resulting provider attribution.
- Restore any temporarily changed configuration and remove probe resources. Preserve real usage records unless cleanup is explicitly required by the deployment procedure.

The design was based on source inspection; the following observations were collected during implementation.

Live verification completed against an isolated stack using the real Go subscription and the official DeepSeek credential. Flash and Pro returned successful Go and official-fallback responses. The Go responses reported billing source `go`; streaming completed normally. Real omp and LibreChat requests used their ordinary DeepSeek model name, and both succeeded through Go and the official fallback. LibreChat's fallback also worked on a subsequent turn in the same conversation. Existing-session recovery stayed on the official source while a new session returned to Go. The actual provider/account was confirmed in the usage ledger. Test containers, copied credentials, temporary keys, and browser tabs were removed; production containers and provider definitions were unchanged.

## Deployment and rollback

Back up the relevant provider configuration and deployment state before applying changes. Use the deployment's established self-check and rollback procedure; avoid cutting off the active gateway used by the assistant. Keep keys and infrastructure-specific addresses out of public repository artifacts.

The new metadata is additive and uses the existing sealed store; do not create a database migration solely for these fields. Deploy matching backend/frontend contracts together. Rollback restores the previous images and provider configuration; do not assume that swapping images restores changed provider definitions or user policies.

Update both repositories' user documentation with generic compatible-provider examples, header secrecy semantics, priority/session interaction, and an OpenCode Go configuration recipe. Deployment-specific notes belong only in the user's private infrastructure documentation.

## Non-goals

No upstream fork, new OpenCode authentication protocol, billing dashboard, custom failover telemetry, model-quality substitution, global affinity change, automatic client installation, or new routing subsystem. Existing upstream diagnostics and actual provider attribution remain the evidence for source selection.
