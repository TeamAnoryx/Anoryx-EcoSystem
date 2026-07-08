# ADR-0032 — MCP & Third-Party Integration Layer (F-026)

- Status: Accepted (implemented, scope-narrowed — see "Scoping decision" below)
- Date: 2026-07-08
- Builds on: ADR-0023 (F-020 webhooks — `orchestration.webhooks.url_guard`,
  reused verbatim for MCP server URL validation; `webhook_config`'s
  per-tenant-external-endpoint-allowlist table shape, mirrored by
  `tenant_mcp_servers`), ADR-0007 (F-005 orchestration hooks — the generic,
  content-agnostic `HookRegistry`/`HookContext` this ADR reuses unchanged for
  MCP payload inspection), ADR-0005 (tenant isolation — RLS pattern this
  ADR's new table follows), ADR-0031 (F-025 — the same contracts-access
  constraint and CLI-first scoping pattern this ADR repeats).
- Scope: `src/mcp_gateway/` (new — a CLI + library, not an HTTP surface),
  `src/persistence/models/tenant_mcp_server.py` +
  `repositories/tenant_mcp_server_repository.py` + migration 0033. **No
  `contracts/` change.**

## Context

Roadmap F-026: "Secure proxy + governance for external MCP servers / AI
tools / third-party APIs. Per-tenant allow-lists, uniform inspection
(PII/injection/secret), MCP audit logs." Before writing code, research
established two structural facts:

1. **A "secure proxy" for external MCP traffic needs a new network-facing
   surface, full stop.** MCP (Model Context Protocol) is JSON-RPC 2.0 over
   stdio/SSE/HTTP with `tools/list`/`tools/call`/session negotiation — not a
   single-shot "prompt in, completion out" call. It does not fit F-006's
   `ProviderRegistry` adapter interface (`complete(CreateChatCompletionRequest)
   -> ChatCompletionResponse`), and `src/gateway/routes/` has no generic
   "passthrough to an arbitrary external URL" mechanism —
   `chat_completions.py`'s own docstring is explicit that Sentinel does "no
   raw passthrough," only "typed re-serialization." A working MCP proxy is
   therefore a genuinely new route family (or a wholly separate
   protocol-speaking component), not an extension of anything that exists.
2. **New routes need `contracts/openapi.yaml`, which was unreachable in
   this session** — the exact same `ANORYX_ACTIVE_AGENT` propagation gap
   documented in ADR-0031. An api-architect subagent was not re-dispatched
   for this task (the gap is already fully diagnosed and documented; the
   outcome would be identical to ADR-0031's).

## Scoping decision

Given (1) and (2), this ADR does **not** build a live MCP proxy. It ships
the **governance substrate** the roadmap line's OTHER two requirements need
— "per-tenant allow-lists" and "uniform inspection" — both of which turned
out to be fully buildable without touching `contracts/`:

- **Per-tenant allow-lists**: a new `tenant_mcp_servers` table
  (migration 0033), same shape as `webhook_config` (ADR-0023 §5.2) — a
  Sentinel-LOCAL, RLS-scoped, admin-managed table, not a signed Delta
  policy (mirrors `tenant_routing_policy`'s own "NOT signed Delta policy"
  precedent exactly, so no `contracts/policy.schema.json` involvement
  either). Managed via the `sentinel-mcp allowlist` CLI (same trust tier as
  `sentinel-cli`/`sentinel-dr`/`sentinel-onboarding` — an admin HTTP route
  for this is deferred to `docs/followups/f-026-mcp-proxy-endpoint.md`
  alongside the proxy itself, for the same reason).
- **Uniform inspection**: confirmed and proven, not just claimed.
  `orchestration.registry.HookRegistry.run_pre_request`/`run_post_response`
  take arbitrary `content: str` — nothing OpenAI-message-shaped is baked
  into the hook contract (only the factory `build_hook_context()` is
  message-shaped, so `src/mcp_gateway/inspection.py` constructs `HookContext`
  directly). `tests/mcp_gateway/test_inspection.py` proves a fake-shaped AWS
  credential embedded in MCP-style payload text gets **blocked by the exact
  same `SecretInboundHook`** `/v1/chat/completions` uses — not a
  reimplementation, not a stub.

**MCP audit logs** are partially delivered: a blocked/masked MCP payload
emits the SAME existing, contract-conformant event types
(`pii_blocked`/`injection_detected`/`secret_leaked`) a chat-completions
request would — genuinely real audit trail, zero new event types needed.
What's NOT delivered: a dedicated "an MCP call to server X happened"
bookkeeping event (analogous to `usage` for chat completions) — that would
need a new `events.schema.json` event type, which is `contracts/`-gated the
same way. Structured `structlog` logging stands in for now; see the
followup doc.

## Decision

### 1. `tenant_mcp_servers` (migration 0033, `TenantMcpServer` model)

Mirrors `webhook_config` field-for-field: `server_id` (PK), `tenant_id` (FK,
RESTRICT), optional `team_id`/`project_id` scope, `name`, `server_url`
(`TEXT`, SSRF-validated at write), `is_active` (soft-disable, no DELETE
path), timestamps. Same RLS setup as every per-tenant table since
migration 0006 (ENABLE + FORCE + `tenant_isolation` policy on the fail-closed
`NULLIF(current_setting('app.current_tenant_id', true), '')` predicate +
GRANT SELECT/INSERT/UPDATE to `sentinel_app`).

### 2. SSRF guard reuse (`src/mcp_gateway/url_guard.py`)

`validate_mcp_server_url()` is a thin wrapper around
`orchestration.webhooks.url_guard.check_url` — the EXACT F-020 SSRF
control (deny-by-default IP classification, resolve-and-pin, TLS-only, no
redirects), not a reimplementation. Default `mcp_allowed_ports = {443}`
(HTTPS-standard only; configurable via `McpGatewaySettings` for self-hosted
MCP servers on non-standard ports — the IP-classification/resolve-and-pin
protections hold at any allowed port). Called BEFORE any write
(`mcp_gateway/allowlist.py::register_server`), mirroring
`admin/webhooks.py::_guard_target_url`'s "a denied URL never reaches the DB"
discipline exactly.

### 3. Inspection reuse (`src/mcp_gateway/inspection.py`)

`inspect_mcp_payload()` / `inspect_mcp_response()` construct a `HookContext`
directly and call `build_default_registry().run_pre_request()` /
`.run_post_response()` — the SAME `SecretInboundHook -> InjectionHook ->
PIIHook` (pre) / `SecretOutboundHook` (post) chain the gateway's own request
path runs. A block raises the SAME `HookBlockedError`; a mask returns the
SAME redacted-content contract. CLAUDE.md #5 fail-safe applies unchanged —
these functions do not catch/reinterpret `HookBlockedError`/
`HookFailSafeError`, they let them propagate for the caller to treat as
BLOCK.

### 4. `sentinel-mcp` CLI (`src/mcp_gateway/cli.py`)

`sentinel-mcp allowlist add/list/revoke` (register/inspect/soft-disable a
tenant's MCP servers) and `sentinel-mcp inspect` (run arbitrary text through
the F-005 chain — an operator-facing preview/testing tool proving governance
behavior before any live proxy exists).

## Honest limitations

- **No live MCP proxy anywhere in this ADR's scope.** Nothing here makes a
  single network call to an external MCP server. `is_server_allowed()`
  (`mcp_gateway/allowlist.py`) is the check a future proxy call site MUST
  invoke before dispatching a byte — but no such call site exists yet. See
  `docs/followups/f-026-mcp-proxy-endpoint.md`.
- **No dedicated MCP-call audit event type** — inspection results (block/
  mask) ARE genuinely audited via existing event types; "this MCP call
  happened" bookkeeping is not, pending `contracts/events.schema.json`
  access (same followup doc).
- **No admin HTTP route for the allow-list** — CLI-managed only, same
  reasoning and same followup pattern as ADR-0031's team/project gap.
- `tenant_mcp_servers.server_url` uniqueness is NOT enforced at the DB
  level (no unique constraint) — `is_allowed()` does an exact string match
  against ANY active row, so registering the same URL twice under different
  names is harmless (both authorize it) but is not deduplicated. An
  operator managing this via the CLI will simply see two list entries.
