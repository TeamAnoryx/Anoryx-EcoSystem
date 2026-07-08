# Follow-up: live MCP proxy + admin HTTP API + MCP-call audit event (F-026)

**Status:** OPEN — blocked on environment access (contracts/) AND genuinely
new architecture (the proxy itself), not a mechanical gap like F-025's.
**Severity:** None (no security issue — F-026 shipped governance substrate
with zero live network surface, so there is nothing to exploit yet).
**Owner:** api-architect (contracts/) + a dedicated design pass (the proxy
mechanism itself — this is NOT a copy-paste-ready spec like
`f-025-team-project-admin-api.md`, see below).

## What F-026 shipped vs. what's deferred

Shipped (`docs/adr/0032-mcp-third-party-integration-layer.md`):
per-tenant MCP server allow-listing (`tenant_mcp_servers` table,
`sentinel-mcp allowlist` CLI), SSRF-safe URL validation at registration
(reuses F-020's `url_guard.check_url` verbatim), and uniform PII/injection/
secret inspection of arbitrary MCP-shaped payload text (reuses the F-005
hook chain verbatim, proven in `tests/mcp_gateway/test_inspection.py`).

Deferred — three separate things, each needing different follow-up work:

### 1. The live proxy itself (genuinely new architecture, not just contracts-blocked)

Unlike F-025's team/project gap (a mechanical CRUD gap with an obvious,
fully-specified fix), an MCP proxy needs a **design decision**, not just an
endpoint definition:

- **Option A — REST wrapper**: a new `POST /v1/mcp/{server_id}/call`-style
  endpoint that accepts a JSON body (tool name + arguments), looks up the
  server via `mcp_gateway.allowlist.is_server_allowed()`, makes the MCP
  JSON-RPC call server-side, runs `mcp_gateway.inspection.inspect_mcp_payload`
  /`inspect_mcp_response` around it, and returns a translated JSON response.
  Fits `contracts/openapi.yaml` naturally (REST in, REST out) but hides MCP's
  richer semantics (streaming, resources, prompts, session state) behind a
  narrowed request/response shape — likely fine for a v1, but a real scoping
  call for whoever picks this up.
- **Option B — Sentinel-as-MCP-server**: Sentinel speaks MCP's own JSON-RPC
  transport directly (a distinct process/port from the `/v1/*` OpenAI-
  compatible REST surface), governing calls between an MCP client (e.g. an
  IDE agent) and the allow-listed upstream MCP servers. This is NOT
  REST/OpenAPI-shaped at all, so it may not need `contracts/openapi.yaml` in
  the same way — but it IS a brand-new, security-sensitive network surface on
  a zero-trust security product, and deserves its own ADR + threat-model pass
  regardless of whether `contracts/` is technically involved. Do not build
  this without that review, even once contracts/ access exists.

Whoever picks this up should write a short design ADR choosing between (or
combining) these before implementing — this followup intentionally does not
pre-decide it.

### 2. Admin HTTP API for the allow-list

Once (1) is scoped, add `POST/GET /admin/tenants/{tenant_id}/mcp-servers`
(mirrors `admin/webhooks.py`'s shape exactly — same SSRF-guard-before-write
discipline, same `_assert_scope_in_tenant`-style checks if team/project-scoped).
Needs `contracts/openapi.yaml` (api-architect). Backing repository
(`TenantMcpServerRepository`) and validation
(`mcp_gateway.url_guard.validate_mcp_server_url`) already exist and can be
called directly from the new route — no new persistence-layer work.

### 3. MCP-call audit event type

A new event type (e.g. `mcp_call_audited`, carrying `server_id`,
`tool_name`, `outcome`) analogous to `usage` for chat completions. Needs, per
the established 4-site consistency pattern (ADR-0023 §5.4):
`contracts/events.schema.json` (api-architect) + a migration widening
`ck_eal_event_type` in `src/persistence/models/events_audit_log.py` +
`VALID_EVENT_TYPES`/`ACTION_TAKEN_BY_EVENT_TYPE` there + whatever emits it
(the proxy from (1), once it exists). Until then, `src/mcp_gateway/cli.py`
and any future proxy code should `structlog`-log MCP call metadata (never
payload content) as an interim, non-audit-chain signal.
