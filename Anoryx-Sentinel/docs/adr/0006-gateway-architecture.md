# ADR-0006: Gateway Architecture (F-004)

**Status:** Proposed
**Date:** 2026-06-16
**Deciders:** Sentinel engineering team
**Tags:** gateway, fastapi, middleware, streaming, rate-limit, audit, fail-safe
**Conforms to (does NOT modify):** `contracts/openapi.yaml`, `contracts/events.schema.json`, `contracts/policy.schema.json`, `contracts/ids.md` (all LOCKED from F-001/F-002)
**Builds on:** ADR-0002 (OpenAI-compatible surface), ADR-0004 (persistence), ADR-0005 (runtime tenant isolation, F-003b — MUST merge before F-004)

---

## Context

F-004 builds the first runtime serving path for Sentinel: the HTTP gateway that
accepts OpenAI-compatible traffic, authenticates it, resolves the authoritative
tenant context, rate-limits it, proxies it to an upstream provider, and emits an
audit + usage record for every terminal outcome. This ADR records the
**architecture and design decisions** for that gateway. It is a decision record
only — it implements no gateway code. The implementation lands in the F-004 task,
conforming to the decisions here.

### The contract is the law

`contracts/openapi.yaml` is the single source of truth for Sentinel's public API
surface (ADR-0002). This ADR **conforms** to it and never changes it. Where the
F-004 brief's deliverable language diverges from the locked contract, the
**contract wins** and the divergence is reconciled in writing (see Decision 2,
Decision 6, and Decision 8 in particular). The four locked contract files are
read-only inputs to this design; nothing here edits a contract field, an
`error_code`, a fixed `message` string, an event field name, or a stable ID.

### Recon facts this design is built on

- **Contract surface:** three endpoints — `POST /v1/chat/completions`,
  `POST /v1/completions`, `GET /v1/models`. Bearer auth
  (`Authorization: Bearer <virtual key>`). Four required headers on every request:
  `X-Anoryx-Tenant-Id`, `X-Anoryx-Team-Id`, `X-Anoryx-Project-Id` (UUID, ≤64),
  `X-Anoryx-Agent-Id` (slug `^[a-z0-9]+(-[a-z0-9]+)*$`, ≤64).
- **Authoritative tenant binding:** `tenant_id` / `team_id` / `project_id` /
  `agent_id` are resolved **server-side** from the `virtual_api_keys` row. The four
  headers are a **cross-check only**; a mismatch is `403 id_context_mismatch`.
  Headers never widen, override, or impersonate scope. Outbound events/audit carry
  server-resolved values only.
- **Error envelope** (closed): `{error_code, message, request_id}`. `error_code`
  enum is EXACTLY: `missing_required_header`, `invalid_request`,
  `request_too_large`, `invalid_api_key`, `id_context_mismatch`, `policy_blocked`,
  `rate_limit_exceeded`, `internal_error`. `message` is a FIXED enum string per
  code, 1:1, with NO request-derived interpolation. The 1:1 pairing is NOT
  schema-enforced; the gateway MUST guarantee it in code + a unit test.
- **Rate limits (contract, Phase 0):** 600 requests / 60 s sliding window, scoped
  BOTH per virtual key AND per server-resolved `tenant_id` (stricter applies); max
  20 concurrent open SSE streams per resolved tenant.
- **Events (`events.schema.json`):** the `usage` variant has 12 required fields,
  field names exact, closed schema. Audit-log column names match schema field
  names (hash-chain `CANONICAL_FIELDS`).
- **Persistence (F-003b / ADR-0005):** `get_tenant_session(tenant_id)` (sets the
  transaction-local GUC; raises `TenantContextRequiredError` on missing/empty
  tenant) for ALL tenant traffic; `get_privileged_session()` (BYPASSRLS owner) for
  audit-log chain ops ONLY. `VirtualApiKeyRepository.lookup_by_plaintext` uses
  HMAC fingerprint + `hmac.compare_digest` (constant time), filters
  `is_active AND (expires_at IS NULL OR > now())`, raises a uniform
  `VirtualApiKeyAuthError` (no timing leak). `AuditLogRepository.append` asserts a
  privileged session, advisory-locks, computes `prev_hash`/`row_hash`. No raw SQL
  — repositories only.
- **Stack:** Python ≥3.12, `fastapi>=0.115`, `uvicorn[standard]`, `httpx>=0.27`,
  `pydantic-settings>=2.3` (a dependency, not yet used), `pytest-asyncio`
  (`asyncio_mode=auto`), coverage `fail_under=80`.

---

## Decision

### Decision 1 — Framework: FastAPI on uvicorn[standard]

**Decision.** Build the gateway on **FastAPI** served by **uvicorn[standard]**
(httptools + uvloop). The brief mandates FastAPI; we confirm it as the right
choice and move on.

**Rationale.**

- FastAPI is already a pinned dependency (`fastapi>=0.115`), as is
  `uvicorn[standard]`, so there is no new dependency surface.
- Pydantic v2 request models give us **closed-schema validation at the boundary
  for free** — `additionalProperties: false` maps to `model_config =
  ConfigDict(extra="forbid")`, and the contract's per-field bounds
  (`maxLength`/`maxItems`/`minimum`/`maximum`) map directly to Pydantic
  constraints. This is exactly the typed re-serialization the upstream-injection
  defense (Decision 8) requires.
- Native ASGI streaming (`StreamingResponse` / async generators) is what the SSE
  fail-safe (Decision 7) needs; `httpx` async streaming pairs with it cleanly.
- FastAPI's exception-handler and middleware model gives us the terminal-emit hook
  the audit guarantee (Decision 3) depends on.

**Alternatives considered.** Raw **Starlette** (FastAPI's own foundation — we get
its benefits anyway, plus Pydantic validation and OpenAPI alignment, for no extra
cost); **Litestar** (capable, but a new dependency and ecosystem churn for no
contract benefit); **aiohttp** (lower-level, no first-class Pydantic/OpenAPI
story, more hand-rolled validation = more places for the closed-schema guarantee
to drift). None offer a benefit that outweighs leaving the pinned, already-vetted
FastAPI stack.

### Decision 2 — Endpoint scope for F-004 (operational endpoints reconciliation)

**Decision.** F-004 implements **`POST /v1/chat/completions` fully** (non-stream
and stream). `POST /v1/completions` and `GET /v1/models` are **DEFERRED to an
F-004 follow-up** task (they share the same pipeline and are cheap to add once the
chat path is proven). Two **operational endpoints** are added: **`GET /health`**
(liveness, no auth, no DB) and **`GET /ready`** (readiness, checks DB
connectivity).

**Reconciliation with "never invent endpoints."** The contract rule (ADR-0002,
`CLAUDE.md` non-negotiable #1) forbids inventing **API** endpoints — surfaces that
carry tenant data and form the OpenAI-compatible contract. `/health` and `/ready`
are **NOT** part of that contract:

- They live **outside** the versioned `/v1` surface (no `/v1` prefix).
- They carry **no tenant data**, require **none of the four ID headers**, and
  emit **no events**.
- They are operational/infra concerns (Kubernetes liveness/readiness probes,
  load-balancer health checks), not part of the API the OpenAI SDK speaks to.
- They are **not** added to `contracts/openapi.yaml`; the contract continues to
  describe exactly the three API endpoints it describes today. This ADR documents
  them as out-of-contract operational endpoints, which is the opposite of
  inventing a contract endpoint.

`/health` returns `200` whenever the process is up. `/ready` returns `200` when a
trivial `SELECT 1` over the persistence layer succeeds and `503` otherwise; it
does **not** use the standard `Error` envelope (that envelope is contract surface
for `/v1`), it returns a minimal operational body. `/ready` performs its
connectivity check via a non-tenant probe (a privileged-session `SELECT 1` or a
dedicated lightweight check) and never sets a tenant GUC.

### Decision 3 — Middleware pipeline order + the audit guarantee

**Decision.** The pipeline order (outermost → innermost), with the failure each
stage owns, is fixed as below. The ordering reconciles two competing pressures
honestly: (a) cheap, pre-auth rejections (oversize body, missing/malformed
headers) must run **before** we spend work or touch the upstream; (b) rate
limiting is keyed on the **resolved** virtual-key id + tenant, so it must run
**after** auth resolves them.

1. **Terminal-audit wrapper / exception layer (outermost).** Establishes the
   `request_id`, wraps the entire downstream pipeline, and **guarantees a usage
   event + audit record is emitted on EVERY terminal outcome** — success (2xx) and
   every rejection (4xx/5xx). See "Audit guarantee" below. This is NOT a
   "before-handler" middleware (those are skipped on early rejection); it is a
   wrapper + a set of FastAPI exception handlers that funnel every terminal
   response through one emit point.
2. **Body-size / edge guard.** Enforces `MAX_BODY_BYTES` (default `1048576` to
   match the contract's 1 MiB cap) by checking `Content-Length` and capping the
   read stream **before** the body is parsed into memory. Rejects oversize bodies
   `413 request_too_large` (the contract permits surfacing as `400`, but we prefer
   `413` for clarity; both are contract-valid). This runs early and before parse —
   an attacker cannot exhaust inspection resources (threat #8). Relies on the ASGI
   server's HTTP framing for request-smuggling resistance (threat #3 — see
   threat table for the honest scope note).
3. **Header presence / format gate.** Validates that all four ID headers are
   present, well-formed (UUID for tenant/team/project, slug for agent), and ≤64
   chars. Missing/malformed/overlong → `400 missing_required_header`. This is
   cheap and pre-auth, so it gates before we do any key lookup.
4. **Authentication.** Extracts the `Authorization: Bearer <key>`, resolves it via
   `VirtualApiKeyRepository.lookup_by_plaintext` (constant-time fingerprint
   compare; filters active + non-expired). Missing/malformed/revoked/unknown →
   `401 invalid_api_key`. On success this yields the **server-resolved**
   `tenant_id`/`team_id`/`project_id`/`agent_id` from the key row — the
   authoritative context. The key-lookup read itself runs under the persistence
   layer per ADR-0005.
5. **ID cross-check (tenant context resolution).** Compares each of the four
   resolved IDs against the corresponding request header. Any mismatch →
   `403 id_context_mismatch`. The resolved (key-bound) values — never the headers
   — become the request-scoped tenant context (Decision 4).
6. **Rate limit.** Keyed on **(virtual-key id, resolved tenant_id)**; enforces the
   600/60 s sliding window (stricter of the two scopes wins) and, for
   `stream: true`, the ≤20 concurrent-SSE-per-tenant cap. Over limit →
   `429 rate_limit_exceeded` with `Retry-After`. Runs **after** auth because it
   needs the resolved key id and tenant (Decision 5).
7. **Request-body validation.** Parses and validates the body against the Pydantic
   model mirroring `CreateChatCompletionRequest` (closed schema, all bounds).
   Unknown keys / out-of-bounds / type errors → `400 invalid_request`. Enforces
   `MAX_TOKENS_PER_REQUEST` (threat #4) as an additional cap layered on the
   contract's `max_tokens ≤ 131072`.
8. **Handler (innermost).** Re-serializes the validated, allowlisted model into the
   upstream request (Decision 8), proxies via `httpx`, streams or buffers the
   response per the SSE fail-safe (Decision 7), and reports token/latency figures
   back up to the terminal-audit wrapper for the usage event.

**Ordering tension, resolved.** We reject oversize bodies and malformed headers
**pre-auth** (steps 2–3) because they are cheap and must not be allowed to consume
inspection resources, while rate limiting (step 6) runs **post-auth** because the
contract scopes it on the resolved key id AND resolved `tenant_id`. This means an
**unauthenticated** flood is bounded by the cheap pre-auth rejections (size +
header checks + the constant-time key lookup) rather than by the per-tenant rate
limiter; per-tenant/per-key limiting begins the moment the key resolves. A coarse
pre-auth safety valve (e.g. global connection limits at the ASGI server / ingress)
is an infra concern noted under Deferred, not part of this in-process pipeline.

**Audit coverage on early-rejected requests.** Because audit MUST emit on both
success and failure, it CANNOT be a normal before-handler middleware (those never
run when an earlier stage rejects). Instead:

- A **pure-ASGI outermost wrapper** (`TerminalAuditMiddleware`) wraps the `send`
  callable for every request. It observes the final HTTP status code produced
  anywhere in the stack — including `JSONResponse` objects returned directly by
  inner `BaseHTTPMiddleware` layers (which bypass the `dispatch()` of any outer
  `BaseHTTPMiddleware` wrapper). This is the correct mechanism to cover
  `401 invalid_api_key`, `400 missing_required_header`, `413 request_too_large`,
  `400` TE+CL, and `500` from the exception handler.
- For route-handled requests (steps 5–8), the route handler calls
  `emit_terminal_record(...)` and marks `request.state.audit_emitted = True`.
  The outermost wrapper checks this flag to avoid double-emission.
- Pre-route rejections (from inner middlewares) have no `TenantContext`; the
  wrapper calls `emit_terminal_record(tenant_context=None, ...)` and
  `build_usage_event()` substitutes safe sentinel IDs (all-zeros UUID,
  agent `gateway-core`), `model=''`, `tokens_in/out=0`.
- **Fail-safe on audit failure (NON-STREAM):** if the audit/usage emit itself
  fails for a non-stream request, the request outcome is forced to
  `500 internal_error` (a non-stream success that cannot be recorded is treated
  as a failure) — consistent with the fail-safe-BLOCK posture and `CLAUDE.md`
  non-negotiable #5.
- **Audit failure on already-committed responses (pre-route rejections and
  STREAM):** for responses whose bytes are already in-flight when the audit emit
  is attempted, the status code cannot be changed. The failure is logged at
  `ERROR` level (structured, no PII) as a documented out-of-band alert signal.
  It MUST NOT be swallowed silently. Operators must monitor `audit_append_failed`
  and `terminal_audit_emit_failed_post_response` log events.

**HIGH-3 Amendment — Streaming honest scope:**
  For **streaming** requests, the `200` response headers are sent before the
  generator runs. If the audit emit inside the generator's `finally`-block fails,
  the `200` cannot be retroactively changed to `500`. This is an inherent SSE
  constraint, not a code defect. The "audit-failure → 500" guarantee is scoped
  to **NON-STREAMING** requests only. For streams, audit is best-effort-after-
  headers with failure surfaced out-of-band at `ERROR` log level. This honest
  scoping is documented in `chat_completions.py` and `audit.py`.

### Decision 4 — Tenant context semantics (conform to contract)

**Decision.** The four IDs are resolved **authoritatively from the virtual-API-key
row**, server-side. The three UUID headers are cross-checked; a mismatch on any →
`403 id_context_mismatch`. The **`X-Anoryx-Agent-Id`** header is cross-checked the
**same way**: the key row carries an authorized agent/component scope, and a header
value outside that scope → `403 id_context_mismatch` (the contract's `AgentId`
parameter description requires exactly this).

- **Headers and body IDs NEVER become the source of truth.** They are validated for
  format (so a malformed one is a cheap `400`) and then compared against the
  resolved values. They are **never** propagated onto events or audit logs. Every
  outbound `usage` event and audit row carries the **server-resolved** values only
  — matching the `events.schema.json` note that attribution "is always the
  server-resolved value … never a raw client-supplied header."
- **Request-scoped lifetime (threat #10).** The resolved tenant context is built
  fresh per request, lives only in that request's scope (FastAPI request
  state / a contextvar set and reset within the request), and is **never** reused
  across requests. The persistence GUC is transaction-local per ADR-0005, so the
  DB layer also cannot leak context across pooled connections. No module-level or
  process-global mutable "current tenant" exists.
- **Tenant session usage.** All tenant data reads (key scope, future policy/team/
  project reads) run via `get_tenant_session(resolved_tenant_id)` per ADR-0005;
  only the audit-chain append runs via `get_privileged_session()`.

### Decision 5 — Rate-limit data structure (Phase 0, in-process)

**Decision.** Phase 0 uses an **in-process** limiter with two components, keyed
ONLY on the virtual-key id and the resolved `tenant_id` — **never on IP** (threat
#5: `X-Forwarded-For` spoofing is immaterial because IP is not a key):

1. **Request-rate limiter** — a sliding-window counter (to match the contract's
   "600 requests per 60-second **sliding** window" exactly), maintained for **both**
   the `(virtual_key_id)` scope and the `(tenant_id)` scope. A request is admitted
   only if **both** windows permit it; the **stricter** of the two governs, per the
   contract. This is exposed as `RATE_LIMIT_RPM` (default `600`). `RATE_LIMIT_BURST`
   bounds short-term bursting within the window (a token-bucket refill style cap)
   so the limiter degrades gracefully rather than admitting a full window instantly
   at the boundary.
2. **Concurrent-stream counter** — a per-resolved-`tenant_id` integer of currently
   open SSE streams, incremented when a `stream: true` response begins and
   **decremented on stream close, completion, error frame, OR client disconnect**
   (Decision 7). Capped at `MAX_CONCURRENT_STREAMS_PER_TENANT` (default `20`). A new
   stream that would exceed the cap → `429 rate_limit_exceeded` with `Retry-After`.
   Decrement is guaranteed via a `finally`/context-manager so an abandoned stream
   does not permanently consume a slot.

**Reconciling the brief vs the contract.** The brief mentioned an "in-memory token
bucket per key (`RATE_LIMIT_RPM`/`BURST`)." The contract requires a **sliding
window**, **dual key-AND-tenant** scoping, and a **concurrent-stream cap**. The
contract wins: we keep the brief's config names but implement the contract's
semantics (sliding window, dual scope, stricter-wins, plus the stream cap). Config
mapping: `RATE_LIMIT_RPM` (default 600), `RATE_LIMIT_BURST`,
`MAX_CONCURRENT_STREAMS_PER_TENANT` (default 20).

**Honest limitation.** In-process state is **per-worker**. With multiple uvicorn
workers/replicas, each holds its own counters, so the effective global limit is
`N × RATE_LIMIT_RPM` and the concurrent-stream cap is per-worker, not truly
per-tenant-global. This is acceptable for Phase 0 single-/few-worker deployments
and is documented honestly, not hidden. **Redis-backed distributed limiting is
deferred to F-010.** The `X-RateLimit-*` response headers REPORT this worker's
view of the limit/remaining/reset; they are reporting, not the control (ADR-0002).

### Decision 6 — Error response shape (exact code → message → status map)

**Decision.** Every failure maps to exactly one contract `error_code`, its single
fixed `message` enum string, and a contract status. There is **NO interpolation**;
the code→message mapping is a constant lookup table guaranteed in code and pinned
by a unit test (the contract notes this pairing is not schema-enforced). The
`request_id` is echoed in BOTH the `X-Request-Id` response header and the body
`request_id` field. See the **Error code → message → status table** below for the
authoritative mapping.

- **`policy_blocked` is reserved, not emitted by F-004.** The policy engine is
  **F-008**. F-004 wires the `policy_blocked` → `403` mapping into the constant
  table (so the contract code is honored the instant F-008 lands) but F-004 itself
  has no policy evaluation and therefore **does not emit `policy_blocked`** yet.
  This is stated honestly here and in the table.
- **`invalid_request`** covers a malformed body, an unknown/forbidden key (closed
  schema), or any out-of-bounds field.
- The message strings are taken **verbatim** from the contract `Error.message`
  enum; this ADR does not introduce new strings.

### Decision 7 — Streaming lifecycle

**Decision.** Streaming conforms to the contract's SSE fail-safe and adds the
operational guards from the brief.

- **Backpressure.** The handler streams upstream `httpx` chunks to the client via
  an async generator; the ASGI server applies natural backpressure (it will not
  read faster than the client drains). No unbounded in-memory buffering of the
  full response.
- **Idle + overall timeouts.** `STREAM_TIMEOUT_SECONDS` bounds the **idle** gap
  between chunks; `REQUEST_TIMEOUT_SECONDS` bounds the **overall** request. On
  either timeout the stream is terminated with the fail-safe error frame (below).
- **Client disconnect.** On client disconnect the gateway **closes the upstream
  `httpx` stream** (cancels the upstream request) so we do not keep paying for a
  generation no one is reading, and **decrements the concurrent-stream counter**
  (Decision 5).
- **Contract fail-safe (mid-stream error).** On any mid-stream inspection/policy/
  timeout/upstream error, the gateway STOPS emitting content chunks, emits exactly
  **one** terminal `event: error` frame carrying the standard `Error` envelope
  (schema `SSEErrorEvent`), and closes the stream **WITHOUT `data: [DONE]`**. The
  client treats a stream ending without `[DONE]` as BLOCKED. (F-004 has no
  inspection/policy engine yet, so in F-004 the error-frame triggers are timeouts,
  upstream failures, and disconnect; the inspection/policy triggers arrive with
  their owning tasks.)
- **`MAX_TOKENS_PER_REQUEST` cap (threat #4).** Enforced at body validation
  (Decision 3, step 7) as a hard ceiling layered on the contract's
  `max_tokens ≤ 131072`, bounding streaming-generation abuse.
- **Partial-stream audit.** If a stream terminates early (disconnect, timeout,
  error frame), the terminal-audit wrapper STILL emits a `usage` event with
  `tokens_out` = tokens counted so far and `latency_ms` = elapsed wall time at
  termination. An early-terminated stream is never un-audited.

**How `tokens_in` / `tokens_out` / `latency_ms` are measured (both paths).**

- `latency_ms` = end-to-end gateway wall time from request receipt to terminal
  outcome, clamped to the schema bound `[0, 3_600_000]`.
- **Non-stream:** `tokens_in`/`tokens_out` come from the upstream response's
  `usage` block when present; if absent, the gateway falls back to a local token
  estimate over the validated request and the returned content. Both are clamped to
  the schema bound `[0, 10_000_000]`.
- **Stream:** the upstream `usage` block is typically absent mid-stream, so the
  gateway counts output tokens incrementally as chunks are emitted and computes
  `tokens_in` from the validated request prompt; on early termination it reports
  the count so far. Cost is a **client-side cost estimate** (`cost_estimate_cents`,
  honest language) derived from token counts, never an authoritative bill.
- On **early-rejected** requests (4xx before the upstream call) the usage event
  carries `tokens_in`/`tokens_out` = 0 and `latency_ms` = elapsed time, so the
  audit trail records the rejected attempt.

### Decision 8 — Upstream proxy

**Decision.** Use a single shared **async `httpx.AsyncClient`** with **mandatory
timeouts** (connect/read/write/pool, driven by `REQUEST_TIMEOUT_SECONDS` and
`STREAM_TIMEOUT_SECONDS`). The upstream request is built by **re-serializing the
typed Pydantic model** — only the contract-allowlisted fields are forwarded.
**There is NO raw body passthrough** (threat #7, upstream injection): unknown keys
were already rejected by the closed schema (Decision 3, step 7) and never reach the
upstream. `UPSTREAM_BASE_URL` is configurable (Decision 9).

**Upstream failure → contract reconciliation (the contract wins).** The contract's
public status list for `/v1/chat/completions` is exactly
`200, 400, 401, 403, 413, 429, 500` — it does **NOT** include `502` or `504`.
Therefore, to conform:

- An upstream **connection refused / connect error** and an upstream **timeout** are
  both surfaced to the client as **`500 internal_error`** with the standard `Error`
  envelope and the fixed `internal_error` message. We do **not** return `502`/`504`
  to the client, because those statuses are not in the contract surface.
- The **true upstream cause** (connect-refused vs timeout vs upstream 5xx) is logged
  **server-side** (without request body or PII, per the contract's privacy rule and
  `CLAUDE.md` non-negotiable #6), correlated by `request_id`. Operators get the
  detail; the client gets the contract-conformant `500`.

This is a deliberate reconciliation: the brief floated returning `502`/`504`, but
the locked contract has no such codes, so the contract wins and upstream failures
collapse to `500 internal_error` on the wire.

### Decision 9 — Config module (pydantic-settings, fail-loud)

**Decision.** Introduce a gateway config module built on **`pydantic-settings`
(`BaseSettings`)** — already a pinned dependency — reading from environment / `.env`.
Required values with no safe default **fail loud at startup** (a missing required
secret raises before the server accepts traffic), consistent with the existing
`os.environ`-with-`RuntimeError` convention but centralized and typed. See the
**Config / env table** below for every variable, default, and whether it is
required. CORS is **default-deny** (threat #11): an explicit allowlist via config,
empty by default, never `*` with credentials.

### Decision 10 — Threat-model mapping

The twelve attack vectors and their owning defense are enumerated in the
**Threat-model defense table** below. Vectors only **partially** addressable in
F-004 (notably request smuggling, which depends on the ASGI server's HTTP parser,
and distributed rate limiting, which is per-worker until F-010) are called out
honestly with their in-scope vs deferred boundary.

---

## Middleware pipeline (ordered; each stage's reject status + error_code)

| # | Stage | Rejects when | Status | error_code |
|---|-------|--------------|--------|------------|
| 1 | Terminal-audit wrapper + exception handlers (outermost) | — (does not reject; guarantees emit on every terminal outcome; forces `500` if audit emit fails) | 500 (on audit failure) | internal_error |
| 2 | Body-size / edge guard | body > `MAX_BODY_BYTES` (1 MiB), checked before parse | 413 (contract permits 400) | request_too_large |
| 3 | Header presence / format gate | any of the four ID headers missing / malformed / > 64 chars | 400 | missing_required_header |
| 4 | Authentication | key missing / malformed / revoked / unknown / expired | 401 | invalid_api_key |
| 5 | ID cross-check (tenant context resolve) | any header (incl. agent) ≠ key-resolved scope | 403 | id_context_mismatch |
| 6 | Rate limit | 600/60 s window (key OR tenant, stricter) OR > 20 concurrent SSE/tenant | 429 (+ Retry-After) | rate_limit_exceeded |
| 7 | Request-body validation | unknown key / out-of-bounds / type error / over `MAX_TOKENS_PER_REQUEST` | 400 | invalid_request |
| 8 | Handler / upstream proxy | upstream connect-refused / timeout / upstream 5xx (cause logged server-side) | 500 | internal_error |
| — | (reserved) policy denial — **F-008**, not emitted by F-004 | policy denies (F-008) | 403 | policy_blocked |

Success path: `200` with `X-Request-Id`, `X-RateLimit-Limit`,
`X-RateLimit-Remaining`, `X-RateLimit-Reset` (and `Retry-After` only on `429`).

---

## Error code → message → status table

`message` strings are **verbatim** from the `contracts/openapi.yaml` `Error.message`
enum. Pairing is a constant lookup, guaranteed in code + unit test (NOT
schema-enforced). No interpolation.

| Failure | error_code | message (fixed, verbatim) | Status |
|---------|------------|---------------------------|--------|
| Missing / malformed / overlong required ID header | `missing_required_header` | "A required header is missing or malformed." | 400 |
| Bad body / unknown key / out-of-bounds field / over `MAX_TOKENS_PER_REQUEST` | `invalid_request` | "The request body is invalid or violates a field constraint." | 400 |
| Body > 1 MiB (`MAX_BODY_BYTES`) | `request_too_large` | "The request body exceeds the maximum allowed size." | 413 |
| Key missing / malformed / revoked / unknown / expired | `invalid_api_key` | "Virtual API key is missing, revoked, or invalid." | 401 |
| Any of four headers ≠ key-resolved scope (incl. agent) | `id_context_mismatch` | "Supplied routing context does not match the API key's authorized scope." | 403 |
| Policy denial — **F-008 only; F-004 does not emit** | `policy_blocked` | "Request blocked by policy for this tenant/team/project/agent context." | 403 |
| Request-rate or concurrent-stream limit exceeded | `rate_limit_exceeded` | "Rate limit exceeded. Retry after the window resets." | 429 |
| Internal failure, upstream connect-refused, upstream timeout, upstream 5xx, audit-emit failure (fail-safe) | `internal_error` | "An internal error occurred. The request was not processed." | 500 |

`request_id` is echoed in BOTH the `X-Request-Id` header and the body. On `429` a
`Retry-After` header is included.

---

## Threat-model defense table (12 vectors)

| # | Vector | Defense in this design | Owning stage / component | In-scope vs deferred (honest) |
|---|--------|------------------------|--------------------------|-------------------------------|
| 1 | Timing attack (key lookup) | Constant-time HMAC fingerprint compare (`hmac.compare_digest`), uniform `VirtualApiKeyAuthError` — no not-found/wrong-key timing distinction | Auth (step 4) via `VirtualApiKeyRepository` (ADR-0004) | In scope |
| 2 | ID smuggling / impersonation | Headers are cross-check ONLY; tenant context resolved server-side from key; mismatch → 403; resolved values (never headers) on events/audit | ID cross-check (step 5), tenant context (Decision 4) | In scope |
| 3 | HTTP request smuggling | Single edge body-size guard before parse; one typed parse path; no raw passthrough | Edge guard (step 2); ASGI server HTTP framing | **Partial** — wire-level smuggling resistance relies on the uvicorn[standard]/httptools parser; gateway adds no second HTTP parser to differ against. We rely on the server parser and keep it pinned/updated; out-of-process WAF is infra-deferred |
| 4 | Streaming abuse / runaway generation | `MAX_TOKENS_PER_REQUEST` cap, `STREAM_TIMEOUT_SECONDS` idle + `REQUEST_TIMEOUT_SECONDS` overall, ≤20 concurrent SSE/tenant, disconnect cancels upstream | Body validation (step 7) + streaming lifecycle (Decision 7) + rate limit (step 6) | In scope |
| 5 | Rate-limit bypass via IP spoofing | Limiter keyed ONLY on virtual-key id + resolved tenant_id, never IP/`X-Forwarded-For` | Rate limit (step 6, Decision 5) | In scope (IP spoof immaterial by design) |
| 6 | Audit bypass | Pure-ASGI TerminalAuditMiddleware wraps send callable — observes every terminal status including direct JSONResponses from inner BaseHTTPMiddleware layers; audit-emit failure forces 500 for NON-STREAM (fail-safe); for STREAM and pre-route rejections where response is already committed, failure logged at ERROR level out-of-band (inherent SSE constraint); chain append on privileged session | Terminal wrapper (step 1, Decision 3 + HIGH-3 amendment) | In scope (with documented SSE honest-scope caveat) |
| 7 | Upstream injection (smuggled fields) | Closed Pydantic schema rejects unknown keys; upstream request re-serialized from typed model; NO raw body passthrough | Body validation (step 7) + upstream proxy (Decision 8) | In scope |
| 8 | Memory exhaustion (oversize body) | 1 MiB edge cap checked before parse; per-field bounds; bounded `messages`/`content` | Edge guard (step 2) | In scope |
| 9 | Information disclosure | Fixed enum messages, no interpolation, no body/PII/header content in errors or logs; correlate by `request_id`; upstream cause logged server-side only | Error mapping (Decision 6), upstream proxy (Decision 8) | In scope |
| 10 | Session / state leakage across requests | Tenant context request-scoped (contextvar set/reset per request); no process-global mutable context; transaction-local GUC (ADR-0005) | Tenant context (Decision 4), persistence (ADR-0005) | In scope |
| 11 | CORS misconfiguration | Default-deny CORS; explicit config allowlist; never `*` with credentials | Config (Decision 9) | In scope |
| 12 | Header injection / CRLF | Fixed enum error messages (no header/value echo); `request_id` charset bounded (events schema `^[A-Za-z0-9._-]{1,64}$`); no client-controlled value reflected into response headers or logs unsanitized | Error mapping (Decision 6), terminal wrapper (step 1) | In scope (response-side); upstream/log sinks must preserve the bounded charset |

---

## Streaming lifecycle (summary)

```
client --stream:true--> [pipeline steps 1-7] --> handler
  handler opens httpx stream to UPSTREAM_BASE_URL (mandatory timeouts)
  concurrent-stream counter += 1   (per resolved tenant; cap 20)
  loop:
    read upstream chunk
      -- idle gap > STREAM_TIMEOUT_SECONDS  --> FAIL-SAFE: error frame, no [DONE]
      -- overall > REQUEST_TIMEOUT_SECONDS  --> FAIL-SAFE: error frame, no [DONE]
      -- upstream error / disconnect        --> close upstream; FAIL-SAFE: error frame, no [DONE]
    inspect-before-flush (F-008 hook; F-004 has no inspector yet)
    emit ChatCompletionChunk (data: ...)
  on normal completion: emit `data: [DONE]`
  finally:
    concurrent-stream counter -= 1   (close / complete / error / disconnect)
    emit usage event (tokens_out so far, latency_ms elapsed) via terminal wrapper
```

A stream that ends WITHOUT `data: [DONE]` MUST be treated by the client as BLOCKED
(contract). The terminal `event: error` frame carries the standard `Error`
envelope (`SSEErrorEvent`). Every stream — complete or early-terminated — produces
exactly one `usage` event.

---

## Config / env table

Built on `pydantic-settings`; required-without-default values fail loud at startup.

| Env var | Purpose | Default | Required |
|---------|---------|---------|----------|
| `UPSTREAM_BASE_URL` | Upstream provider base URL for the proxy | — | Yes |
| `REQUEST_TIMEOUT_SECONDS` | Overall per-request timeout (non-stream + stream cap) | (sane default, e.g. 60) | No |
| `STREAM_TIMEOUT_SECONDS` | Idle gap timeout between SSE chunks | (sane default, e.g. 30) | No |
| `MAX_BODY_BYTES` | Edge body-size cap; **MUST match contract 1 MiB** | `1048576` | No |
| `MAX_TOKENS_PER_REQUEST` | Hard ceiling on requested generation tokens (≤ contract 131072) | (sane default ≤ 131072) | No |
| `RATE_LIMIT_RPM` | Requests per 60 s sliding window (contract default) | `600` | No |
| `RATE_LIMIT_BURST` | Short-term burst bound within the window | (sane default) | No |
| `MAX_CONCURRENT_STREAMS_PER_TENANT` | Concurrent open SSE streams per resolved tenant (contract default) | `20` | No |
| `CORS_ALLOWED_ORIGINS` | Explicit CORS allowlist (default-deny; never `*` w/ credentials) | empty (deny) | No |
| `DATABASE_URL` | Privileged engine (audit-chain ops, migrations) — reused from ADR-0004/0005 | — | Yes |
| `APP_DATABASE_URL` | Tenant-scoped engine (`sentinel_app`, NOBYPASSRLS) — reused from ADR-0005 | — | Yes |
| `SENTINEL_KEY_SECRET` | HMAC secret for virtual-key fingerprinting — reused from ADR-0004 | — | Yes |

`MAX_BODY_BYTES` defaulting to `1048576` keeps the edge guard aligned with the
contract's 1 MiB cap; overriding it below the contract value is allowed (stricter),
above it is a divergence the deployment owns. `MAX_TOKENS_PER_REQUEST` must not be
configured above the contract's `max_tokens` maximum of 131072.

---

## Consequences

### Positive

- A single, ordered pipeline with one terminal-emit point makes the audit guarantee
  (event + chain row on EVERY outcome, including 4xx/5xx) structural rather than
  best-effort — auditing cannot be skipped by an early rejection.
- The contract is honored end-to-end: exact `error_code`/`message`/status mapping,
  server-resolved attribution only, dual-scoped sliding-window rate limiting, the
  SSE fail-safe, and the 1 MiB edge cap, all without touching a contract file.
- Closed Pydantic models give boundary validation and upstream-injection defense
  (no raw passthrough) for free, reusing the existing FastAPI/Pydantic stack.
- Upstream failures collapse to the contract's `500 internal_error` on the wire
  while preserving operator-grade cause detail server-side — conformant and
  debuggable.
- Tenant context is request-scoped and resolved from the key, eliminating
  cross-request state leakage by construction (paired with ADR-0005's
  transaction-local GUC).

### Negative / costs

- In-process rate limiting is **per-worker**: the global effective limit scales
  with worker/replica count, and the concurrent-stream cap is per-worker until the
  F-010 Redis-backed limiter lands. Documented honestly, not hidden.
- The terminal-audit wrapper adds a privileged-session write on the hot path of
  **every** request (including rejected ones), a cost we accept for non-bypassable
  auditing; it must be efficient and must itself fail safe (audit failure → 500).
- F-004 ships only `/v1/chat/completions`; `/v1/completions` and `/v1/models` users
  must wait for the follow-up. The pipeline is built to absorb them cheaply.
- `policy_blocked` is wired in the table but inert until F-008; an operator reading
  the code sees a mapping that cannot fire yet (documented to avoid confusion).

### What stays deferred

- **Per-worker in-process rate limiting multiplies the effective per-tenant ceiling by the worker/replica count; Redis-backed distributed rate limiting in F-010 closes this.**
- **`POST /v1/completions` and `GET /v1/models`** — F-004 follow-up (same pipeline).
- **`policy_blocked` emission + policy evaluation / signed-policy intake** — **F-008**
  (the contract code and `policy.schema.json` are already in place; F-004 only
  reserves the mapping).
- **Model fallback / multi-provider routing** — **F-006**.
- **Redis-backed distributed rate limiting + observability (metrics/tracing
  surfacing the X-RateLimit state globally)** — **F-010**.
- **Shadow-AI detection** (`shadow_ai_detected` event) — **F-007**.
- **Inspection engines** (PII / prompt-injection / secret-leak — the inspect-before-
  flush hook in the streaming lifecycle) — their owning data-protection / defense
  tasks; F-004 leaves the hook point but ships no inspector.
- **Out-of-process / coarse pre-auth flood protection** (ingress/WAF connection
  caps) — infra concern, not this in-process pipeline.

---

## Summary of decisions

| Decision | Choice | Primary rationale |
|----------|--------|-------------------|
| Framework | FastAPI on uvicorn[standard] | Already pinned; Pydantic closed-schema validation + ASGI streaming + exception hooks |
| F-004 endpoint scope | `/v1/chat/completions` full; `/v1/completions` + `/v1/models` deferred | Prove the pipeline once; cheap to extend |
| Operational endpoints | `/health` (liveness), `/ready` (DB) — outside `/v1`, no tenant data | Not contract API endpoints; not added to openapi.yaml; no "invented" surface |
| Pipeline order | size → headers → auth → id-cross-check → rate-limit → body-validate → handler, under a terminal-audit wrapper | Cheap pre-auth rejects; rate limit needs resolved key+tenant |
| Audit coverage | Pure-ASGI outermost send-wrapper (TerminalAuditMiddleware) + exception handlers; emits on every terminal outcome including inner-middleware direct JSONResponses; audit failure → 500 for non-stream; for streams, failure logged out-of-band at ERROR level (inherent SSE constraint, honest scope) | Auditing must not be bypassable by early middleware rejection; streaming honest-scope documented |
| Tenant context | Resolved from key; headers (incl. agent) cross-checked → 403; request-scoped; resolved values only on events/audit | Conform to contract; threat #2 + #10 |
| Rate limiting | In-process sliding window, dual key+tenant (stricter wins) + ≤20 SSE/tenant; keyed never on IP | Contract semantics; brief config names; per-worker honesty; Redis → F-010 |
| Error mapping | Constant code→message→status table, verbatim contract strings, no interpolation, unit-tested | Contract pairing not schema-enforced; threat #9/#12 |
| Streaming | Backpressure + idle/overall timeouts + disconnect-cancels-upstream + fail-safe error frame (no `[DONE]`) + partial-stream usage event | Contract SSE fail-safe + threat #4 |
| Upstream proxy | Shared async httpx, mandatory timeouts, typed re-serialize (no raw passthrough); upstream failure → `500 internal_error` | Threat #7; contract has no 502/504 — contract wins |
| Config | `pydantic-settings`, fail-loud on missing required; default-deny CORS | Already a dep; centralized typed config; threat #11 |
| Contracts / stable IDs | unchanged | This work edits no contract file |
| Framing | "audit-ready", "risk reduction" — never "compliant" / "blocks all" | Honest language per CLAUDE.md |
