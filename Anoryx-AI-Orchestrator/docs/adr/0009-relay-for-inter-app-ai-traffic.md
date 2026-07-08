# ADR-0009 — Governed Relay for Inter-App AI Traffic

- Status: Accepted
- Date: 2026-07-08
- Task: O-009 (ninth Orchestrator task, first task from the Phase 2 ecosystem-integration
  layer)
- Builds on: ADR-0004 (O-004 policy distribution — the outbound-httpx + audit pattern this
  reuses), ADR-0005 (O-005 multi-Sentinel registry — the SSRF gate + health-gated target
  selection this reuses verbatim)
- Supersedes: nothing. Adds one new seam, one new hash chain, and embedded relay settings;
  does not alter the O-003 ingest pipeline, O-004 distribution engine, O-005 registry/
  coordination, O-006 read seams, or O-007 admin API.

## Context

The roadmap lists O-009 as **"Centralized Sentinel proxy for all inter-app traffic"** under
the Orchestrator's Phase 2 ecosystem-integration layer, marked **🏦 POST-INVESTMENT** — the
roadmap's own governance text states post-investment tasks are "scheduled for after a funding
round" and "not next-buildable," gated behind capital, not merely behind the Orchestrator's own
MVP (O-001→O-008, which is fully shipped). This run initially stopped in front of that gate, on
the reasoning that dispatching a Heavy (22-30h), High-risk, funding-gated task without explicit
authorization would be scope creep. **The task owner then explicitly instructed proceeding with
post-investment tasks too.** That instruction is the authorization this ADR records; it lifts
the funding-round gate for this run, not the ordinary engineering discipline the rest of this
document applies.

The roadmap's literal ask — "every inter-app data flow (Delta↔Rendly↔Sentinel) routed through a
Sentinel-governed proxy that monitors, redacts, and filters... the literal enforcement of 'data
never leaves the org' at the ecosystem level" — describes a data-plane proxy sitting in front of
*all* traffic between three products. That is not buildable as a single, honest PR today:

- **There is no existing inter-app data plane to intercept.** Delta and Rendly do not currently
  call each other, or call Sentinel, through the Orchestrator for anything but events (O-003),
  policies (O-004), and read queries (O-006) — none of which is "AI traffic" in the sense the
  roadmap phrase means (an LLM request). There is nothing today that a transparent interception
  layer would transparently intercept.
- **Sentinel's monitor/redact/filter behavior (F-005's PII/injection/secret/shadow-AI detectors)
  is not an importable library.** It is Sentinel-internal code (Presidio + spaCy's large English
  model, tightly coupled to Sentinel's own hook framework and event emission), not packaged for
  reuse, and pulling Presidio/spaCy into the Orchestrator's image would directly contradict
  ADR-0008 Fork C1 ("no optional heavy extras"). Re-implementing those detectors here would be a
  second, divergent copy of security-critical logic — exactly the kind of drift CLAUDE.md's
  "contract is the law" / single-source-of-truth discipline exists to prevent.
- **Protect-paths scope.** This task must be implemented inside `Anoryx-AI-Orchestrator/` — the
  roadmap's own "Builder: gateway-core + orchestration" tag names agents scoped to
  `Anoryx-Sentinel/src/gateway` and `Anoryx-Sentinel/src/orchestration` respectively, which
  cannot write here, and this run must not write there either.

This ADR resolves that tension the same way ADR-0008 resolved O-008's "Vault, mTLS provisioning"
literal text: ship the piece that is genuinely buildable and useful now, and name the rest as an
honest deferral rather than build a first-of-its-kind, unreviewed proxy on top of infrastructure
that does not exist yet.

## Decision — resolved forks

| Fork | Decision |
|------|----------|
| **A** — what "governed relay" means without an existing data plane | **A1**: a NEW, explicit, opt-in seam (`POST /v1/relay/dispatch`) that Delta/Rendly call to route an outbound AI request (an OpenAI-compatible call) *through* the Orchestrator to a specific registered Sentinel, rather than calling that Sentinel directly. This is a governed ROUTING + AUDIT layer, not a transparent network interception layer — there is no traffic to transparently intercept yet, and inventing one would be speculative infrastructure with no consumer. |
| **B** — who does the actual monitoring/redaction | **B1**: Sentinel's own already-shipped gateway (F-004/F-005/F-006) does it, unchanged, when the forwarded request lands on its real `/v1/chat/completions` (or `/v1/completions`, `/v1/models`) endpoint. This module's job is centralizing *which* Sentinel a request reaches and *auditing* that it was routed — never re-implementing PII/injection/secret detection. |
| **C** — target selection | **C1**: reuse the O-005 registry verbatim — a dispatch target must be a registered, `enabled`, effective-`healthy` (staleness-aware) Sentinel, and its endpoint is re-validated through the SSRF gate immediately before every outbound call (never trusting a stored endpoint). Same discipline as the O-004/O-005 outbound calls; no new SSRF surface invented. |
| **D** — request shape (URL path segment vs. body field) | **D1**: `target_path` travels as a REQUEST BODY field, not a URL catch-all path segment. A `{target_path:path}`-style FastAPI catch-all route is not representable in a standard OpenAPI 3.1 path template, and a body field is trivially validated against a closed server-side allowlist before any dispatch — cleaner and more auditable than parsing/validating an arbitrary URL suffix. |
| **E** — path allowlist | **E1**: `target_path` MUST be one of `ORCH_RELAY_ALLOWED_PATHS` (default: Sentinel's three shipped OpenAI-compatible paths). A CLOSED allowlist, not an open passthrough to any Sentinel route — the relay is a governed seam onto Sentinel's real gateway, not a general reverse proxy. |
| **F** — auth model (two separate credentials) | **F1**: (1) a per-source-product bearer (`ORCH_RELAY_SOURCE_TOKENS`, keyed `delta`/`rendly`) authenticates the CALLER — source_product is server-resolved from the matched token, mirroring the ingest seam's source_product discipline, never accepted from the body; (2) the TENANT'S OWN Sentinel virtual API key travels in a separate `X-Sentinel-Authorization` header and is forwarded to Sentinel unchanged as its real `Authorization` header. The Orchestrator never mints, stores, or inspects that key — it is a pure pass-through, preserving Sentinel's own per-tenant auth boundary exactly as if the tenant had called Sentinel directly. |
| **G** — retry policy | **G1**: exactly ONE outbound attempt, no automatic retry — unlike O-004/O-005's fire-and-forget bounded retries, a relay dispatch is a synchronous call an interactive caller is blocked on, and auto-retrying a non-idempotent LLM request risks duplicate provider cost / duplicate side effects. A caller that wants a retry issues a new request. |
| **H** — response semantics | **H1**: a TRANSPARENT relay — Sentinel's own status code and body are returned unchanged (never normalized to 200). A non-2xx from Sentinel (e.g. its own hooks blocked the content, or its own auth rejected the virtual key) is Sentinel's decision, relayed as-is; it is a successful DISPATCH (audited `forwarded`), not a relay failure. |
| **I** — streaming | **I1**: NOT supported in v1. A `payload.stream: true` request is rejected (422, `streaming_not_supported`) before any outbound call. Relaying Sentinel's SSE stream correctly (chunked forwarding, backpressure, partial-failure semantics) is real additional scope this pass does not take on. |
| **J** — audit chain shape / RLS | **J1**: a NEW global hash chain (`relay_audit_log`), mirroring `sentinel_registry_audit_log` exactly — no RLS (cross-tenant fleet infrastructure, not tenant-owned data, same precedent as the O-005 registry), `tenant_id` carried as a plain attribution column. Records every dispatch attempt: `forwarded` (Sentinel answered, any status), `blocked` (target unknown/disabled/unhealthy/SSRF-invalid — nothing sent), or `failed` (transport-layer error). The payload itself is NEVER logged or persisted — only a sha256 `content_hash` + short metadata. |
| **K** — no read/query API for the chain | **K1**: DEFERRED. This pass ships write + hash-chain-validate (`validate_relay_chain`, mirroring `validate_registry_chain`) but no operator-facing "recent relay dispatches" read seam (the O-007 admin-API pattern). Adding one is a natural, small follow-up, not bundled here to keep this PR's diff reviewable. |

## API addition

### `POST /v1/relay/dispatch`

Request: `{tenant_id, sentinel_id, target_path, payload}`. Auth: `mutualTLS` (declared, not
enforced until O-008, matching every other seam's honesty posture) + `relaySourceBearer` +
the `X-Sentinel-Authorization` header. Response: Sentinel's real status code + body,
unchanged. Errors before any outbound call: `401` (missing/wrong source bearer or missing
tenant-key header), `422` (schema / unknown-field / NUL / oversized / path-not-allowed /
streaming-not-supported), `413` (body over `ORCH_RELAY_MAX_BODY_BYTES`), `503`
(`RelayTargetUnavailable` — target unknown/disabled/unhealthy/SSRF-invalid), `502`
(`RelayUpstreamError` — transport-layer failure).

## Data access

`relay.client.relay_request` resolves the target via `coordination.registry.fetch_sentinel`
(privileged read, no RLS — same as the O-004/O-005 registry lookups), re-validates the endpoint
via `coordination.endpoint_validation.validate_endpoint_async`, then makes the single outbound
`httpx` call. Every terminal outcome appends one `relay_audit_log` link via
`get_privileged_session()` + `session.begin()` (the chain-append discipline every other
Orchestrator chain uses) — never inside `get_tenant_session` (no double-begin risk, since this
table has no tenant GUC to set in the first place).

## Honesty boundaries (verbatim — non-removable)

- **This is NOT the roadmap's literal "every inter-app data flow... routed through a proxy."**
  It is an OPT-IN dispatch seam Delta/Rendly must deliberately call; there is no transparent
  interception of any traffic that does not explicitly come through `/v1/relay/dispatch`.
- **This does NOT re-implement Sentinel's PII/injection/secret/shadow-AI detection.** Those run
  on Sentinel's own gateway when the forwarded request lands there — this seam performs
  centralized, governed ROUTING + AUDIT, not detection.
- **"Data never leaves the org" is Sentinel's claim about its own gateway, not a new guarantee
  this seam adds.** The relay's contribution is: the dispatch went through a registered, healthy,
  SSRF-validated Sentinel and that fact is durably, tamper-evidently recorded — not a new
  data-sovereignty enforcement mechanism.
- **No streaming.** A streaming request is rejected outright (Fork I), never silently
  downgraded to a buffered response Sentinel didn't actually send that way.
- **No automatic retry.** A caller that wants one issues a new request (Fork G) — this seam
  never duplicates a non-idempotent LLM call on the caller's behalf.
- **No operator read seam for the new chain yet** (Fork K) — an operator validates the chain's
  integrity via `validate_relay_chain` today; a triage UI is a natural, un-bundled follow-up.
- **Dispatched only via THIS run's explicit authorization to build post-investment tasks.** The
  roadmap's own 🏦 label means this was not scheduled as next-buildable MVP work; it shipped
  because the task owner explicitly instructed proceeding past that gate in this session, which
  is recorded here for anyone auditing why an O-009-numbered, Phase-2-labeled task landed ahead
  of the roadmap's stated sequencing.

## Threat model

| Threat | Mitigation |
|--------|------------|
| SSRF via a manipulated/rebound Sentinel endpoint | Reuses the O-005 gate verbatim: re-resolved and re-validated (private/loopback/link-local/reserved rejected unless operator-allowlisted) immediately before EVERY outbound call, never trusting the stored registry row. |
| Relay-source token theft / cross-source impersonation | Constant-time compare across every configured token (`hmac.compare_digest`); source_product is resolved FROM the matched token, never claimed by the caller; a caller holding Delta's token cannot claim to be Rendly. |
| Tenant Sentinel-key exposure | The `X-Sentinel-Authorization` value is never logged, stored, or included in the audit chain — forwarded once, in-memory, to Sentinel and discarded. |
| Payload / prompt content leaking into the audit trail | The chain records only a sha256 `content_hash` + short metadata (tenant_id, source_product, sentinel_id, target_path, disposition, status_code, error_reason) — never the payload itself. |
| Open-proxy abuse (relay to an arbitrary Sentinel path) | Closed, operator-configured `target_path` allowlist (Fork E), enforced before any outbound call. |
| Duplicate LLM cost from an automatic retry | No automatic retry (Fork G) — a transport failure is `failed`, once, and returned to the caller. |
| Resource exhaustion via an oversized payload | `ORCH_RELAY_MAX_BODY_BYTES` cap (default 1 MiB) enforced before JSON parsing. |
| Tamper on the relay audit chain | Append-only via BEFORE UPDATE/DELETE deny-triggers + SHA-256 hash chain (mirrors every other Orchestrator chain); `validate_relay_chain` re-verifies the full chain. |

## Residual risk (known, deferred)

- **No operator read/triage seam for `relay_audit_log`** (Fork K) — chain integrity is
  checkable via `validate_relay_chain`, but there is no "recent relay dispatches" UI/API yet.
- **No streaming support** — a real caller wanting a streamed completion cannot use this seam
  in v1; it must call Sentinel directly (bypassing the relay's audit trail) or wait for a
  streaming-relay follow-up.
- **`target_path` allowlist is static/operator-configured**, not derived from Sentinel's live
  declared capabilities (unlike the O-005 registry's `capabilities` field, which IS
  policy-type-aware) — a Sentinel instance that does not actually implement a listed path
  still passes the allowlist check and only fails at the real HTTP call.
- **No mTLS enforcement** (declared, not live) — unchanged from every other seam; deferred to
  O-008, same as ADR-0008 already states.
- **This is not the roadmap's full ecosystem-proxy vision** (O-009's literal text) — it is the
  smallest honest, buildable slice of it. The remaining gap (transparent interception of
  genuinely inter-product traffic once such traffic exists) is real future work, not silently
  claimed as done here.

## Configuration

New environment variables (all resolved NON-FATALLY — absence is not fatal; an unconfigured
relay fail-closed-401s every request since no source token can ever match):

- `ORCH_RELAY_SOURCE_TOKENS` — JSON object `{"delta"|"rendly": bearer_token}` (`{}` if unset).
- `ORCH_RELAY_ALLOWED_PATHS` — comma-separated Sentinel path allowlist (default the three
  shipped OpenAI-compatible paths).
- `ORCH_RELAY_HTTP_TIMEOUT` — per-dispatch outbound HTTP timeout seconds (default 30.0).
- `ORCH_RELAY_MAX_BODY_BYTES` — request-body size cap in bytes (default 1 MiB).

## Testing

- **Unit** (`tests/unit/test_relay_config.py`, `test_relay_router.py`, `test_hash_chain_relay.py`):
  env-parsing (defaults, misconfiguration ConfigErrors, known-source-product validation);
  the auth/allowlist/schema boundary (missing/wrong source bearer → 401, missing tenant-key
  header → 401, unknown fields / bad path / oversized body / streaming request → 422/413) —
  all return before any DB or outbound call, so no Postgres is needed; the relay hash-chain's
  opt-in-when-present + tamper-evidence properties (mirrors `test_hash_chain_registry.py`).
- **Integration** (`tests/integration/test_relay_e2e.py`, `pytest.mark.integration`): a
  NON-STUBBED e2e over a real loopback socket — registers a real Sentinel-shim instance (the
  existing test-only `_sentinel_shim.py` pattern, extended with a lightweight relay-target
  route standing in for Sentinel's real OpenAI-compatible surface, the same way it already
  stands in for Sentinel's admin-intake route), dispatches through the real HTTP router,
  and proves: a healthy+capable target is genuinely forwarded and Sentinel's real response is
  relayed back unchanged; an unregistered/disabled/unhealthy target is `blocked` before any
  outbound call; the relay chain validates; a wrong source token is rejected. Gated by
  `ORCH_REQUIRE_RELAY_E2E=1` in CI (fail, not silently skip, mirroring the O-005/O-006 gates).

## Out of scope (do not build here)

Transparent interception of ANY traffic not explicitly routed through `/v1/relay/dispatch`;
re-implementing Sentinel's PII/injection/secret/shadow-AI detectors; streaming relay; automatic
retry; an operator read/triage UI for the new chain; mTLS provisioning (O-008); the remaining
O-009→O-014 ecosystem-integration-layer tasks (unified identity, cross-module automation
engine, sub-ms messaging backbone, global third-party gateway, command dashboard).

## Consequences

- Delta/Rendly gain a real, working, audited path to route AI traffic through a specific
  registered Sentinel without the Orchestrator ever seeing (or needing to understand) the
  content itself — Sentinel's own already-shipped gateway does the actual governance.
- The relay is additive and reuses the O-005 registry + SSRF gate + audit-chain machinery
  verbatim; no existing seam, engine, or schema changed.
- The gap between this slice and the roadmap's full "every inter-app data flow" vision is
  named explicitly here (Honesty boundaries, Residual risk, Out of scope) rather than implied
  away — consistent with CLAUDE.md's mandatory honest-language rule and the banked process
  rule that a feature's real scope, when narrower than its name implies, must be stated
  verbatim rather than silently assumed complete.
