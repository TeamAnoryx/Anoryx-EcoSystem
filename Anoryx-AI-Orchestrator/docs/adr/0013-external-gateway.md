# ADR-0013 — Third-Party API-Key Gateway (not a global cross-product proxy)

- Status: Accepted
- Date: 2026-07-08
- Task: O-013 (thirteenth Orchestrator task, first task from the roadmap's Phase 2
  "Global API gateway for third-party interactions" line)
- Builds on: ADR-0006 (O-006 `require_tenant_principal` / `query_service_tokens` — the
  hashed-secret, operator-global-lookup credential shape this reuses), ADR-0007 (O-007
  admin API — the `_require_admin` operator-bearer boundary this reuses verbatim),
  ADR-0011 (O-011 automation engine — the per-tenant advisory-lock-then-COUNT cap idiom),
  ADR-0012 (O-012 messaging — the "every attempt is chain-audited" semantics this reuses)
- Supersedes: nothing. Adds one new package (`external_gateway`), three new tables, one
  new hash chain, and a standalone `ExternalGatewaySettings`; does not alter any existing
  seam, engine, schema, or credential.

This run's default posture is to stop in front of the 🏦 POST-INVESTMENT gate; the task
owner has explicitly authorized proceeding with post-investment tasks in this run — the
same standing authorization already recorded in ADR-0009/ADR-0010/ADR-0011/ADR-0012.

## Context

The roadmap lists O-013 as **"Global API gateway for third-party interactions.
Standardized external-facing gateway for all third-party interactions with the ecosystem
(rate-limit, auth, governance applied uniformly). Overlaps F-026 (MCP layer) — reconcile
when both are reached."** — in the same Phase-2 ecosystem-integration tier as
O-009/O-010/O-011/O-012, and it names a dependency (F-026) that does not exist. This is
not buildable as a single, honest PR today, for two independent reasons, the same shape
as every prior Phase-2 ADR:

- **"Global... for all third-party interactions with the ecosystem" implies a
  cross-product proxy fronting Sentinel, Delta, and Rendly alike.** No such shared
  ingress exists — each product owns its own API surface, and this repo's protect-paths
  hook confines `Anoryx-AI-Orchestrator/` code to its own directory; it must not reach
  into `Anoryx-Sentinel/`, `Delta/`, or `Rendly/` to front their APIs.
- **"Overlaps F-026 (MCP layer) — reconcile when both are reached" is an explicit
  roadmap instruction to wait for F-026, and F-026 is unshipped** (still 🔮 SPECULATIVE
  on the Sentinel checklist). Building the "reconciled" version now would mean
  inventing F-026's shape unilaterally, which is not this task's call to make.

This ADR resolves that tension the same way ADR-0009→ADR-0012 resolved their own literal
roadmap text: ship the smallest genuinely useful, honest slice of what "rate-limit, auth,
governance applied uniformly" concretely means — a real API-key credential class, distinct
from every existing Orchestrator credential, that gates ONE Orchestrator-owned read seam
with rate limiting, scope enforcement, and a uniform, tamper-evident audit trail — and name
everything else (the cross-product proxy, F-026 integration, any other product's surface)
as an honest, explicit deferral, never implied as done.

## Decision — resolved forks

| Fork | Decision |
|------|----------|
| **A** — what "global gateway for all third-party interactions" means without a cross-product proxy or F-026 | **A1**: a NEW credential class (`third_party_api_keys` + `X-Api-Key`), distinct from every existing Orchestrator credential (`ORCH_SERVICE_TOKEN`, `ORCH_ADMIN_TOKEN`, `query_service_tokens`), gating exactly ONE Orchestrator-owned read seam (`GET /v1/external/events`, mirroring the O-006 `GET /v1/events` projection). Rate-limit, auth, and governance are all real and uniformly enforced — for this one seam, not "all third-party interactions with the ecosystem." |
| **B** — auth model | **B1**: a per-key SHA-256-hashed secret (`eak_...`), issued by an operator via `POST /v1/admin/external-keys` (gated by the EXISTING `ORCH_ADMIN_TOKEN` / `_require_admin`, mirrors O-007), never self-service. Each key is scoped to exactly ONE tenant (the key's `tenant_id`, set at issuance — not caller-supplied per-request, unlike `require_tenant_principal`'s Bearer-resolves-tenant shape, which this mirrors structurally but issues through a distinct admin flow). |
| **C** — capability model ("governance applied uniformly") | **C1**: a closed, explicit `scopes` enum (`_KNOWN_SCOPES`), currently `{"events:read"}` only. An issuance request naming any scope outside this set is a 422 — there is no way to grant a capability the router does not actually enforce somewhere. Extending the gateway to a second seam means adding both a new scope value AND the route that checks it, in the same PR — never widening the enum alone. |
| **D** — rate limiting without Redis | **D1**: a Postgres fixed-window counter (`external_gateway_rate_limit_counters`, PK `(key_id, window_start)`, `window_start` truncated to the minute), incremented via a single atomic `INSERT ... ON CONFLICT ... DO UPDATE ... RETURNING request_count` — no advisory lock needed (Postgres's own upsert is atomic), no broker (mirrors ADR-0008's "no optional heavy extras" and ADR-0012's identical no-broker reasoning). This is an honest fixed window, not a sliding one — a burst straddling a window boundary can momentarily exceed the configured rate by up to 2x; named here, not hidden (see Honesty boundaries). |
| **E** — master enable/disable switch | **E1**: YES, `ORCH_EXTERNAL_GATEWAY_ENABLED` (default `false`) — UNLIKE O-012's messaging seams (Fork I there: no switch, because those reuse an existing internal trust root as ordinary CRUD). This is the OPPOSITE case: `GET /v1/external/events` is the Orchestrator's FIRST surface intended for a credential class outside the existing internal-product/tenant trust boundary, so an unconfigured deployment must not silently expose it merely by upgrading. Key issuance/revocation is NOT gated by this switch (an operator may provision keys ahead of enabling the read seam, mirroring how `POST /v1/automation/rules` works regardless of `ORCH_AUTOMATION_ENABLED`). |
| **F** — audit-chain semantics ("every attempt" vs. "only genuine outcomes") | **F1**: `external_gateway_audit_log` records every request attempt for which a key resolved to a tenant — `allowed`, `scope_denied`, `rate_limited`, AND `revoked` all get a chain link. Mirrors O-012's messaging-chain choice (Fork F there), for the identical reason restated for this domain: the entire point of a governance gateway is a durable record of what was TRIED, not only what succeeded — a security team auditing third-party access needs the denials at least as much as the successes. A wholly unknown/malformed key resolves NO tenant at all and is therefore never audited here (mirrors `PrincipalAuthError`'s identical non-audited-401 precedent — there is no tenant to attribute the row to). |
| **G** — key-cap enforcement without RLS | **G1**: `third_party_api_keys` carries NO RLS (Fork H below), so the per-tenant cap (`ORCH_EXTERNAL_GATEWAY_MAX_KEYS_PER_TENANT`) is enforced via an EXPLICIT `WHERE tenant_id = :tenant_id` COUNT, preceded by a tenant-keyed `pg_advisory_xact_lock` in the SAME transaction as the INSERT (TOCTOU-safe, mirrors `lock_messaging_message_cap` / `lock_automation_rule_cap` exactly — the only difference from those precedents is the explicit filter replacing RLS's implicit one). |
| **H** — table RLS scope | **H1**: `third_party_api_keys` is OPERATOR-GLOBAL, NO RLS (mirrors `query_service_tokens`/ADR-0006 exactly — the auth lookup must resolve tenant BEFORE any GUC is set, chicken-and-egg). `external_gateway_rate_limit_counters` is also NO RLS (pure internal bookkeeping, never tenant-readable). `external_gateway_audit_log` DOES carry RLS (SELECT scoped to `tenant_id`, mirrors `agent_messaging_audit_log` — genuinely tenant-relevant audit data, even though no tenant-facing read endpoint exposes it in THIS PR). |
| **I** — revocation semantics | **I1**: `POST /v1/admin/external-keys/{key_id}/revoke` is IDEMPOTENT — revoking an already-revoked key re-applies the same UPDATE and returns 200 with the current (still-revoked) state, never an error. A revoked key's OWN requests still resolve (its tenant is known) and are chain-audited as `revoked`, then rejected 403 — this is what makes a revoked key's post-revocation access ATTEMPTS visible in the audit trail, not merely its non-access. |
| **J** — key-count cap counts revoked rows | **J1**: revoking a key does NOT free its slot in the per-tenant cap (the row is never deleted — only `status`/`revoked_at` change). An operator who wants headroom back must be aware revocation alone does not reclaim it. Named explicitly (Residual risk) rather than silently surprising an operator who revokes-then-reissues expecting the cap to reset. |

## API additions

- `POST /v1/admin/external-keys` — issue. Body: `{tenant_id, label, scopes: [...],
  rate_limit_per_minute?}` → `201 {key_id, api_key, tenant_id, label, scopes, status,
  rate_limit_per_minute, created_at, revoked_at}`. `api_key` (the plaintext secret)
  appears in THIS response only.
- `GET /v1/admin/external-keys?tenant_id=` — list (metadata only, never `key_hash`/plaintext).
- `POST /v1/admin/external-keys/{key_id}/revoke` — idempotent revoke.
- `GET /v1/external/events?limit=&cursor=` — the gated third-party read. `X-Api-Key`
  header credential. `200 {data: [EventMetadata...], next_cursor}` / `401` (missing/unknown
  key) / `403` (revoked / scope-denied) / `404` (gateway disabled) / `422` (malformed
  cursor) / `429` (rate limited).

The three admin endpoints reuse `operatorBearer` (the SAME scheme as the existing O-007
admin API); the gated read is a NEW scheme, `externalApiKey` (`X-Api-Key` header).

## Data access

`external_gateway.router` runs key issuance/listing/revocation on `get_privileged_session()`
(the table carries no RLS — Fork H). The gated read resolves the caller's
`ExternalGatewayPrincipal` via `require_third_party_api_key` (privileged lookup, mirrors
`require_tenant_principal`), then opens `get_tenant_session(principal.tenant_id)` for the
actual event read — RLS still structurally scopes it, exactly like the internal
`GET /v1/events` seam. The rate-limit increment and every audit-chain append run on
separate `get_privileged_session()` + `session.begin()` blocks (mirrors every other
Orchestrator chain's discipline — never nested inside the tenant session's autobegin).

## Honesty boundaries (verbatim — non-removable)

- **This is NOT a global gateway for all third-party interactions with the ecosystem.**
  It gates exactly ONE Orchestrator-owned read seam (`GET /v1/external/events`). Sentinel,
  Delta, and Rendly's own APIs are untouched — nothing here fronts, proxies, or governs
  traffic to any other product.
- **This does NOT integrate with F-026 (the MCP layer).** F-026 does not exist yet; the
  roadmap's own text says to reconcile when both are reached — that reconciliation is
  future work, not something this PR can honestly do unilaterally.
- **This is NOT a sliding-window rate limiter.** `ORCH_EXTERNAL_GATEWAY_*` limits are
  enforced via a fixed one-minute window; a burst straddling a window boundary can
  momentarily exceed the configured rate by up to roughly 2x. A stricter sliding-window or
  token-bucket limiter is real, separate, out-of-scope future work.
- **This does NOT provide per-request client attribution beyond the key.** Every request
  made with a given key is indistinguishable from any other made with the SAME key — there
  is no sub-key identity (mirrors O-012 Fork J2's identical "caller-asserted label, not a
  verified identity" honesty boundary, one level up: here there is no sub-key concept at
  all, by design, to keep the credential surface small).
- **Revoking a key does not reclaim its slot in the per-tenant key-count cap.** The row
  persists (status changes; the row is never deleted) — an operator wanting headroom back
  must issue against remaining capacity, not assume revocation frees it.
- **Dispatched only via this run's explicit authorization to build post-investment tasks**
  (mirrors ADR-0009→ADR-0012's identical disclosure) — the roadmap's own 🏦 label means
  this was not scheduled as next-buildable MVP work.

## Threat model

| Threat | Mitigation |
|--------|------------|
| Cross-tenant event read via a third-party key | The key's `tenant_id` is set ONLY at issuance by an operator (never caller-supplied per-request); the gated read opens `get_tenant_session(principal.tenant_id)`, so RLS structurally confines it — a key can never read another tenant's events regardless of what it presents. |
| An unauthorized caller granting itself a broader scope | `scopes` is validated against the closed `_KNOWN_SCOPES` enum at issuance (422 for anything else); issuance itself is admin-token-gated, so no caller without the operator credential can mint or widen a key's scopes at all. |
| A revoked key continuing to read | `require_third_party_api_key` resolves the row regardless of `status` (Fork B/I); the ROUTER checks `status == "active"` before proceeding, rejecting a revoked key with a chain-audited 403 on every subsequent attempt. |
| Rate-limit bypass via key churn (issue many keys to escape a per-key cap) | `ORCH_EXTERNAL_GATEWAY_MAX_KEYS_PER_TENANT`, enforced at issuance via `lock_external_gateway_key_cap` + an explicit `COUNT(*) WHERE tenant_id = ...` (Fork G) inside the same transaction as the INSERT — a tenant cannot mint unbounded keys to route around any single key's rate limit. |
| Concurrent requests racing past a key's rate limit | The atomic `INSERT ... ON CONFLICT ... DO UPDATE ... RETURNING request_count` (Fork D) means two concurrent requests for the SAME key in the SAME window can never both read a stale pre-increment count — each sees the POST-increment value, so the limit is enforced under real concurrency, not merely under a single-threaded read-then-write. |
| Plaintext key leakage via storage or logs | Only `key_hash` (SHA-256) is ever persisted; the plaintext appears in exactly one response body (issuance) and is never logged (mirrors `security.py`'s and `external_gateway/auth.py`'s identical discipline). |
| Enumeration oracle distinguishing "unknown key" from "revoked key" from "wrong scope" at the AUTH layer | `require_third_party_api_key` raises the SAME `ExternalGatewayAuthError` → uniform 401 for missing/malformed/unknown keys only; a resolved-but-rejected key (revoked or scope-denied) is a DIFFERENT, later 403 — this is an intentional two-layer split (unknown-key ambiguity vs. resolved-key authorization detail), not an oracle, because a 403 already requires possessing a valid, resolvable key secret to reach. |
| Tamper on the audit chain | Append-only via BEFORE UPDATE/DELETE deny triggers + SHA-256 hash chain (mirrors every other Orchestrator chain); `validate_external_gateway_chain` re-verifies the full chain under the same FAIL-LOUD BYPASSRLS assertion as `validate_state_chain`. |
| Oversized/malformed issuance request | Allow-listed fields, bounded string lengths (`tenant_id` ≤ 64, `label` ≤ 128), a closed `scopes` enum, and a bounded `rate_limit_per_minute` range are all validated at the request boundary before any DB write — never a 5xx for an ordinary validation failure. A NUL byte or deeply-nested body reuses `boundary.contains_nul` + a narrow `RecursionError` catch (mirrors `messaging/router.py` verbatim). |

## Residual risk (known, deferred)

- **Fixed-window rate limiting can momentarily allow up to ~2x the configured rate** at a
  window boundary (Fork D). A sliding-window or token-bucket limiter is genuine,
  separate, out-of-scope future work.
- **No sub-key identity.** Every request made with a given key is indistinguishable from
  any other made with it. A finer-grained per-caller identity within a single tenant's
  third-party integration is out of scope for this PR.
- **Revoking a key does not free its slot in the per-tenant key-count cap** (Fork J) — an
  operator must be aware of this when planning key rotation under a tight cap.
- **No key expiry / TTL.** A key is valid indefinitely until explicitly revoked; there is
  no automatic expiry in v1.
- **Single-Postgres-instance only**, like every prior ADR in this series — no notion of
  multi-region rate-limit or audit-chain replication.

## Configuration

New environment variables (all resolved NON-FATALLY — absence is not fatal):

- `ORCH_EXTERNAL_GATEWAY_ENABLED` — master switch for `GET /v1/external/events` (default
  `false`; see Fork E). Key issuance/revocation is unaffected by this flag.
- `ORCH_EXTERNAL_GATEWAY_DEFAULT_RATE_LIMIT_PER_MINUTE` — default per-key rate limit
  assigned at issuance when the request omits `rate_limit_per_minute` (default 60, ≥ 1).
- `ORCH_EXTERNAL_GATEWAY_MAX_RATE_LIMIT_PER_MINUTE` — ceiling an operator may configure
  for any single key (default 6000, ≥ 1).
- `ORCH_EXTERNAL_GATEWAY_MAX_KEYS_PER_TENANT` — per-tenant `third_party_api_keys` row-count
  cap, enforced at issuance (default 20, ≥ 1).

## Testing

- **Unit** (`tests/unit/test_external_gateway_config.py`, `test_hash_chain_external_gateway.py`,
  `test_external_gateway_router.py`): env-parsing defaults/overrides/misconfiguration; the
  new chain's canonicalization and tamper-evidence properties; the admin-token boundary
  (401/403, byte-identical to `admin/router.py`'s); the issuance validation boundary (422:
  unknown field, missing field, oversized `tenant_id`/`label`, non-subset `scopes`,
  out-of-range `rate_limit_per_minute`, NUL byte); the gated-read boundary (401 with no/
  unknown key, 404 when disabled, 403 revoked, 403 scope-denied, 429 over rate limit, 200
  allowed) with the repository layer monkeypatched (mirrors `test_messaging_router.py`'s
  pattern — no DB); a tenant-scoping contract test proving the gated read always opens
  `get_tenant_session` with the KEY's own resolved tenant_id, never a caller-suppliable one.
- **Integration** (`tests/integration/test_external_gateway_e2e.py`, `pytest.mark.integration`,
  gated by `ORCH_REQUIRE_EXTERNAL_GATEWAY_E2E=1`, fails loud if set but unable to run,
  never silently skips on CI): a NON-STUBBED path over a real DB proving a genuine issued
  key reads its own tenant's events and never another tenant's; a revoked key is rejected
  and chain-audited; a key without the required scope is rejected and chain-audited; a key
  exceeding its configured rate limit within one window is rejected (429) and chain-audited,
  while a fresh window admits requests again; the external-gateway chain validates in full;
  the disabled-gateway 404 path when `ORCH_EXTERNAL_GATEWAY_ENABLED` is unset.
- `tests/integration/test_migration_roundtrip.py` updated for the new head revision
  (`0010_external_gateway`) and the three new tables.
- `contracts/openapi.yaml` updated with the four new operations + the `externalApiKey`
  security scheme, reusing existing schema-composition conventions; verified against
  `tests/test_contract.py`.

## Out of scope (do not build here)

A cross-product proxy fronting Sentinel/Delta/Rendly's own APIs; any integration with
F-026 (the MCP layer, which does not exist); a sliding-window or token-bucket rate
limiter; per-request sub-key identity; key expiry/TTL; self-service (non-operator) key
issuance; any additional gated seam beyond `GET /v1/external/events` (extending scope
coverage is real, separate follow-up work, per Fork C).

## Consequences

- Third-party integrators gain a real, working, rate-limited, scope-checked, tamper-evident
  audited path to one Orchestrator read seam, reusing every existing credential/session/
  RLS/audit pattern this repo already established — entirely additive, no existing seam,
  engine, schema, or credential changed.
- The gap between this slice and the roadmap's fuller "global gateway for all third-party
  interactions... overlaps F-026" vision is named explicitly (Honesty boundaries, Residual
  risk, Out of scope) rather than implied away, consistent with CLAUDE.md's mandatory
  honest-language rule and ADR-0009→ADR-0012's identical precedent.
- The scope-enum discipline (Fork C) means every future extension of this gateway to a new
  seam is a deliberate, reviewable, two-part change (new scope + new enforcement site),
  not a silent capability expansion.
