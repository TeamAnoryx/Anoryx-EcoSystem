# ADR-0006 — Persistence Consolidation + Tenant-Scoped Read Seams

- Status: Accepted
- Date: 2026-07-02
- Task: O-006 (sixth Orchestrator task, fourth runtime task)
- Builds on: ADR-0001 (internal API contract), ADR-0002 (event-bus contract), ADR-0003
  (O-003 ingest persistence), ADR-0004 (O-004 policy distribution), ADR-0005 (O-005
  coordination)
- Supersedes: nothing. Tightens the O-001/O-002/O-004 READ seams from
  coarse-grained to per-tenant; the distribution WRITE (POST) stays coarse relay auth (O-004
  LOW-2 carried forward). Consumes O-004 distribution + O-005 coordination unchanged.

## Context

O-003/O-004/O-005 each stood up a minimal slice of persistence and **deferred**
cross-cutting tenant-isolation to "the persistence task." This is that task. O-006:

1. **Closes the O-004 cross-tenant READ hole (LOW-1); carries the inbound-`tenant_id` write
   finding (LOW-2) forward.**
   - **O-004 audit LOW-1** (`docs/audit/O-004-security-audit.md`): `GET
     /v1/policies/distributions/{id}` is coarse — the handler resolves the owning tenant
     *from the stored row* under a privileged BYPASSRLS session, so any holder of the
     single shared `ORCH_SERVICE_TOKEN` reads *any* tenant's distribution metadata
     (`distribution/router.py`). **CLOSED in O-006** — the GET status read now runs under the
     principal's RLS session.
   - **O-004 audit LOW-2** (§3.1 step 5 of ADR-0004): inbound distribution `tenant_id` is
     taken from the signed policy body (`distribution/router.py`) and never validated against
     the caller. A shared-token holder can store a distribution under any tenant. **CARRIED
     FORWARD, not closed in O-006:** the live Delta budget engine is a trusted multi-tenant
     RELAY on the distribution POST — one shared `ORCH_SERVICE_TOKEN` distributes many tenants'
     policies — so gating the POST per-tenant would 401 the relay. Closing LOW-2 requires the
     Delta consumer to authenticate per-tenant (out of O-006 scope). The distribution POST
     therefore stays COARSE relay auth; its `tenant_id` remains server-resolved from the signed
     body.
2. **Closes the O-002 coarse DLQ-read deferral.**
   - **Honesty correction (verbatim):** the dispatch calls this "O-002 LOW-2," but there is
     **no `O-002` security-audit file** and **no numbered LOW-2 in ADR-0002**. The
     numbered LOW-2 in this repo is the O-004 inbound-`tenant_id` finding above. The
     O-002 concern is *prose*: ADR-0002:176-179 ("the Delta service token is
     coarse-grained; per-tenant read authorization is O-006") and the `GET /v1/bus/dlq`
     NOTE at `openapi.yaml:488-489`. O-006 closes that prose deferral.
3. **Builds the read seams O-001/O-002 specified but never implemented.**
   `GET /v1/events`, `GET /v1/bus/dlq`, `GET /v1/bus/schema-versions` exist only as
   `app.py:11-13` comments today — no route is registered. O-006 implements them to the
   already-merged contract (no contract *shape* change).
4. **Consolidates** the per-task persistence model (light, additive).

### The load-bearing problem: there is no per-tenant authenticated principal

Every existing credential is a **single shared coarse secret**: the ingest HMAC
(`ORCH_INGEST_HMAC_SECRET`), the peer service token (`ORCH_SERVICE_TOKEN`), and the
operator token (`ORCH_ADMIN_TOKEN`). **None carries a tenant identity.** Tenant context is
only ever derived from a record body and injected into the RLS GUC by
`get_tenant_session(tenant_id)` (`persistence/database.py:210-237`). You cannot "validate
`tenant_id` against the authenticated principal" (Fork C) when no per-tenant principal
exists. The acceptance gate demands a **non-stubbed** proof that tenant A cannot read
tenant B — which is only meaningful if A and B authenticate as *distinct* principals.

**Therefore O-006 introduces a per-tenant principal** (`query_service_tokens`). This is the
load-bearing addition; the rest of O-006 is plumbing around it. The interim Bearer scheme
stays (mTLS → O-008), but the Bearer now resolves to a tenant.

## Decision — resolved forks (STEP 0)

| Fork | Decision |
|------|----------|
| **A** — consolidation strategy | **A1**: unify in place, additive. The tables are already coherent and RLS'd; consolidation is light — sync the stale `forward_outbox` ORM, add cursor indexes, add the one new principal table. No rebuild, no DDL churn on the audit chains (preserves hash-chain continuity by construction). |
| **B** — authz enforcement point | **B1**: RLS at the DB (reuse F-003b `_NULLIF_PREDICATE`) **plus** a principal assertion in the read path. Defense in depth; isolation stays structural at the DB even if a handler forgets a filter. |
| **C** — inbound `tenant_id` trust | **C1 (reverted post-merge → coarse relay):** the distribution POST stays COARSE relay auth (`ORCH_SERVICE_TOKEN`); its body `tenant_id` is server-resolved from the signed policy, NOT validated against a per-tenant principal. Per-tenant POST auth 401s the live Delta budget-engine relay (one shared credential, many tenants), so **O-004 LOW-2 is CARRIED FORWARD, not closed.** |
| **D** — DLQ metadata scoping | **D1**: tenant-scope DLQ reads. `dead_letter_queue` **already** has a nullable `tenant_id` + RLS (O-003); the read seam simply runs on a tenant session. **No schema change to the DLQ table.** NULL-tenant (payload-invalid) rows stay operator-only (RLS-invisible to every tenant). |
| **E** — read-seam exposure | **E1**: bounded, tenant-scoped, metadata-only. The contract already dictates cursor pagination, `Limit` caps, and no-payload responses; implement exactly to it. |
| **F** (premise gap) — the principal | **F1**: per-tenant service tokens. New `query_service_tokens` table maps a hashed Bearer → `tenant_id`; the query/bus/distribution seams derive `principal.tenant_id` from the presented token. |
| Inbound **scope** | **Reads only; POST deferred.** The distribution POST (Delta→Orch write) stays COARSE relay auth: its `tenant_id` is server-resolved from the signed body, NOT validated against a per-tenant principal — the live Delta budget-engine consumer is a trusted multi-tenant RELAY (one shared credential distributes many tenants' policies), so a per-tenant POST gate would 401 it (O-004 LOW-2 carried forward). **Ingest (Sentinel→Orch) likewise stays a trusted multi-tenant relay** — one Sentinel peer legitimately emits events for many tenants; a per-tenant HMAC would break the single-peer model. Both keep their coarse peer check + structural invariants, documented below as explicit (unclosed) honesty boundaries. |

### Locked (not forks)

- **Consume O-004 distribution + O-005 coordination unchanged.** O-006 adds a per-tenant authz
  layer in front of the O-004 GET seam and builds new read seams (the POST keeps its coarse
  relay auth); it does **not** alter
  `distribution/engine.py`, the coordinator, the registry, or health. The O-005
  `/v1/policies/coordinate` path (gated by `ORCH_ADMIN_TOKEN`, persists rows internally
  via `get_tenant_session`) is untouched.
- **Reuse the F-003b two-role model**: `orchestrator_app` (NOBYPASSRLS) for tenant data,
  the privileged owner role for chain ops + the auth bootstrap lookup.
- **Migration extends the live head** `0004_sentinel_registry` (reconfirmed single head).
  Delta migrations are landing; if a second head appears, converge with a no-op merge
  migration (the `0003_merge_o004_d004` tuple-`down_revision` pattern) — **never rebase**
  (force-push blocked).
- **`get_tenant_session` autobegins** — no `async with session.begin()` around reads
  (ADR-0026 double-begin fail-open, re-fixed at d7f1505).
- **Hash-chain continuity**: no audit-chain table or column changes → the three chains stay
  verifiable across the migration by construction.

## Schema

### `query_service_tokens` (operator-global, NO RLS, privileged-managed) — NEW

The auth lookup must resolve the tenant *before* a tenant GUC can be set, so this table
cannot be RLS-scoped on itself (chicken-and-egg). It is operator infrastructure, mirroring
the `sentinel_registry` precedent (no RLS, no `orchestrator_app` grants; read on the
privileged session).

| column | type | notes |
|--------|------|-------|
| `token_id` | `String(64)` PK | logical id |
| `tenant_id` | `String(64) NOT NULL` | the tenant this credential authenticates as |
| `token_sha256` | `String(64) NOT NULL UNIQUE` | SHA-256 hex of the presented Bearer secret. **The plaintext is never stored or logged.** |
| `label` | `String(128) NOT NULL` | operator-facing description |
| `enabled` | `Boolean NOT NULL` default `true` | operator revoke without delete |
| `created_at` | `TIMESTAMP(tz) NOT NULL` server_default `now()` | |

- Operator-seeded via the privileged role (like registry rows). No self-service issuance in
  O-006 (a token-issuance admin API is out of scope; deferred).
- Auth gate: `SELECT tenant_id FROM query_service_tokens WHERE token_sha256 = :h AND
  enabled` on `get_privileged_session()`. Miss/disabled/absent header → **401**. No 401 vs
  404 distinction on the token itself (no enumeration oracle).

### Indexes (consolidation) — NEW

- `ix_ingest_events_tenant_seq` on `ingest_events (tenant_id, sequence_number)` — bounded
  cursor scans for `GET /v1/events`.
- `ix_dead_letter_queue_tenant_created` on `dead_letter_queue (tenant_id, created_at,
  dlq_id)` — bounded cursor scans for `GET /v1/bus/dlq`.

### `forward_outbox` ORM sync (code only, no DDL)

`models/forward_outbox.py` gains `attempt_count`, `last_attempt_at`, `last_error` to match
the live schema (added by `d004_forward_dispatch_state`; the ORM class was stale and the
dispatcher read them via raw SQL). No migration — the columns already exist.

### Not touched

The three audit-chain tables (`ingest_audit_log`, `distribution_audit_log`,
`sentinel_registry_audit_log`) get **no** column or RLS changes — hash-chain continuity is
preserved trivially. The cosmetic `ingest_audit_log`-has-no-`created_at` gap is left as-is
(ordering is by `sequence_number`; not a defect).

## Migration `0005_tenant_principal_and_reads` (`down_revision = "0004_sentinel_registry"`)

- `upgrade()`: CREATE `query_service_tokens` + its unique `token_sha256` index; CREATE the
  two read indexes. **No RLS statements** (the new table is operator-global; existing tables
  already have correct RLS). No `orchestrator_app` grants on `query_service_tokens`
  (privileged-read only, mirrors registry).
- `downgrade()`: drop indexes + table. Non-stubbed round-trip proven by
  `test_migration_roundtrip.py` (its head assertion is bumped to `0005_...`).
- Convergence: reconfirm `alembic heads` at build; a second head → no-op merge migration,
  never rebase.

## The principal + auth dependency (`persistence` + a shared gate)

`resolve_principal_tenant(token: str) -> str | None` (repositories.py, privileged session):
hash → lookup → return `tenant_id` or `None`. A shared FastAPI dependency
`require_tenant_principal(authorization: str) -> str` extracts the Bearer, calls the
resolver, and raises 401 on miss. Every tenant-scoped seam depends on it; the read then runs
under `get_tenant_session(principal_tenant_id)` so RLS is the structural enforcer.

`ORCH_SERVICE_TOKEN` (the old coarse peer token) **no longer grants tenant-data reads** —
the query/bus/distribution seams require a per-tenant token. This is the intended tightening
(the coarse token had no legitimate cross-tenant read grant). Operator cross-tenant / NULL-
tenant DLQ triage is **not** exposed via the API in O-006 (operators inspect the DB
directly; an operator DLQ seam is deferred).

## Read seams (implement to contract; run on a tenant session; metadata-only)

- **`GET /v1/events`** (`queryEvents`): SELECT metadata columns from `ingest_events` under
  the principal's tenant session; cursor on `sequence_number`; `Limit` 1..200 (default 50);
  project `EventMetadata` (`openapi.yaml:1256-1300`) — never `payload`. If `FilterTenantId`
  is present and ≠ principal → **403** (an A token may not even *ask* for B; RLS would also
  return empty, but the explicit reject matches Fork C).
- **`GET /v1/bus/dlq`** (`queryDeadLetters`): SELECT from `dead_letter_queue` under the
  tenant session; cursor + `Limit`; project `DeadLetterMetadata` (`openapi.yaml:1372-1406`)
  — **never** `original_envelope`. RLS hides NULL-tenant (payload-invalid) rows from every
  tenant. New repo method `list_dead_letters`.
- **`GET /v1/bus/schema-versions`** (`getSupportedSchemaVersions`): a **global allow-list**
  (supported schema ints + `envelope_schema_id`). Auth-gated by a valid per-tenant token but
  **not** tenant-scoped — it is config, not tenant data. Stated as an honesty boundary.

**Cursor validation (422, not 503).** A malformed or over-length (>512-char) pagination cursor
on `GET /v1/events` / `GET /v1/bus/dlq` returns the contract's **422 `schema_invalid`**, never
the app's 503 catch-all. The cursor decoders validate shape/type/range BEFORE the query — a
non-object JSON cursor, an out-of-BIGINT-range sequence, and an unparseable DLQ timestamp are all
caught in the decoder rather than surfacing as a DB `DataError`. The contract's `GET /v1/events`
and `GET /v1/bus/dlq` operations were updated to document this `422` response.

## Distribution seam retrofit (no engine change)

- **GET status** (`distribution/router.py:283-323`): replace the privileged pre-resolve +
  re-read with `principal → get_tenant_session(principal) → get_distribution(session, id)`.
  RLS returns the row only if it belongs to the principal; otherwise **404** (cross-tenant
  lookups are indistinguishable from not-found — no existence oracle).
- **POST** (`distribution/router.py`): stays COARSE relay auth via `_require_bearer`
  (`ORCH_SERVICE_TOKEN`, constant-time compare, fail-closed 401/403). The body `tenant_id` is
  server-resolved from the signed policy, NOT validated against a per-tenant principal — the
  live Delta budget-engine consumer is a trusted multi-tenant relay, so a per-tenant POST gate
  would 401 it. O-004 LOW-2 is carried forward; distribution-engine behavior is unchanged.

## Honesty boundaries (verbatim — non-removable)

- **GET distribution-status, `GET /v1/events`, and `GET /v1/bus/dlq` are now
  tenant-scoped.** A per-tenant service token establishes the principal; reads run under
  that tenant's RLS session; a token cannot read another tenant's data. (Closes O-004 LOW-1
  and the O-002 DLQ-read prose deferral.)
- **The distribution POST remains coarse relay auth (`ORCH_SERVICE_TOKEN`); its `tenant_id`
  is server-resolved from the signed body, not validated against a per-tenant principal —
  O-004 LOW-2 is carried forward, because the live Delta consumer is a trusted multi-tenant
  relay. Only the READ seams (GET status, `/v1/events`, `/v1/bus/dlq`) are tenant-scoped in
  O-006.**
- **Ingest (Sentinel→Orch) remains a trusted multi-tenant relay.** Its `tenant_id` is
  server-resolved from the schema-validated body; the peer is authenticated by
  `source_product`, not per-tenant. O-006 does **not** close ingest tenant-binding — this is
  an explicit, documented boundary, not an oversight.
- **Reads are metadata-only per contract** — no event payloads, no policy bodies, no DLQ
  `original_envelope`.
- **`schema-versions` is a global allow-list**, not tenant-scoped.
- **`query_service_tokens` is operator-seeded**; no self-service issuance API in O-006.
- **mTLS provisioning still → O-008**; the interim Bearer stays (now tenant-bound).
- **"distributed" ≠ "applied"** (O-004) unchanged; **O-004 distribution + O-005
  coordination semantics are consumed, not rewritten.**

## Threat model

| Threat | Mitigation |
|--------|------------|
| Cross-tenant read via GET status / `/v1/events` / `/v1/bus/dlq` | Per-tenant principal → `get_tenant_session` → RLS (`orchestrator_app` is NOBYPASSRLS, `FORCE ROW LEVEL SECURITY`); a token physically cannot widen past its tenant. Proven by a direct-DB cross-tenant probe in the e2e (not just app filtering). |
| Forged / mismatched inbound `tenant_id` on distribution POST | **Carried forward (not mitigated in O-006).** The POST stays coarse relay auth; `tenant_id` is server-resolved from the signed body (never a client header) and Sentinel's intake is the verifying authority on the compact-JWS signature, but the Orchestrator does NOT validate the body `tenant_id` against a per-tenant principal — the Delta consumer is a trusted multi-tenant relay. O-004 LOW-2 deferred. |
| RLS bypass | The runtime uses the NOBYPASSRLS `orchestrator_app` role; the strict `NULLIF(...)` predicate is unsatisfiable when the GUC is unset (fail-closed to zero rows). The chain-validators keep their BYPASSRLS fail-loud guard. |
| `query_service_tokens` as a NEW trust root — token theft / replay | Only the SHA-256 hash is stored (no plaintext at rest or in logs); tokens are high-entropy operator-issued secrets; `enabled=false` revokes instantly; a miss/disabled token → 401 with no enumeration oracle. Replay within TLS is bounded by O-008 mTLS (deferred); interim risk is the shared-transport risk already accepted for the Bearer scheme. |
| Read-seam over-exposure / PII leak | Metadata-only projections enforced in the repo layer + asserted in tests (no `payload` / `original_envelope` / policy body in any response). Cursor + `Limit` bound the result set. |
| Hash-chain break on consolidation | The migration touches no audit table/column; continuity is preserved by construction and re-validated in the round-trip test. |
| Existence oracle via GET status | Cross-tenant lookup returns 404 (identical to not-found), not 403. |

## Residual risk (known, deferred)

- **O-004 LOW-2 (inbound distribution `tenant_id`) is carried forward, not closed.** The
  distribution POST stays coarse relay auth: the live Delta budget-engine consumer is a trusted
  multi-tenant RELAY (one shared `ORCH_SERVICE_TOKEN` distributes many tenants' policies), so a
  per-tenant POST gate would 401 the relay. The body `tenant_id` is server-resolved from the
  signed policy (never a client header), and Sentinel's intake remains the verifying authority
  on the signature; but the Orchestrator does not bind the body `tenant_id` to a per-tenant
  principal. Closing LOW-2 requires the Delta consumer to authenticate per-tenant (out of O-006
  scope). This was reverted after the initial per-tenant POST enforcement 401'd the merged
  Delta→O-004 integration lane.
- **Ingest tenant-binding is not closed** (trusted-relay decision). A holder of the shared
  ingest HMAC secret can ingest an event for any `tenant_id`. Bounded operationally (single
  operator-provisioned Sentinel peer); real per-tenant ingest identity → future task (needs
  per-tenant peer credentials / mTLS SANs, O-008 territory).
- **O-005's "per-tenant registry authz"** (ADR-0005:243, 255-256: letting a tenant constrain
  which Sentinels its policies reach) is a *coordination-semantics* enhancement. The O-006
  dispatch scopes O-006 to the read holes + consolidation and forbids rewriting O-005
  coordination, so this is **not** built here — carried forward. The registry stays
  operator-global.
- **O-004 static-targets SSRF gap** (ADR-0005:211-213) and the **DNS-rebind connect-time
  TOCTOU** (ADR-0005:199-210) are outbound-transport concerns owned by O-008; unchanged here.
- **Append-only audit assumes the runtime role is BYPASSRLS-but-not-SUPERUSER** — enforced
  at deploy (O-008), consistent with the existing chains.
- **Per-tenant tokens are stored as *unsalted* SHA-256.** Acceptable here: they are
  high-entropy, operator-issued secrets (not user passwords), so a rainbow-table / brute-force
  pre-image attack is infeasible, and the `orchestrator_app` role is denied `SELECT` on
  `query_service_tokens` (privileged-read only), so the hash column is not app-reachable. A
  minimum-entropy issuance policy and/or an HMAC-pepper is deferred to the (out-of-scope)
  token-issuance admin API.

## Configuration

- `ORCH_REQUIRE_AUTHZ_E2E` (CI: `"1"`) — flips the authz/read-seam e2e skip-gate to
  `pytest.fail` so the gate provably executes on a fresh CI DB (mirrors
  `ORCH_REQUIRE_COORDINATION_E2E`).
- No new runtime secret: per-tenant tokens live in `query_service_tokens`, seeded by the
  operator. `ORCH_SERVICE_TOKEN` / `ORCH_ADMIN_TOKEN` / ingest HMAC unchanged in role.

## Testing

- **Unit** (`tests/unit/`): per-tenant token gate (valid / invalid / disabled / missing →
  401); principal derivation; the coarse distribution POST gate (missing/empty/non-Bearer →
  401, wrong token → 403); cursor `Limit` clamp; metadata-only projection asserts (no
  `payload` / `original_envelope` / policy body).
- **Integration (non-stubbed, the gate)** — `tests/integration/test_authz_reads_e2e.py`,
  `ORCH_REQUIRE_AUTHZ_E2E=1`: seed per-tenant tokens + rows for tenants A and B on the
  privileged conn, then prove: (1) A reads its distribution → 200, B reads the same id →
  404; (2) A's DLQ read returns only A's rows, B sees none of A's; (3) A's `/v1/events`
  returns A only, `FilterTenantId=B` → 403; (4) **direct-DB RLS proof** via the raw
  `orchestrator_app` conn (GUC→A sees the row, GUC→B sees 0) — Windows-robust, mirrors
  `test_ingest_e2e.py:208`; (5) a Linux-only `get_tenant_session` runtime-path variant
  (`skipif win32`). The distribution POST is coarse relay auth, so there is no per-tenant
  POST-mismatch assertion — O-004 LOW-2 is carried forward.
- **Migration** (`test_migration_roundtrip.py`): head bumped to `0005_...`; downgrade→upgrade
  clean; the ingest chain still validates across it.
- **O-004 test updates**: the existing distribution GET-status tests
  (`test_distribution_e2e.py`, `test_distribution_router.py`) seed and use a per-tenant token
  for the READ; the POST cases authenticate with the coarse `ORCH_SERVICE_TOKEN` relay — an
  authz *tightening on the reads only*, not a semantics change.

## Out of scope (do not build here)

O-005 registry/coordination (done — consumed as-is); O-004 distribution engine (done);
per-tenant registry authz (coordination semantics — carried forward); operator DLQ triage
API / token-issuance admin API; ingest per-tenant binding; O-007 UI; O-008 deploy + real
mTLS provisioning; Sentinel's real HTTP intake/health routes.

## Consequences

- The Orchestrator gains its first real per-tenant authorization boundary on the READ seams;
  the coarse service token is demoted from a cross-tenant reader to (nothing, for those
  reads) — it still gates the distribution POST as a trusted multi-tenant relay. Future read
  seams should depend on `require_tenant_principal`.
- The O-004 cross-tenant READ hole (LOW-1) and the O-002 DLQ-read prose deferral are closed
  and proven non-stubbed; the query/bus read seams O-001/O-002 promised now exist. The O-004
  inbound-`tenant_id` write finding (LOW-2) is CARRIED FORWARD: the live Delta budget-engine
  consumer is a trusted multi-tenant relay on the POST, so per-tenant POST auth is deferred to
  a per-tenant Delta consumer (out of O-006 scope).
- Consolidation is deliberately light: the persistence layer was already coherent, so O-006
  reconciles ORM drift + adds read-path indexes rather than reshaping tables — keeping the
  hash chains untouched and the change reversible.
