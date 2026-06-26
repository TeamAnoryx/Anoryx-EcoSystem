# ADR-0003: Event Ingest Pipeline (O-003)

## Status

Proposed (2026-06-26). Third Anoryx-AI-Orchestrator ADR; builds on and does not contradict
**ADR-0001** (O-001 internal API contract) and **ADR-0002** (O-002 ecosystem event bus contract).
Scope: **runtime + the Orchestrator's first persistence migration**. O-002 *specified* the envelope,
at-least-once delivery with consumer dedup, bounded replay, and reject-to-DLQ as **contract only**;
O-003 builds the **ingest half** of that machinery. The distribution engine (O-004), subscriber
registry / real routing (O-005), full persistence consolidation + the GET query/bus read seams (O-006),
UI (O-007), and deploy + mTLS provisioning (O-008) are later tasks and are **out of scope** here.

## Context

ADR-0002 closed with: "O-003 (ingest pipeline) implements at-least-once consumption + dedup on
`idempotency_key`, the reject-to-DLQ router, the DLQ store with the attempt ceiling, and the three
documented invariants (`event_type`/`idempotency_key`/`source_product`)." It also recorded three
non-removable honesty boundaries: **(a)** replay and DLQ are SPECIFIED, not implemented — O-003 builds
the machinery; **(b)** delivery is at-least-once, consumers MUST dedupe on `idempotency_key`;
**(c)** unknown-version handling is reject-to-DLQ.

The Orchestrator package is **contracts-only** today (`contracts/`, `docs/adr/`, a contract-test
harness, `pyproject.toml` with `packages = []`). O-003 stands up the **first runtime code** and the
**first Alembic migration**.

Inputs that constrain the design (restated for self-containment):

- **The ingest seam is fixed by the merged contract.** `POST /v1/ingest/events` accepts the O-002
  envelope (`event-envelope.schema.json`, `$id anoryx:event-envelope:v1`) whose `payload` member is the
  locked F-002 event (`../../Anoryx-Sentinel/contracts/events.schema.json`, `$id sentinel:events:v1`),
  validating **unmodified**. Response is `202 {status: accepted, event_id}`. Auth is mTLS (peer =
  Sentinel) **AND** a per-event HMAC-SHA256 body signature reusing the F-020 webhook pattern:
  `HMAC-SHA256(secret, "{timestamp}.{body}")` sent as `X-Sentinel-Signature: sha256=<hex>` plus
  `X-Sentinel-Timestamp` (Unix seconds), rejected outside a ±300s window, recomputed and compared in
  constant time. O-003 **implements** this seam; it does not alter the contract.
- **mTLS provisioning is deferred to O-008** (ADR-0001 honesty boundary a). Until then the per-event
  HMAC (only the holder of the shared signing secret can sign) is the **interim emitter authenticator**,
  and the trusted `source_product` for this seam is the constant `sentinel` (the ingest peer), stamped by
  the receiver and verified against the body — never trusted from the body (rule 7, ADR-0002 threat 2).
- **`schema_version` is an envelope-level integer (1..1000), not a `const`** (ADR-0002 Fork C). A
  well-formed but unknown version (e.g. `2`) **structurally validates** and must be **routed to the DLQ,
  not rejected with a 422** — the reject-to-DLQ disposition is a documented consumer obligation, not a
  schema constraint.
- **Three envelope invariants** JSON Schema cannot express across sibling values, each consumer-enforced
  fail-closed (ADR-0002): `event_type == payload.event_type`; `idempotency_key == payload.event_id`
  (the F-002 bus dedup key); `source_product == the authenticated peer`. Disagreement → reject-to-DLQ.
- **Sentinel's proven persistence patterns** (F-003 hash-chained append-only audit; F-003b two-role
  RLS isolation: a privileged owner/BYPASSRLS role for chain ops + a NOBYPASSRLS app role for tenant
  traffic, with the strict `NULLIF(current_setting('app.current_tenant_id', true), '')` fail-closed
  predicate; the `get_tenant_session` **autobegin** contract and the ADR-0026 double-begin fix). O-003
  **ports** these patterns into the Orchestrator's own package — it does **not import** Sentinel modules
  (products stay decoupled; each owns its own DB).

## Decision

Build a synchronous, in-process **ingest pipeline** behind the contract's HMAC webhook seam, backed by
the Orchestrator's first Alembic baseline (a minimal ingest store), porting Sentinel's hash-chain +
two-role RLS patterns. Each STEP-0 fork below was surfaced with a recommendation and **the owner (Affu)
confirmed all five** at the lean / fail-closed default.

### Fork A — Persistence ownership: **minimal ingest store as the first Alembic baseline** (A1)

O-003 stands up a minimal, ingest-shaped persistence model as the Orchestrator's first migration
(`0001_ingest_baseline`). O-006 consolidates the full persistence model later. Pulling O-006's full
model forward (A2) was rejected as off-roadmap-order with a larger blast radius. The four tables are the
minimum the ingest half needs: a dedup+metadata+replay store, a global hash chain, a DLQ, and a
forward-intent outbox.

### Fork B — Dedup store: **persistent UNIQUE constraint on `idempotency_key`** (B1)

At-least-once delivery (boundary b) means duplicates are expected. Dedup is a **persistent UNIQUE
constraint** on `ingest_events.idempotency_key` — it survives restart, giving true idempotency. A
second delivery of the same key trips the constraint and is handled as a duplicate. An in-memory / Redis
TTL window (B2) was rejected: it only dedupes within a bounded window and silently re-admits a duplicate
after eviction/restart, contradicting A1.

### Fork C — DLQ backing: **Postgres `dead_letter_queue` table** (C1)

Reject-to-DLQ writes the O-002 `DeadLetterEnvelope` (original envelope preserved + reason + attempt
count + first-failed-at) as a row in a Postgres `dead_letter_queue` table. Durable, queryable, matches
the contract's failure-envelope shape, and is exactly what replay-from-DLQ (a later task) re-drives.
Redis-backed DLQ (C2) was rejected as less durable/queryable and divergent from the contract's row shape.

### Fork D — Forward-to-subscribers seam: **forward-INTENT outbox row only** (D1)

On accept, the pipeline records **forward-INTENT** as a `forward_outbox` row. It builds **no router** —
O-005 owns subscriber registration and real routing. Implementing forwarding now (D2) is out of O-003
scope (it pulls a registry + router forward). This is an honest, non-removable boundary: O-003 records
that an event *should* be forwarded; it does not forward it.

### Fork E — O-002 deferred LOW-2: **tenant-scope the DLQ store now** (E1)

O-002 review left LOW-2 open: the coarse-grained Delta service token can read DLQ metadata across
tenants (per-tenant read authorization deferred to O-006). O-003 **closes LOW-2 at the source** by
putting a `tenant_id` column + RLS on the DLQ store from day one — structural isolation, not a runtime
check. A payload-invalid envelope whose `tenant_id` is unextractable is stored with `tenant_id = NULL`,
which the strict `NULLIF` RLS predicate makes **invisible to every tenant** (fail-closed; operator/
privileged-only). Leaving the store coarse and carrying LOW-2 to O-006 (E2) was rejected — the
structural fix is cheap now. (Note: O-003 does **not** implement the `GET /v1/bus/dlq` read seam — that
serving surface is O-006; E1 hardens the *store* the future read seam will sit on.)

### Fixed (not forks)

Transport = the HMAC webhook per the merged contract (not re-decided). RLS on every tenant-scoped table
(mirror F-003b). The contract is **not** altered — O-003 implements it. This ADR is number **0003**.

## Ingest design

### Receiver (`POST /v1/ingest/events`)

A new `orchestrator` FastAPI app (`create_app()` factory, mirroring `Anoryx-Sentinel/src/gateway/main.py`
conventions: router include, exception handlers, fail-safe). The handler:

1. Reads the **raw body** (`await request.body()`) **before** JSON parsing, so the bytes the HMAC was
   computed over match exactly.
2. **HMAC verification** (first inbound HMAC verify in the ecosystem; mirrors the F-020 signer's
   contract): a missing/malformed `X-Sentinel-Signature` or a recompute mismatch → **401 Unauthorized**;
   an `X-Sentinel-Timestamp` outside ±300s → **403 Forbidden** (replay window). The digest is recomputed
   as `HMAC-SHA256(ORCH_INGEST_HMAC_SECRET, f"{ts}.{raw_body}")` and compared with `hmac.compare_digest`
   (constant time). The secret is read from the environment and never logged.
3. **Structural envelope validation** — the envelope fields are present and typed, `payload` is an
   object, and `schema_version` is an integer. A structurally malformed envelope → **422
   UnprocessableEntity**. The payload is **not** deep-validated against `events.schema.json` at this
   boundary — that, the version-allow-list check, and the invariant checks are deferred to the pipeline
   stage so a well-formed-but-rejected envelope reaches the **DLQ** (per ADR-0002 Fork C, an unknown
   `schema_version` must be DLQ'd, not 422'd; the same two-stage split routes payload-schema and
   invariant failures to the DLQ rather than 422). This split is deliberate and documented.
4. On passing the boundary checks → **202 `{status: accepted, event_id: envelope.idempotency_key}`**
   and runs the in-process pipeline. The 202 means "received and durably recorded" — either as an
   accepted event or, on a pipeline-stage failure, as a DLQ entry. The contract defines no
   "dead-lettered" client status; reject-to-DLQ is an internal disposition. (`event_id` echoes
   `idempotency_key`, which equals `payload.event_id` for a valid Sentinel event — the bus dedup key.)

### Pipeline (consumer obligations → reject-to-DLQ on failure; ordered)

1. `schema_version` ∈ supported `[1]`? No → DLQ `unknown_schema_version`. (Version-gate **first** — do
   not best-effort-parse an unknown shape; boundary c / threat: version downgrade.)
2. `payload` validates against the locked `events.schema.json` (a `Draft202012Validator`, the same
   library + dialect the contract tests use — no parser-differential)? No → DLQ `payload_schema_invalid`.
3. `source_product == "sentinel"` (the ingest peer)? No → DLQ `source_identity_mismatch`.
4. `envelope.event_type == payload.event_type`? No → DLQ `payload_schema_invalid` (envelope/payload
   coherence; mapped to the closest closed reason — see "Reason mapping" below).
5. `envelope.idempotency_key == payload.event_id`? No → DLQ `payload_schema_invalid` (coherence).
6. **Dedup + persist** — open a tenant transaction via `get_tenant_session(payload.tenant_id)` (autobegun
   by `set_config(...)`; **no** `session.begin()` wrap), INSERT `ingest_events` (the UNIQUE
   `idempotency_key` is the dedup gate) + INSERT `forward_outbox`, commit. On a unique-violation, compare
   the stored `content_hash`: identical content → **benign dedup** (no-op; the 202 already acknowledged);
   different content under the same key → DLQ `idempotency_conflict` (the suppression-attack defense,
   ADR-0002 threat 5).
7. On accept → open a privileged transaction (`get_privileged_session()` + `session.begin()` — privileged
   sessions do **not** autobegin, so `begin()` is correct here) and append the `ingest_audit_log` chain
   link (disposition `accepted`). DLQ paths likewise append a chain link (disposition `dead_lettered`,
   with `dlq_reason` + `dlq_id`).

### Reason mapping (the closed DLQ-reason set vs the failure modes)

The contract's `DeadLetterReason` enum is **closed**: `unknown_schema_version`, `payload_schema_invalid`,
`source_identity_mismatch`, `idempotency_conflict`, `max_attempts_exceeded`. O-003 maps each failure mode
into it without inventing a reason:

| failure | reason |
|---|---|
| `schema_version` not in `[1]` | `unknown_schema_version` |
| payload fails `events.schema.json` | `payload_schema_invalid` |
| `source_product` ≠ authenticated peer | `source_identity_mismatch` |
| `event_type` ≠ `payload.event_type` (coherence) | `payload_schema_invalid` |
| `idempotency_key` ≠ `payload.event_id` (coherence) | `payload_schema_invalid` |
| same key, different content | `idempotency_conflict` |
| attempt ceiling reached (re-drive bound) | `max_attempts_exceeded` |

The two coherence failures map to `payload_schema_invalid` because an envelope whose classifying fields
disagree with the authoritative payload is malformed framing — the closest closed reason. This mapping
is stated here rather than implied.

### Fail-posture / exception handling (ADR-0026 discipline)

Any DB call in the pipeline that catches connectivity errors catches **only** the family
`(sqlalchemy.exc.OperationalError, sqlalchemy.exc.InterfaceError, sqlalchemy.exc.TimeoutError, OSError)`.
`InvalidRequestError` / `ProgrammingError` are deliberately **outside** this family, so a double-begin
(or any future logic defect) **raises** instead of being swallowed into a silent fail-open — the exact
class re-fixed last merge in F-009 + F-018 (ADR-0026). `sqlalchemy.exc.TimeoutError` (pool-checkout
timeout) and `OSError` (down/restarting Postgres surfaces as `ConnectionRefusedError`, an `OSError`;
DNS failure as `socket.gaierror`; command-timeout as the builtin `TimeoutError`) are named explicitly
because the two SQLAlchemy connection classes do **not** cover the dominant real failures. The
`get_tenant_session(...)` call sites read/write directly on the autobegun transaction and never wrap it
in `session.begin()`. The overall posture is **fail-safe**: an inspection/persistence error blocks
(never silently passes); within that, a genuine connectivity error is handled per the documented per-
path posture (it never produces a silent dark control).

## Persistence schema (`0001_ingest_baseline`)

A new, product-isolated package + DB. Env vars: `ORCH_DATABASE_URL` (privileged owner/BYPASSRLS, used
for migrations + chain ops), `ORCH_APP_DATABASE_URL` (the `orchestrator_app` login role —
`NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE`, used for tenant traffic), `ORCH_INGEST_HMAC_SECRET`,
`ORCH_PROVISION_APP_ROLE` (local/CI-only role-provisioning flag). A dedicated `alembic.ini`
(`script_location = src/orchestrator/persistence/migrations`) and its own `alembic_version` table —
because the Orchestrator's database is separate from Sentinel's, the two products' migration chains do
not collide. The baseline `CREATE ROLE orchestrator_app` is idempotent and carries **no password in
SQL** (provisioned out-of-band via Vault; in local/CI an `ALTER ROLE … PASSWORD` step provides a SCRAM
verifier). All columns are bounded; CHECK constraints mirror the contract enums.

Four tables:

1. **`ingest_events`** — tenant-scoped (RLS ENABLE+FORCE, strict `NULLIF` predicate). The dedup +
   metadata + replay-source store. `sequence_number` bigserial PK; `envelope_id` (unique);
   `idempotency_key` (**UNIQUE** — the dedup gate, Fork B1); `source_product`; `source_sequence` bigint
   (the envelope's monotonic per-source `sequence`, the inclusive lower bound a future replay uses);
   `schema_version`; `occurred_at`; `correlation_id`; `causation_id` (nullable); the F-002 metadata
   projection (`event_id, event_type, event_timestamp, request_id, tenant_id, team_id, project_id,
   agent_id`); `payload` JSONB (the full locked event — a future replay re-emits it; the metadata-only
   GET read seam that projects just the join keys is O-006); `content_hash` (distinguishes a benign
   duplicate from an `idempotency_conflict`); `received_at`.

2. **`ingest_audit_log`** — the tamper-evident **global hash chain**, written by the **privileged**
   session (rule 7: privileged role for chain ops; mirrors F-003 `events_audit_log` — a single chain
   across tenants, because a tenant-scoped chain would fork per tenant). Append-only via BEFORE
   UPDATE/DELETE deny-triggers; RLS-scoped `SELECT` so a tenant reads only its own links. Columns:
   `sequence_number` bigserial PK (chain order); the common F-002 fields; ingest-specific `envelope_id,
   idempotency_key, source_product, disposition` (`accepted | deduped | dead_lettered`), `dlq_reason`
   (nullable), `dlq_id` (nullable); `prev_hash`, `row_hash`. The row hash is
   `SHA-256(canonical_json(...))` with `prev_hash` + `event_timestamp` always in the content; the first
   link's `prev_hash` is a domain-separated `GENESIS_HASH`. `dlq_reason`/`dlq_id` follow the F-003/F-014
   **opt-in-when-present** rule (hashed iff not None) so accepted rows (both None) are byte-identical to
   the chain-without-them form and a set value is tamper-evident.

3. **`dead_letter_queue`** — tenant-scoped (RLS, Fork E1 closes LOW-2). The O-002 failure-envelope:
   `dlq_id` uuid PK; `original_envelope` JSONB (the original **preserved**); `reason` (CHECK = the five
   closed reasons); `attempt_count` (0..1000); `first_failed_at`, `last_failed_at` (nullable); the
   classifying `event_type`, `source_product`, `source_sequence` (triage without opening the body);
   `tenant_id` (best-effort from the payload; NULL when payload-invalid → RLS-invisible to tenants =
   fail-closed). `max_attempts_exceeded` is the terminal reason that bounds re-drive (DLQ-poisoning
   defense).

4. **`forward_outbox`** — tenant-scoped (RLS). Forward-INTENT only (Fork D1; no router): `id` uuid;
   `tenant_id`; `event_id` / `idempotency_key`; `status` (`pending`); `created_at`. O-005 consumes it.

`orchestrator_app` is granted the minimal DML it needs (SELECT on all four; INSERT on the three tenant
tables + a SELECT-only view of the chain); it gets **no** INSERT/UPDATE/DELETE on `ingest_audit_log`
(chain writes are privileged) and **no** DDL/BYPASSRLS/superuser. The down-migration reverses cleanly
(drop policies → triggers → tables; drop the role only if it owns nothing) and is proven by a
non-stubbed persist→load round-trip plus a `downgrade base` rebuild-from-drop.

## RLS (tenant isolation)

Mirrors F-003b. Tenant-scoped tables (`ingest_events`, `dead_letter_queue`, `forward_outbox`) have RLS
ENABLE + FORCE with `USING`/`WITH CHECK` = `tenant_id = NULLIF(current_setting('app.current_tenant_id',
true), '')` — unsatisfiable when the GUC is unset/empty (fail-closed zero rows, never a widen). The
`orchestrator_app` role is NOBYPASSRLS, so isolation holds regardless of application correctness; the
privileged role (BYPASSRLS) is used **only** for the global chain and migrations. `get_tenant_session`
sets the GUC transaction-local (`SET LOCAL`-equivalent) before the first query and autobegins; callers
read/write directly on that transaction. The e2e proves isolation **live** (a `get_tenant_session(A)`
read cannot see tenant B's row), not by inspection.

## Threat model

| # | vector | what the pipeline does |
|---|---|---|
| 1 | **Forged event / HMAC bypass.** An attacker POSTs an event without the shared signing secret, or tampers with a captured body. | Raw body is read before parsing; the digest is recomputed `HMAC-SHA256(secret, "{ts}.{body}")` and compared constant-time. No/invalid signature → 401; stale timestamp (outside ±300s) → 403. Until mTLS provisioning (O-008), the HMAC secret-holder is the interim emitter authenticator (stated gap, ADR-0002 threat 2). |
| 2 | **Replay → suppression-or-duplicate.** A captured envelope is re-sent to either suppress a new event (forged dedup key) or duplicate-process. | Two layers: the ±300s HMAC window rejects stale replays at the boundary; at-least-once + the persistent `idempotency_key` UNIQUE constraint makes a genuine duplicate a benign no-op. `idempotency_key` MUST equal `payload.event_id` (a coherence invariant) — a forged key with mismatched content is a `idempotency_conflict` → DLQ, not a silent drop. |
| 3 | **Cross-tenant read/write.** A bug or a compromised app path reads/writes another tenant's rows. | RLS (NOBYPASSRLS `orchestrator_app` + strict `NULLIF` predicate, FORCE) on every tenant-scoped table; `WITH CHECK` blocks writing a row for the wrong tenant. The chain's cross-tenant span is confined to the privileged role used only for chain ops. Proven live in the e2e. |
| 4 | **DLQ poisoning.** An attacker floods the DLQ to exhaust storage or bury real failures, or re-drives a poisoned entry forever. | `attempt_count` is bounded (0..1000); `max_attempts_exceeded` is a terminal reason (no infinite re-drive — the re-drive engine is a later task, but the bound is in the schema now). DLQ rows are closed + bounded. Fork E1's tenant-scoping prevents a flood in one tenant from being readable cross-tenant. |
| 5 | **Version-downgrade DoS / lenient parsing.** An attacker sends an unknown/older `schema_version` hoping for best-effort parsing that skips newer validation. | Version-gate is the **first** pipeline step; an unknown version → reject-to-DLQ `unknown_schema_version`, never best-effort-parsed. The supported set is an explicit allow-list (`[1]`). There is no lenient path. |
| 6 | **Audit tampering.** An attacker (or a buggy migration) alters a persisted audit row to hide an event or change its attribution. | `ingest_audit_log` is append-only (BEFORE UPDATE/DELETE deny-triggers + RLS USING(false) for U/D) and hash-chained; altering any hashed field breaks `verify_row_hash` for that row and all successors. This is tamper-**evident** (rapid detection), not tamper-proof: a Postgres superuser can rebuild the whole chain (honest limit, as in F-003/ADR-0004). Proven by the e2e tamper test. |

## Honesty boundaries (verbatim, non-removable — rule 5)

- O-003 records forward-**INTENT** (a `forward_outbox` row); it does **not** route to subscribers
  (that is O-005).
- O-003 persists the monotonic `source_sequence` + the DLQ failure-envelope rows that **make replay
  possible**; it does **not serve** replay or DLQ-replay (a later task).
- mTLS provisioning is deferred to O-008; until then the ingest HMAC secret-holder is the interim peer
  authenticator, and `source_product = sentinel` is stamped by the receiver, never trusted from the body.
- O-003 builds the **ingest half** only. The GET query/bus read seams (`/v1/events`, `/v1/bus/dlq`,
  `/v1/bus/schema-versions`) are O-006.
- Framing is "audit-ready" and "risk reduction", never "compliant" or "blocks all attacks".

## Honest residuals

- **Cross-session chain gap.** The accept path commits the tenant transaction (`ingest_events` +
  `forward_outbox`) and then, in a separate privileged transaction, appends the chain link — two sessions
  because the chain is global/privileged (rule 7) and the data is tenant/app-role. A crash *between* the
  two commits leaves a chain gap that redelivery (which dedups the already-inserted event) does not
  refill. At-least-once + dedup keep this **bounded and non-duplicating**, and the gap is **detectable**
  (an `ingest_events` row with no matching chain link) and repairable. Full crash-consistency (a
  transactional-outbox / two-phase chain completion) is O-006. The e2e proves the happy-path chain link
  validates and is tamper-evident; it does not assert crash recovery (out of scope).
- **DLQ re-drive is bounded but not yet executed.** The `max_attempts_exceeded` terminal reason and the
  `attempt_count` bound are in the schema; the re-drive engine that increments and enforces them is a
  later task (serving replay-from-DLQ is out of scope). O-003 persists the fields that make the bound
  enforceable.
- **Coarse DLQ read token (carried, not introduced).** Fork E1 tenant-scopes the DLQ **store**; the
  coarse Delta read token (ADR-0001 boundary d) is an O-006 concern and O-003 does not implement the DLQ
  read seam.
- **`validate_chain` is O(n) memory.** It fetches the full `ingest_audit_log` chain in order and
  recomputes each link. For the O-003 scope (first migration; chain validation is audit tooling, not a
  request-path operation) this is acceptable; a streaming cursor (`yield_per`) over the chain is the
  O-006 hardening when the audit log grows large.

## Consequences

- The Orchestrator gains its first runtime + first migration. O-004…O-008 build on this baseline: the
  distribution engine, the subscriber registry + real forwarding (consuming `forward_outbox`), the full
  persistence consolidation + GET read seams, the UI, and deploy + mTLS.
- The ingest seam now has a live implementation that conforms exactly to the merged contract (no drift):
  the same envelope, the same 202 shape, the same HMAC scheme, the same closed DLQ-reason set, the same
  at-least-once + dedup-on-`idempotency_key` semantics.
- A new `orchestrator-integration` CI lane (a fresh `postgres:16-alpine` service) runs the non-stubbed
  e2e on every PR touching `Anoryx-AI-Orchestrator/**`, alongside the existing contract lane. CI on a
  fresh DB is the authority of record (rule 2) — local green proves nothing (load_dotenv repopulates env
  and masks drift).

## Rollback

The branch is additive: a new package, a new migration, a new CI lane, this ADR, and the audit doc.
Nothing in production consumes the Orchestrator runtime yet. Rollback = revert the O-003 commit (which
removes the runtime package, the `0001` migration, the integration lane, and the docs) and drop the
Orchestrator database. No other product depends on it at O-003 time; the contract (O-001/O-002) is
untouched.
