# ADR-0002: Ecosystem Event Bus Contract (O-002)

## Status

Proposed (2026-06-26). Second Anoryx-AI-Orchestrator ADR; builds on and does not contradict
**ADR-0001** (O-001 internal API contract). Scope: **contract-only** — a canonical cross-product
event **envelope** plus **replay**, **dead-letter (DLQ)**, and **schema-version negotiation**
semantics. There is no runtime, persistence, broker, or consumer in O-002. O-003 (ingest pipeline)
builds the machinery that *honors* replay/DLQ; O-004…O-008 bind to these shapes.

## Context

ADR-0001 deliberately left the event-ingest body as a **single bare event** and recorded that
"batching and a cross-product envelope are deliberately left to O-002 (anticipated, not specified) so
the contract is not painted into a corner." It also anticipated "a dedup key (`event_id` is the bus
dedup key, echoed on the 202) without specifying the O-002 envelope," and noted that "cross-product
**envelope** version negotiation is O-002 and is not specified here."

Without an envelope there is nowhere to carry idempotency, ordering, correlation, or a schema
version — and therefore no contractual basis for **dedup**, **replay**, or **DLQ**. O-002 supplies
exactly **one canonical event shape** across the whole Orchestrator contract and specifies the bus
semantics that O-003 will implement.

Inputs that constrain the design (unchanged from ADR-0001, restated for self-containment):

- **F-002 locked schemas.** `events.schema.json` (`$id sentinel:events:v1`) and `policy.schema.json`
  (`$id sentinel:policy:v1`, frozen at F-008 `a9e2344`), both JSON Schema **Draft 2020-12**, all
  objects closed (`additionalProperties:false`) and all fields bounded. The envelope **wraps the
  whole `events.schema.json` `oneOf` by `$ref`** and never copies or widens it. `events.schema.json`
  already designates `event_id` as **"the bus dedup key."**
- **OpenAPI 3.1.** O-001's `contracts/openapi.yaml` is `openapi: "3.1.0"`; O-002 stays 3.1 (3.1 aligns
  with 2020-12, so the locked schemas are `$ref`'d with no translation). **Fixed, not a fork.**
- **The four stable IDs** (`tenant_id/team_id/project_id/agent_id`) plus `event_id`,
  `event_timestamp`, `request_id` ride **inside** the wrapped payload; the envelope does not redefine
  them. The envelope's `correlation_id` defaults to the payload's `request_id`; its `idempotency_key`
  binds to the payload's `event_id`.
- **O-001 security posture.** mTLS authenticates the **peer product** on every operation; a per-event
  HMAC body signature gives the ingest seam tamper-evidence + a ±300s replay window; a Delta service
  token (bearer) authorizes the Delta/operator seams. **mTLS provisioning is deferred to O-008** —
  until then the interim peer-authenticators are the ingest HMAC and the service token (ADR-0001
  honesty boundary a). O-002 inherits this verbatim and adds no new transport security scheme.

## Decision

A standalone **event-envelope** schema (`contracts/event-envelope.schema.json`, 2020-12,
`$id anoryx:event-envelope:v1`) that wraps a locked F-002 event payload by `$ref`, plus three new
bus seams on the existing 3.1 `openapi.yaml` (bounded replay, DLQ read, schema-version negotiation),
and a **reconciliation of O-001's ingest seam** so there is exactly one event representation across
the contract. Each STEP-0 fork below resolved to the lean / fail-closed default (banked rule 4); the
owner confirmed all five.

### Fork A — Delivery posture: **at-least-once + consumer-side dedup on `idempotency_key`**

The bus promises **at-least-once** delivery. Consumers MUST dedupe on `idempotency_key`. Exactly-once
across a real broker/network is a distributed-systems trap that no implementation can honor, so the
contract does not promise it. `idempotency_key` is a first-class envelope field; for Sentinel events
it **MUST equal `payload.event_id`** (F-002's designated bus dedup key). This is honesty boundary (b).

### Fork B — Replay model: **bounded replay + monotonic `sequence`**

The envelope carries a monotonic, strictly-increasing `sequence` (per `source_product` emission
stream). Replay is a **bounded** operation (`POST /v1/bus/replays`): a caller replays from a
`from_sequence` **or** `from_timestamp` **or** a specific `dlq_id`, always with a `limit` cap, behind
mTLS + service token. Unbounded full event-store replay is rejected — it is a replay-amplification /
DoS surface with no rate ceiling. The replay endpoint **acknowledges** a request (202) and runs no
replay in O-002 (honesty boundary a).

### Fork C — Unknown `schema_version`: **reject-to-DLQ (fail-closed)**

`schema_version` is an envelope-level integer (the envelope schema major; v1 = `1`). A v1 consumer
accepts `1` and routes **any unrecognized value to the DLQ** — it does not best-effort-parse an
unknown shape. The supported set is published as an explicit allow-list via
`GET /v1/bus/schema-versions`. This is honesty boundary (c).

A deliberate modelling choice: an unknown `schema_version` (e.g. `2`) still **structurally validates**
against the v1 envelope schema (the field is `integer, minimum 1`), so the message is well-formed and
is **routed to the DLQ** rather than rejected with a 422. Were the schema to pin `schema_version`
with a `const`, an unknown version would 422 at the schema gate and the reject-**to-DLQ** rule would
be untestable and unreachable. The reject-to-DLQ decision is therefore a documented **consumer
obligation** (O-003), not a schema constraint — stated, not implied.

### Fork D — O-001 ingest reconciliation: **envelope canonical; rewire the ingest seam** (load-bearing)

`POST /v1/ingest/events` is rewired so its `requestBody` `$ref`s the **envelope**, which wraps the
F-002 payload under `payload`. This gives the contract **one event shape** (rule 8). It is a
deliberate revision to an already-merged contract — safe now (nothing consumes O-001 in production),
recorded here, and proven by re-running O-001's contract suite.

The wrapped F-002 payload still validates against `events.schema.json` **unmodified** — it is simply
nested one level under `payload`. The alternative (leave O-001 ingest untouched, reconcile in O-003)
was rejected because it ships two event shapes and a temporary contradiction in a published
cross-product contract.

**Two O-001 tests are deliberately updated** (ADR-0001's suite explicitly permits "the 13 must still
pass or be deliberately updated, noted in the ADR"):

1. `test_ingest_example_validates_against_events_schema` — the ingest example is now an envelope, so
   the test validates `example["payload"]` against `events.schema.json`. This preserves the original
   intent (the wrapped F-002 payload validates **unmodified**), one indirection deeper.
2. `test_refs_point_only_at_locked_sentinel_schemas` — `openapi.yaml` now also `$ref`s the sibling
   `event-envelope.schema.json`. The allow-set is widened to
   `{events.schema.json, policy.schema.json, event-envelope.schema.json}`, still rejecting any other
   external target. The envelope file itself `$ref`s **only** the locked `events.schema.json`, so
   "reuse by reference, never by copy" is preserved transitively (no Sentinel schema is copied or
   widened anywhere).

The other **11** O-001 tests are unchanged. **Regression proof:** the extended suite is green locally —
**27 passed** = all 13 O-001 contract tests (including the two updated) + 14 new O-002 tests, with
`ruff check` and `black --check` clean and the codegen smoke passing. CI is the authority of record
(rule 2) and is confirmed green on the PR.

### Fork E — Envelope home: **standalone `event-envelope.schema.json`, `$ref`'d by `openapi.yaml`**

The envelope is a **shared cross-product wrapper**, so it lives in its own 2020-12 schema file and is
`$ref`'d by `openapi.yaml` (and by the `DeadLetterEnvelope`'s `original_envelope`). Inlining it in
`openapi.yaml` only would deny other products a referenceable wrapper. Reinforced by the deliverable
list, which names this exact standalone file.

### Envelope design (`anoryx:event-envelope:v1`)

Closed object (`additionalProperties:false`), all fields bounded (the F-001 audit posture: closed
schemas remove a smuggling channel, bounded fields remove a DoS-via-inspection vector). Fields:

| field | type / constraint | req | role |
|---|---|---|---|
| `schema_version` | integer, 1..1000 | yes | Envelope schema major. v1 accepts `1`; unknown → reject-to-DLQ (boundary c). |
| `envelope_id` | string, uuid, ≤64 | yes | Id of THIS envelope; distinct from `payload.event_id`. |
| `event_type` | string, slug `^[a-z0-9]+(_[a-z0-9]+)*$`, ≤64 | yes | Routing / DLQ-triage hint, surfaced so a router or a dead-lettered entry is classifiable **without opening the large `oneOf` payload**. MUST equal `payload.event_type`; the payload is authoritative; a consumer rejects-to-DLQ on disagreement (the same "a cross-check can never widen scope" placement O-001 uses for body IDs vs signature). |
| `source_product` | string, enum `[sentinel, orchestrator, delta, rendly]` | yes | The emitting product. Its **trusted** value is established by the **receiver** from the mTLS-authenticated peer identity; the body value MUST be verified against the peer and is **never trusted from the body** (rule 7). Disagreement → reject. The closed enum is the four ecosystem products. |
| `occurred_at` | string, date-time, ≤64 | yes | Envelope emission time (RFC 3339, UTC); distinct from `payload.event_timestamp` (the underlying event time). |
| `idempotency_key` | string, `^[A-Za-z0-9._:-]{1,128}$`, ≤128 | yes | Consumer dedup key (boundary b). For Sentinel events MUST equal the server-resolved `payload.event_id`. |
| `sequence` | integer, 0..9007199254740991 | yes | Monotonic, strictly increasing per `source_product` stream; the lower-bound for sequence replay. |
| `correlation_id` | string, `^[A-Za-z0-9._:-]{1,128}$`, ≤128 | yes | Groups a causal chain; defaults to `payload.request_id`. |
| `causation_id` | string, `^[A-Za-z0-9._:-]{1,128}$`, ≤128 | no | `envelope_id` of the direct predecessor; absent at chain root. |
| `payload` | `$ref ../../Anoryx-Sentinel/contracts/events.schema.json` | yes | The locked F-002 event (whole `oneOf`); validates **unmodified**. Same relative path O-001 already uses (rule 6). |

Three invariants are **documented contract obligations**, not schema constraints (JSON Schema 2020-12
cannot cross-reference sibling values), each consumer-enforced by O-003 and each with a fail-closed
disposition: `event_type == payload.event_type`, `idempotency_key == payload.event_id` (for events),
and `source_product == mTLS-authenticated peer`. Stating them as obligations — rather than pretending
the schema enforces them — is the honest framing.

### New bus seams on `openapi.yaml` (each mTLS + a second factor, per O-001's all-ops rule)

- `POST /v1/bus/replays` — `ReplayRequest` (`oneOf` over `{from_sequence} | {from_timestamp} | {dlq_id}`,
  plus `source_product` and a bounded `limit` 1..1000) → **202** `ReplayAccepted` `{replay_id, state:
  pending}`. mTLS + serviceToken. Bounded by window + `limit` + auth + rate; **acknowledges only**, no
  replay runs (boundary a).
- `GET /v1/bus/dlq` — read-only **metadata** page of dead-lettered entries (`DeadLetterMetadata`:
  `dlq_id, reason, attempt_count, first_failed_at, event_type, source_product, sequence`), filterable
  by `reason`/`source_product`/`since`/`until`, cursor-paginated. mTLS + serviceToken. It **never
  returns `original_envelope`** — consistent with ADR-0001's read-only-metadata boundary (the query
  seams expose metadata, never full payloads).
- `GET /v1/bus/schema-versions` — `SchemaVersions` `{supported: [1], envelope_schema_id:
  "anoryx:event-envelope:v1"}`. mTLS + serviceToken. The explicit allow-list backing the
  reject-to-DLQ rule (Fork C).

### DLQ failure-envelope (`DeadLetterEnvelope` component)

The dead-letter shape preserves the original and records why it failed: `dlq_id` (uuid),
`original_envelope` (`$ref event-envelope.schema.json` — the **original preserved**), `reason` (closed
enum: `unknown_schema_version, payload_schema_invalid, source_identity_mismatch, idempotency_conflict,
max_attempts_exceeded`), `attempt_count` (0..1000), `first_failed_at` (date-time), `last_failed_at`
(date-time, optional). Closed and bounded. This is the **full** failure-envelope the O-003 DLQ stores
and that replay-from-DLQ re-drives; the `GET /v1/bus/dlq` read seam returns the metadata projection of
it, not the full record (boundary, above).

## Honesty boundaries (verbatim, non-removable — rule 5)

These appear verbatim in `openapi.yaml` `info.description` and are repeated here:

- **(a)** Replay and DLQ are SPECIFIED, not implemented — O-003 builds the machinery.
- **(b)** Delivery is at-least-once; consumers MUST dedupe on `idempotency_key`.
- **(c)** Unknown-version handling is reject-to-DLQ.

Carried forward from ADR-0001 and still in force: mTLS provisioning is deferred to O-008 (the interim
peer-auth is the ingest HMAC + the service token); the query/read seams return **read-only metadata**,
never full payloads (the new `GET /v1/bus/dlq` honors this); the Delta service token is coarse-grained
(per-tenant read authorization is O-006).

## Threat model (seam)

Design-level — there is no enforcement code yet, so each vector lists what the **contract** asserts
and what is **explicitly deferred** to O-003.

1. **Replay amplification.** A caller (or a captured token) drives the bus to re-emit a huge history,
   flooding consumers. **Contract:** replay is bounded — a `from_sequence`/`from_timestamp`/`dlq_id`
   selector with a `limit` cap, behind mTLS + service token; the envelope's monotonic `sequence`
   gives a precise lower bound. Unbounded replay is not expressible. **Deferred:** the actual window
   enforcement + rate limiting is O-003.

2. **`source_product` spoofing.** A peer claims to be a product it is not (e.g. a compromised Delta
   credential stamping `source_product: sentinel`). **Contract:** `source_product`'s trusted value is
   the **mTLS-authenticated peer identity**; the body value MUST be verified against the peer and is
   never trusted from the body (rule 7); disagreement is rejected. **Gap:** mTLS provisioning is
   deferred to O-008 (ADR-0001 boundary a) — until then the ingest HMAC (only the holder of the
   shared signing secret can sign) is the interim emitter authenticator. Stated, not hidden.

3. **DLQ poisoning.** An attacker floods the DLQ with failing messages to exhaust storage or bury real
   failures, or re-drives a poisoned entry repeatedly. **Contract:** `attempt_count` is bounded and
   `max_attempts_exceeded` is a terminal `reason` (no infinite re-drive); DLQ entries are bounded
   (closed + `maxLength`/`maximum`); both the DLQ read and replay-from-DLQ sit behind mTLS + service
   token. **Deferred:** the attempt-ceiling enforcement and DLQ quota are O-003.

4. **Version downgrade.** An attacker sends an unknown/older `schema_version` hoping for lenient
   "best-effort" parsing that skips a newer validation. **Contract:** unknown `schema_version` →
   **reject-to-DLQ** (fail-closed, Fork C); `supported` is an explicit allow-list
   (`GET /v1/bus/schema-versions`); there is no best-effort path to exploit. **Deferred:** the routing
   decision itself is O-003.

5. **Idempotency-key forgery → event suppression.** A faulty or malicious emitter sets
   `idempotency_key` to a value matching an already-seen key, so an at-least-once consumer **dedupes
   (drops) the new event** — silently suppressing it. **Contract:** `idempotency_key` MUST equal the
   **server-resolved** `payload.event_id` (F-002 attribution is server-resolved, not a client header),
   and the ingest HMAC gives per-event tamper-evidence over `"{timestamp}.{body}"`, so an in-flight
   forgery is detectable. **Deferred:** the consumer's key==event_id check and the dedup store are
   O-003; the contract states the binding, the runtime enforces it.

## Consequences

- O-003 (ingest pipeline) implements at-least-once consumption + dedup on `idempotency_key`, the
  reject-to-DLQ router, the DLQ store with the attempt ceiling, and the three documented invariants
  (`event_type`/`idempotency_key`/`source_product`). O-004…O-008 bind to the envelope, the DLQ shape,
  and the replay/version seams. Changing the envelope shape or a bus path later is a breaking change
  to a published cross-product contract.
- The Orchestrator contract now has **one event shape**: every ingested event is an envelope wrapping
  a locked F-002 payload. O-001's ingest seam is revised accordingly (Fork D), with the two test
  updates above as the recorded regression boundary.
- Because the envelope (and the spec) `$ref` the locked F-002 schemas, the CI lane already triggers on
  `Anoryx-Sentinel/contracts/**` as well as `Anoryx-AI-Orchestrator/**` — a change to
  `events.schema.json` that would break an envelope example runs this lane (unchanged from O-001).
- No `policy_type` is added and no Sentinel schema is widened; `policy.schema.json` stays frozen at
  F-008 `a9e2344`.

## Rollback

The contract is additive and stands alone (no runtime depends on it yet). Rollback = revert the O-002
commit, which removes `contracts/event-envelope.schema.json`, the `openapi.yaml` bus additions, the
ingest reconciliation (restoring the O-001 bare-event body), `docs/adr/0002-*`, the extended tests,
and the root audit doc. The two O-001 test edits revert with it. No data migration, no deployed
surface, nothing else depends on it at O-002 time.
