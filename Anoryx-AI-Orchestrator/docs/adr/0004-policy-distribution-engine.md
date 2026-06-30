# ADR-0004 — Policy Distribution Engine (O-004)

- **Status:** Proposed (STEP 1 gate — awaiting Affu review before any code)
- **Date:** 2026-06-30
- **Supersedes:** none
- **Builds on:** ADR-0001 (Orchestrator internal API contract / O-001),
  ADR-0003 (event ingest pipeline + persistence / O-003), Sentinel ADR-0026
  (double-begin fail-open fix). Reuses the O-003 persistence layer unchanged.
- **Risk:** HIGH — this engine pushes Delta's budget/deny policies into Sentinel's
  enforcement path. A defect ships a bad policy into live enforcement. Gate scrutiny
  is doubled.

---

## 1. Context

O-004 is the second Orchestrator runtime task. It implements the policy-distribution
seam that O-001 (ADR-0001) declared in the contract and left unimplemented:

- `POST /v1/policies/distributions` — Delta submits a signed policy record for
  distribution (`PolicyDistributionRequest`). Returns **202** `DistributionAccepted`.
- `GET /v1/policies/distributions/{distribution_id}` — distribution + per-target status
  (`DistributionStatus`).

Both are defined in `Anoryx-AI-Orchestrator/contracts/openapi.yaml` (O-001, MERGED).
This ADR does not re-decide their shapes; it implements them.

The engine takes the already-signed policy and forwards it, unchanged, to one or more
Sentinel deployments, tracking per-target status, retrying on transient failure, and
recording a hash-chained distribution audit.

### 1.1 Blocking premise correction (Fork F) — Sentinel has no HTTP policy-intake route

The task brief states *"F-012a (Sentinel admin API) is the outbound target that already
exists."* **It does not.** Verified across three independent explorations + direct grep:

- `GET /admin/tenants/{tenant_id}/policies` is **read-only** (`Anoryx-Sentinel/src/admin/control.py:160`,
  `Anoryx-Sentinel/contracts/openapi.yaml:1013`). No `POST`/`PUT`/`PATCH` policy-accept route
  exists anywhere under `/admin` (`Anoryx-Sentinel/src/admin/router.py:46-54`).
- The only policy intake is the internal async function `intake_policy()`
  (`Anoryx-Sentinel/src/policy/intake.py:75`), called solely by the internal CLI
  `sentinel-cli policy push` (`Anoryx-Sentinel/src/policy/cli.py`). No HTTP.
- `Anoryx-Sentinel/src/orchestration/__init__.py:8-11` states verbatim: *"the event-bus
  emitter, **policy-intake API**, and internal mTLS channel … are owned by a separate task
  and are NOT part of F-005."* — the Sentinel-side HTTP policy-intake route is an explicitly
  un-built future task.

**Resolution (Affu, STEP 0): F1.** The engine targets a *configurable Sentinel admin-intake
URL*. The non-stubbed e2e stands up a **test-only HTTP shim** (in the Orchestrator test
harness) that is gated by `Authorization: Bearer <SENTINEL_ADMIN_TOKEN>` and wraps Sentinel's
**real** `intake_policy()` + **real** `enforcement.py`. The distribution *call* is fully real
(real HTTP, real peer-auth, real pass-through signed JWS); Sentinel's real ES256 verification,
persistence, and enforcement run unstubbed. The only test-harness code is the HTTP envelope —
and it is test-only precisely because the production Sentinel route does not yet exist. **No
Sentinel `src/` or `contracts/` files are touched** (subproject boundary respected).

**Honesty boundary (non-removable):** the shipped Sentinel-side HTTP policy-intake route does
not exist; O-004 distributes to the documented admin-intake contract; standing up that route
inside Sentinel is a separate Sentinel task.

---

## 2. Resolved forks

| Fork | Decision | Rationale |
|------|----------|-----------|
| **A — Signing posture** | Pass-through of an already-signed compact-JWS policy. Orchestrator never signs on Delta's behalf and never holds Delta's key. | The contract already enforces this at the schema layer: `PolicyDistributionRequest.sign_on_behalf` is `enum: [false]` (`openapi.yaml:761`). Orchestrator-signing is a deliberate trust-surface expansion gated behind a future ADR. |
| **B — Peer auth to Sentinel** | Interim `Authorization: Bearer <SENTINEL_ADMIN_TOKEN>`, mirroring Sentinel's real `require_admin` (`Anoryx-Sentinel/src/admin/auth.py:120`, constant-time compared). Real mTLS deferred to **O-008**. | Consistent with O-003's interim posture (HMAC/bearer until mTLS lands). Does not duplicate the cert-provisioning work that is O-008's scope. |
| **C — Multi-target consistency** | Per-target **independent** status, best-effort fan-out, partial state surfaced honestly. | Atomic multi-target distribution is a distributed-transaction trap. The contract already models this: `DistributionStatus.state` includes `partial` (`openapi.yaml:834`); `DistributionTargetStatus.state ∈ {pending, distributed, failed}` (`:808`). |
| **D — Retry semantics** | Bounded retries with exponential backoff; on exhaustion the target moves to `failed`, an alert is emitted (structured log + metric), and a `failed` audit link is appended. The set of `failed` targets *is* the queryable dead-letter set (surfaced via the GET status seam). | Unbounded retry is a retry-amplification DoS against both Sentinel and our own DB. Bounded + alert + observable-failure is honest and safe. |
| **E — "applied" confirmation honesty** | The engine stops at `distributed` (= the receiver accepted the policy). It never claims `applied`. | The contract has **no `applied` state** — only `distributed`/`partial`/`failed`. Whether a distributed policy is *live in F-008 enforcement* is not observable from the distribution seam, so it is not asserted. |
| **F — Outbound HTTP target** | **F1** (test HTTP shim over Sentinel's real intake+enforce; see section 1.1). | Respects the subproject boundary, keeps the distribution call genuinely non-stubbed, and runs Sentinel's real crypto-verify + enforcement. |

Fixed (not forks): validate every policy against the **LOCKED** `policy.schema.json`
(`sentinel:policy:v1`, frozen at F-008 `a9e2344`) unmodified; the six `policy_type` values
and both structural CHECK constraints are CLOSED — **never widened**. Migration `0002`
extends O-003's `0001`. RLS on every tenant-scoped table. Hash-chained audit reusing O-003's
`hash_chain` primitives. Intake shape matches O-001's contract exactly.

---

## 3. Decision — distribution design

### 3.1 Inbound — `POST /v1/policies/distributions`  (`src/orchestrator/distribution/router.py`)

Mirrors the O-003 ingest router boundary discipline (`src/orchestrator/ingest/router.py`):

1. **Peer auth (fail-closed).** Require `Authorization: Bearer <token>` and constant-time
   compare against the configured inbound service token (`ORCH_SERVICE_TOKEN`). Missing/
   malformed → **401**; mismatch → **403**. If `ORCH_SERVICE_TOKEN` is unset the seam can
   never match → 401 (fail-closed). The token is resolved non-fatally at app construction so
   an ingest-only deployment is not forced to configure the distribution seam; the *request*
   enforces presence. (Per O-001 honesty boundary (d) this bearer is coarse-grained; per-tenant
   authorization is O-006.)
2. **Parse + structural validation.** Parse JSON → 422 on malformed. Validate
   `PolicyDistributionRequest` (`additionalProperties: false`, required `policy`, optional
   `targets[]`/`sign_on_behalf`). `sign_on_behalf` must be `false` (schema enum) → else 422.
3. **Locked-schema policy validation.** Validate `policy` against the unmodified
   `policy.schema.json` via a `Draft202012Validator` (the same library/dialect as
   `schema_validation.py`). A failure → **422** (`policy_schema_invalid`). The Orchestrator
   does **NOT** cryptographically re-verify the JWS — Sentinel's intake is the verifying
   authority (`openapi.yaml:76`). Schema validation here is a structural guard, not a trust
   decision.
4. **NUL guard.** Reuse `_contains_nul`: a `\x00` anywhere in the policy record cannot be
   stored in Postgres `text`/JSONB, so it can be neither persisted nor recorded — reject at
   the boundary as 422 (not a 503 retry-storm). (O-003 audit M-2 class.)
5. **`tenant_id` is server-resolved.** `tenant_id` is taken from `policy.tenant_id` (the
   schema-validated body field), never a client header.
6. **Persist (tenant session, autobegin).** Under `get_tenant_session(policy.tenant_id)` —
   which **autobegins**; **no `async with session.begin()`** (ADR-0026 double-begin trap) —
   insert one `policy_distributions` row (`state='pending'`) and one
   `policy_distribution_targets` row per resolved target (`state='pending'`); `await
   session.commit()`.
7. **Audit (privileged session).** Under `get_privileged_session()` + `async with
   session.begin()` (privileged sessions do not autobegin), append one hash-chained
   `distribution_audit_log` link with `disposition='submitted'`.
8. **Schedule + respond.** Schedule `drive_distribution(distribution_id)` as a FastAPI
   `BackgroundTask` and return **202** `DistributionAccepted{distribution_id, policy_id,
   state:'pending'}`. Any error below the auth boundary propagates to the app's fail-safe
   handler → **503** (never a 202 for a non-durably-recorded distribution).

Target resolution: if `request.targets` is present, use it (each `{sentinel_id}`); otherwise
resolve from a static config map `ORCH_DISTRIBUTION_TARGETS` (`sentinel_id → base URL`). A
registry-backed dynamic resolver is **O-005, out of scope** — O-004 consumes a minimal static
list only. If no target resolves, the distribution is recorded with zero targets and aggregates
to `failed` (honest: nothing to distribute to).

### 3.2 Outbound engine — `drive_distribution()`  (`src/orchestrator/distribution/engine.py`)

For each target row of a distribution (per-target independent — Fork C):

1. Resolve `sentinel_id → base URL` from config. Unknown id → target `failed`
   (`unknown_target`), alert, audit link; continue to the next target.
2. POST the **byte-identical signed policy record** (the exact JSON stored in
   `policy_distributions.signed_record`, signature string unchanged) to
   `<base URL><ORCH_SENTINEL_INTAKE_PATH>` with header
   `Authorization: Bearer <SENTINEL_ADMIN_TOKEN>` (httpx async client, bounded timeout).
   Forwarding the record unchanged is what makes it **verify unchanged** on Sentinel:
   ES256 over `header.payload`, the 8-claim scope cross-check, and the `policy_hash`
   full-record content hash (`Anoryx-Sentinel/src/policy/crypto.py:206`, `…/intake.py`).
3. **2xx** → target `distributed`, `distributed_at` set, audit link `distributed`.
4. **Transient failure** (connection error, timeout, 5xx, 429): increment `attempt_count`;
   if `attempt_count < max_attempts` retry in a bounded in-process loop with exponential
   backoff; else move to `failed`, set `last_error`, emit an alert (structured log + metric
   counter), append a `failed` audit link.
5. **Permanent rejection** (4xx other than 429, e.g. Sentinel rejected the signature): target
   `failed` immediately (no retry — retrying a rejected signature is pointless amplification),
   `last_error`, alert, audit link.
6. After all targets settle, recompute the parent `policy_distributions.state`:
   all `distributed` → `distributed`; some `distributed`, some `failed` → `partial`; none
   `distributed` → `failed`; append a parent audit link with the terminal disposition.

**Exception discipline (ADR-0026).** Any `except` that swallows connectivity errors catches
**only** `(sqlalchemy.exc.OperationalError, sqlalchemy.exc.InterfaceError,
sqlalchemy.exc.TimeoutError, OSError)`. `InvalidRequestError`/`ProgrammingError` are
deliberately outside this family so a double-begin or any logic defect **raises** rather than
silently failing open (which would make the engine inert on a real DB). Outbound HTTP errors
are `httpx`-typed and handled explicitly in the retry logic, never folded into a bare `except`.

### 3.3 Status read — `GET /v1/policies/distributions/{distribution_id}`

Reads the distribution + its target rows under the caller's tenant session (RLS-scoped) and
returns `DistributionStatus` (parent state + per-target `DistributionTargetStatus[]`). 404 if
the distribution is not visible in the caller's tenant.

---

## 4. Schema — migration `0002` (extends `0001`)

`revision = "0002"`, `down_revision = "0001"`. Reuses O-003's role, NULLIF predicate, RLS
ENABLE+FORCE, append-only trigger, and GRANT patterns verbatim
(`migrations/versions/0001_ingest_baseline.py`).

**`policy_distributions`** (tenant-scoped, RLS):
`distribution_id` (PK, uuid text), `policy_id`, `policy_version` (bigint), `tenant_id`
String(64) NOT NULL, `policy_type` String(32), `state` String(16)
CHECK ∈ {pending, distributed, partial, failed}, `signed_record` JSONB (the exact signed
policy, for byte-identical forwarding), `content_hash` String(64), `created_at`/`updated_at`
TIMESTAMP(tz). `policy_type` CHECK lists the six existing values — **membership check only,
never a widening** of the locked enum.

**`policy_distribution_targets`** (tenant-scoped, RLS):
`target_id` (PK), `distribution_id` (FK → policy_distributions, ON DELETE CASCADE),
`tenant_id` String(64) NOT NULL, `sentinel_id` String(128), `state` String(16)
CHECK ∈ {pending, distributed, failed}, `attempt_count` int default 0, `max_attempts` int,
`last_error` text NULL, `next_attempt_at` TIMESTAMP(tz) NULL, `distributed_at` TIMESTAMP(tz)
NULL, `created_at`/`updated_at`. UNIQUE `(distribution_id, sentinel_id)` (idempotent per
target).

**`distribution_audit_log`** (global hash chain — mirrors `ingest_audit_log`):
`sequence_number` bigserial PK; attribution `distribution_id`, `policy_id`,
`tenant_id` (NULL — chain is global, RLS scopes SELECT), `policy_type`; envelope-derived
`disposition` String(16) CHECK ∈ {submitted, distributed, partial, failed};
opt-in-when-present `sentinel_id` NULL, `error_reason` NULL; `prev_hash` String(64) NOT NULL,
`row_hash` String(64) NOT NULL UNIQUE; `created_at`. Append-only via BEFORE UPDATE/DELETE
triggers + RLS deny-update/deny-delete; `FOR SELECT USING (NULLIF predicate)`, `FOR INSERT
WITH CHECK (true)`.

**RLS / GRANTs:** ENABLE + FORCE RLS with the NULLIF tenant predicate on
`policy_distributions` and `policy_distribution_targets`. GRANT `SELECT, INSERT, UPDATE` on
those two to `orchestrator_app` (UPDATE is required for state transitions). GRANT `SELECT`
only on `distribution_audit_log` (its inserts run on the privileged session). Sequence USAGE
grants for the two bigserial/identity columns.

**Reversibility:** `downgrade()` drops policies → triggers → tables in FK-safe order
(`policy_distribution_targets` → `policy_distributions` → `distribution_audit_log`), leaving
O-003's `0001` objects intact. A non-stubbed `0001 <-> 0002` round-trip is asserted in
`tests/integration/test_migration_roundtrip.py` (which is updated from head `0001` → `0002`).

**Hash-chain reuse (additive, O-003 `hash_chain.py` untouched):** new
`DISTRIBUTION_GENESIS_HASH = sha256("anoryx-orchestrator:distribution-audit:genesis:v1")`
(domain-separated from the ingest chain so the two can never be confused),
`DISTRIBUTION_CANONICAL_FIELDS` (fixed order, `prev_hash` last), `_DISTRIBUTION_OPTIONAL_FIELDS`
= `("sentinel_id", "error_reason")` (opt-in-when-present: folded into the hash only when not
None, so a `submitted` link hashes identically with or without them — backward-compatible,
tamper-evident when set), and `compute_distribution_row_hash`. A new
`repositories.append_distribution_audit_link` (own advisory-lock key, own tip query) appends a
link; `validate_distribution_chain` re-validates with the same fail-loud bypass-RLS assertion
O-003 uses.

---

## 5. Threat model

| # | Threat | Mitigation |
|---|--------|-----------|
| T1 | **Forged-signature pass-through.** A caller submits a policy whose JWS is invalid or forged, hoping the Orchestrator forwards it and it lands in enforcement. | The Orchestrator never treats the signature as trusted — it forwards unchanged and Sentinel is the verifying authority. Sentinel's `intake_policy` performs full ES256 verification, the 8-claim scope cross-check, and the `policy_hash` content-hash check; a forged/invalid signature is **rejected at Sentinel** → the target moves to `failed` (permanent, no retry) and is surfaced. The Orchestrator forwards but never *applies*; a bad signature cannot reach enforcement. Schema validation at intake additionally rejects structurally malformed records before they are ever stored. |
| T2 | **Stale-policy / rollback replay.** A caller re-submits an old `policy_version` to roll a tenant back to a weaker policy. | Replay/rollback defense lives in Sentinel intake (reject `policy_version <=` stored — `policy.schema.json` line 6, F-008). The Orchestrator forwards; Sentinel rejects the stale version → target `failed`, surfaced. The `distribution_audit_log` records every submission (including rejected ones) tamper-evidently, so a replay attempt is auditable. |
| T3 | **Distribution to a spoofed Sentinel.** An attacker stands up a rogue endpoint and tricks the engine into distributing tenant policies to it (policy exfiltration / poisoning a fake enforcement plane). | Targets are resolved only from the trusted static `ORCH_DISTRIBUTION_TARGETS` config (or an explicit `targets[]` whose `sentinel_id` must still resolve in that map) — never from an attacker-controlled URL in the request body. The outbound call presents `SENTINEL_ADMIN_TOKEN`; a rogue endpoint cannot impersonate the real Sentinel back-channel. Full mutual authentication (mTLS, so the *Orchestrator* also verifies the Sentinel's identity) is deferred to **O-008** and stated as a known interim gap. Until then a compromised config map is the trust anchor — documented, not hidden. |
| T4 | **Partial-distribution consistency.** One target accepts, another fails; an operator believes the policy is uniformly live. | Per-target independent status (Fork C). The parent aggregates to `partial` (never silently `distributed`) and the GET status seam exposes each target's state and `last_error`. No all-or-nothing illusion is presented. |
| T5 | **Retry amplification (DoS).** A persistently failing target drives unbounded retries that hammer Sentinel and our own DB. | Bounded retries with exponential backoff and a hard `max_attempts` (Fork D). On exhaustion the target is `failed` and alerted; it is not retried in a loop. A permanent 4xx rejection short-circuits retries entirely. |
| T6 | **Audit tampering.** An insider edits or deletes distribution-audit rows to hide a bad distribution. | `distribution_audit_log` is a SHA-256 hash chain (`prev_hash` links every row) with BEFORE UPDATE/DELETE triggers and RLS deny-update/deny-delete policies; inserts run only on the privileged session. Any edit/deletion breaks the chain and is detected by `validate_distribution_chain`, which itself fails loud if run under a non-BYPASSRLS role (so it can't vacuously pass over an invisible chain). The chain genesis is domain-separated from the ingest chain. |
| T7 | **Cross-tenant leakage.** Tenant A reads or distributes tenant B's policies. | `tenant_id` is server-resolved from the validated `policy.tenant_id`, never a header. All tenant-scoped tables have RLS ENABLE+FORCE under the `orchestrator_app` NOBYPASSRLS role with the NULLIF predicate (unset GUC → zero rows, fail-closed). The GET status seam reads under the caller's tenant session. |
| T8 | **NUL-byte poison.** A policy string field carries `\x00`, crashing the JSONB persist so the distribution is neither recorded nor rejected (retry storm). | `_contains_nul` boundary guard rejects such a record as 422 (deterministic terminal disposition), reusing the O-003 audit M-2 mitigation. |

---

## 6. Consequences

- **Positive:** implements the O-001 distribution seam end-to-end; reuses the proven O-003
  persistence + RLS + hash-chain stack with no changes to shipped code; honest per-target /
  partial / non-`applied` semantics; full tamper-evident audit; the e2e proves real ES256
  verification and real allow/deny enforcement with nothing stubbed on the distribution call.
- **Negative / deferred (stated honestly):** (a) the Orchestrator does not mutually
  authenticate the Sentinel it distributes to — mTLS is O-008; the static target config is the
  interim trust anchor. (b) "applied" (live-in-F-008) is not observable from the distribution
  seam and is not claimed. (c) the production Sentinel-side HTTP policy-intake route does not
  exist; O-004 distributes to the documented admin-intake contract and the real route is a
  separate Sentinel task (Fork F / F1). (d) dynamic registry-backed target resolution is O-005;
  O-004 consumes a static minimal list.
- **CI:** the integration lane (`orchestrator-ci.yml`) is extended to install Sentinel's
  package + run Sentinel migrations into a separate `sentinel_ci` database and set
  `POLICY_SIGNING_PUBKEY_PATH`, so the e2e's test shim can drive Sentinel's real intake +
  enforcement. The distribution e2e lives under `tests/integration/` with
  `@pytest.mark.integration` + the `db_ready` gate, so it auto-runs in the integration lane and
  auto-skips in the contract lane.

---

## 7. Alternatives considered

- **F2 (build the real Sentinel HTTP intake route now):** cleanest end-state but crosses into
  the Sentinel subproject (contract + code via api-architect), doubling the PR and violating
  "agents stay in their subproject" for an Orchestrator task. Rejected for O-004; it is a
  legitimate future Sentinel feature.
- **F3 (in-process `intake_policy()`, no HTTP):** abandons the cross-product HTTP distribution
  premise entirely. Rejected.
- **Atomic all-or-nothing distribution (Fork C alt):** a distributed-transaction trap across
  independent Sentinel deployments; rejected for per-target best-effort.
- **Orchestrator-signs-on-behalf (Fork A alt):** the Orchestrator holding Delta's signing key
  is the larger trust surface; the contract gates it off (`enum:[false]`) pending a future ADR.
