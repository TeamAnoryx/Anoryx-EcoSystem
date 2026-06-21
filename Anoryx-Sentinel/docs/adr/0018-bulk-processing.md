# ADR-0018 — Bulk Processing Pipeline (F-015)

- **Status:** Proposed
- **Date:** 2026-06-22
- **Deciders:** (bulk-pipeline owner / implementer), persistence (migrations `0018`/`0019`, `events_audit_log` constants, new `BatchRepository`), api-architect (contract — `openapi.yaml` `/v1/batches*` + `events.schema.json` 5 variants + `ids.md` `bulk-worker` slug), security-auditor (extended-adversarial gate — async cross-tenant isolation is the highest-risk surface in F-015), Affu (solo founder & product owner — resolved the STEP-0 forks during planning: **Fork 1 worker-scoping = (a) per-job `get_tenant_session`**, **Fork 2 delivery = (a) at-least-once + idempotent dedup**, **Fork 3 storage = (a) MinIO wired, S3 behind the interface**, **Fork 4 autoscaling = (a) KEDA-ready, autoscale deferred**, **Fork 5 submission = (a) data-plane virtual-API-key**; approves this ADR at the STEP-1 gate).
- **Supersedes / amends:** Builds **on top of** and **does not modify** ADR-0005/0006 (tenant isolation / RLS Option α — F-015 **reuses** `get_tenant_session(TARGET)` for all per-file work and `get_privileged_session()` only for the global hash-chain append, exactly as the sync gateway does; **no new bypass**), ADR-0007 (F-005 hooks/detectors — F-015 **reuses** `build_default_registry()` + `HookRegistry.run_pre_request` per file; detector logic unchanged), ADR-0009 (F-008 policy — F-015 **reuses** `evaluate_model_policies` / `evaluate_budget_pre_request`; engine unchanged), ADR-0011 (F-009 Redis/observability — F-015 **reuses** the Redis pool for the Streams queue + per-tenant counters, and the metrics registry for the KEDA-ready signal), ADR-0012 (F-010 deployment — F-015 follows the optional-extras + slim-image discipline and adds a MinIO compose service), ADR-0003 (persistence / hash-chain audit — F-015 **appends** new event variants via the existing append-only writer; never mutates rows). Governed by `contracts/openapi.yaml`, `contracts/events.schema.json`, `contracts/ids.md`. **The contracts win over this ADR on any conflict.**
- **Feature:** F-015 — the **async batch lane**: a tenant uploads many files to object storage, submits them as a batch, and a **worker pool** runs **each file through the same F-005 detectors + F-008 policy** as the synchronous gateway — under the submitting tenant's RLS scope — with per-file outcomes audited, failures isolated to a DLQ, idempotent replay, and a per-file outcome manifest that reconciles with the append-only audit log. It introduces Sentinel's **first async principal** (a worker outside the HTTP request path) and its **first external storage surface** (presigned object storage).

---

## 1. Context and Decision Summary

### 1.1 Context (what exists today)

Every Sentinel inspection to date is **synchronous and in-request**: a single
`/v1/chat/completions` call resolves a `TenantContext`, runs the F-005 hook chain, applies
F-008 policy, proxies upstream, and appends one audit record — all under one tenant session
on one event-loop task. The raw material F-015 builds on:

- **Tenant isolation** (ADR-0005, Option α): `get_tenant_session(tenant_id)` on the
  **`sentinel_app`** login role (**NOBYPASSRLS**) sets the transaction-local GUC
  `app.current_tenant_id`; the RLS predicate
  `tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')` fail-closes to
  zero rows when the GUC is unset/empty, and `get_tenant_session` raises
  `TenantContextRequiredError` on a missing/empty tenant_id **before** opening the
  transaction. `get_privileged_session()` (owner, **BYPASSRLS**, no GUC) is the sanctioned
  path for hash-chain ops, migrations, and break-glass — **never** for serving ordinary
  tenant traffic.
- **Detectors** (ADR-0007): `orchestration/registry.py` `build_default_registry()` returns a
  `HookRegistry`; `run_pre_request(content, ctx)` runs SecretInbound → Injection → PII in
  order, returns the (possibly masked) content, and raises `HookBlockedError` on a block or
  `HookFailSafeError` on an unexpected detector error (fail-safe BLOCK, never silent pass).
  `orchestration/context.py` `build_hook_context(...)` builds the per-call context.
- **Policy** (ADR-0009): `policy/enforcement.py` `evaluate_model_policies(session, scope,
  model_id)` and `evaluate_budget_pre_request(session, scope, est_tokens, est_cost)` resolve
  deny/allow/budget decisions; `scope_from_context(tenant_context)` builds the four-ID scope.
  These run on the **caller's tenant session** (RLS-scoped reads).
- **Audit** (ADR-0003): `AuditLogRepository(session).append(event_data)` appends an
  append-only, SHA-256-chained row; it **asserts a privileged session** and takes
  `pg_advisory_xact_lock` (the chain is global, ordered by `sequence_number`). The honest
  attribution template is `src/admin/audit.py` `emit_admin_event(...)`.
- **Redis** (ADR-0011): `gateway/redis_client.py` `get_client()` returns a client from a
  shared pool (init in `gateway/main.py`); `arq>=0.26` and `redis>=5` are **already core
  dependencies**.
- **Auth / context** (ADR-0006): `AuthMiddleware` resolves the Bearer virtual key →
  `request.state.virtual_key_row`; `resolve_tenant_context(request)` builds the immutable
  `TenantContext` (the four server-resolved stable IDs). `RequestValidationMiddleware`
  caps the request body at 1 MiB.
- **Events 4-site discipline**: `VALID_EVENT_TYPES` (`events_audit_log.py`, 34 types) +
  `ACTION_TAKEN_BY_EVENT_TYPE` + `ck_eal_event_type` (last widened migration `0015`) +
  `contracts/events.schema.json`. Migration head = **`0017`**.
- **Attribution** (`contracts/ids.md`): `WILDCARD_UUID` = system attribution (5 documented
  uses); reserved `agent_id` slugs `all-agents`, `rate-limiter`, `admin-console`,
  `operator-sso`; optional `actor_id` for human operators.

**What does not exist:** any principal that runs **outside** the HTTP request path, any
**external object-storage** surface, and any **queue/worker** infrastructure beyond the
already-declared `arq` dependency. F-015 adds all three.

### 1.2 Decision (one paragraph)

We add a **`src/bulk/` package** providing: (1) a **`Storage` abstraction** with a wired
**MinIO/S3-compatible** backend (**Fork 3 (a)**), issuing **presigned PUT/GET** URLs scoped
to a single, **tenant-namespaced, unguessable, server-minted** object key with a short TTL
and size/count caps; (2) a **data-plane submission API** under `/v1/batches*`
(**Fork 5 (a)**) authenticated by the **existing virtual-API-key** path (`AuthMiddleware` +
`resolve_tenant_context`, zero new auth), tenant-scoped so a tenant sees only its own
batches; (3) a **Postgres job/file state model** (`batches` + `batch_files`, RLS-scoped,
migration `0018`) carrying status, an **idempotency key**, and a checkpoint cursor; (4) a
**Redis Streams queue** (reusing the F-009 pool) consumed by an **Arq worker pool** where
each worker, per job, opens an **explicit `get_tenant_session(submitting_tenant_id)`**
(**Fork 1 (a)** — the security spine) and processes **every file through the same F-005
detectors + F-008 policy** as the sync path (**no bypass, no reimplement**); (5)
**at-least-once delivery + idempotent dedup** (**Fork 2 (a)**) with **bounded retry → DLQ**,
**checkpointing** that skips completed files on resume, and a **per-file outcome manifest**
that reconciles with the append-only audit log; (6) **per-tenant batch limits +
backpressure** via Redis counters so one tenant cannot starve others; (7) **five new event
variants** added **4-site** with a reversible migration (`0019`), attributed honestly to the
**submitting tenant + a new reserved `bulk-worker` principal slug**. The worker pool is
**horizontally scalable and KEDA-ready** (it exposes a clean queue-depth scaling signal) but
**real KEDA autoscaling is DEFERRED** (**Fork 4 (a)**); the roadmap's 5000-files/5-min
target is validated as a **measured design goal** by a load-test harness, not promised as a
production autoscale guarantee. **No `/v1` sync path, no F-003/F-003b/F-005/F-008/F-009/F-010
engine logic is modified** — F-015 is purely additive.

### 1.3 What changes vs. what is frozen

| Frozen (MUST NOT change) | Changes (F-015) |
|---|---|
| ADR-0005/0006 RLS role/GUC model | **Reused unchanged.** Worker opens per-job `get_tenant_session(submitting_tenant)`; privileged session only for the global hash-chain append. No new bypass. |
| F-005 detectors / `HookRegistry` (ADR-0007) | **Reused per file** via `build_default_registry()` + `run_pre_request`. Logic untouched. |
| F-008 `policy/enforcement.py` (ADR-0009) | **Reused per file** (`evaluate_model_policies` / `evaluate_budget_pre_request`). Engine untouched. |
| `events_audit_log` rows / hash chain / append-only writer | F-015 **appends** 5 new variants via the existing writer; mutates nothing. |
| `ck_eal_action_taken` CHECK | **Unchanged** (new variants reuse `logged`/`blocked`). |
| Redis pool / rate limiter (ADR-0011) | **Reused** (Streams queue + per-tenant counters); limiter logic untouched. |
| `/v1/chat/completions` sync pipeline | **Untouched.** F-015 adds a parallel `/v1/batches*` lane. |
| `contracts/*` existing variants/paths | **Additive only** (api-architect): new `/v1/batches*` paths, 5 event variants, `bulk-worker` slug. No existing entry changed. |
| Slim base image (ADR-0012) | **Held.** Storage client is an optional `[bulk]` extra, lazy-imported; base/gateway image stays slim. |

---

## 2. Decision D1 (Fork 1) — Worker tenant-scoping = per-job `get_tenant_session` (the security spine)

**Affu chose (a) at the STEP-0 gate, with NO default offered** — this is the load-bearing
security decision of F-015 and the async twin of the F-012a cross-tenant escalation.

The Arq worker is a **new principal** that runs **outside** the HTTP request path, so it has
no `AuthMiddleware`, no `resolve_tenant_context`, and no ambient tenant. The job payload
therefore carries the **submitting tenant's four stable IDs**, captured at submit time from
the **authenticated** `TenantContext` (server-resolved from the virtual key — never
client-supplied). For each job the worker:

1. Opens **`get_tenant_session(job.tenant_id)`** on the `sentinel_app` (NOBYPASSRLS) engine.
   This is byte-for-byte the F-012a per-target pattern (`get_tenant_session(TARGET)`) and the
   F-003b Option α model. RLS is **fully in force**, scoped to the one named tenant.
2. Reconstructs a `TenantContext` from the job's four IDs and runs **all per-file work**
   under that session: `batch_files` state reads/writes, `build_hook_context` +
   `run_pre_request` (detectors), and `evaluate_model_policies` / `evaluate_budget_pre_request`
   (policy, whose `budget_period_used` reads `usage` events under RLS).
3. Uses **`get_privileged_session()` ONLY** for the global hash-chain audit append — exactly
   as the sync gateway's `emit_terminal_record` already does. The privileged session is
   **never** used to read or write tenant batch data.

**Why (a) and not (b) — a privileged worker with code-level scoping.** Option (b) would run
the worker on the BYPASSRLS engine and rely on application `WHERE tenant_id = …` filters per
job. That is precisely the **F-003b Option γ "RLS is decorative" failure mode**, reproduced
in async form: a single forgotten or wrong filter on any of the worker's many per-file
queries silently reads or cross-writes another tenant's data, and a batch processes thousands
of files per job — multiplying the blast radius. With (a), tenant isolation is a **property of
the engine/role**, enforced at the storage engine independent of worker-code correctness.
**Fail-closed by construction beats fail-closed by discipline**, and for a worker whose whole
job is to touch one tenant's data at scale, the DB floor is the only acceptable boundary.

**How it fails closed.** If `job.tenant_id` is missing/empty, `get_tenant_session` raises
`TenantContextRequiredError` **before** any query — the file is failed (retried → DLQ),
never processed under an ambient or wrong scope. If the GUC is somehow unset at the DB, the
`NULLIF` predicate yields zero rows (silent-deny), never another tenant's rows. A worker
**never** opens a blanket BYPASSRLS session for processing (vector 4 asserts no such code
path exists).

**Attribution.** Per-file lifecycle/outcome events attribute `tenant_id = the submitting
tenant` (the real owner — **never** `WILDCARD_UUID`) and `agent_id = "bulk-worker"` (the new
reserved subsystem slug). Per-file **security findings** are emitted by the reused F-005/F-008
path with their existing variants and the tenant's own four IDs.

---

## 3. Decision D2 (Fork 2) — Delivery = at-least-once + idempotent dedup

Affu chose (a). Redis Streams with a consumer group gives **at-least-once** delivery; we make
processing **idempotent** so redelivery and explicit replay are safe:

- Each batch carries a client-supplied **idempotency key**; `(tenant_id, idempotency_key)` is
  **unique** in `batches`. Re-submitting the same key returns the **existing** `batch_id`
  (no new batch, no re-enqueue) — no double-process / double-emit / double-bill (vector 9).
- Each `batch_files` row has a terminal status (`done` / `blocked` / `dead_lettered`). On
  redelivery or resume the worker **skips** files already in a terminal state (checkpoint, D3)
  — a file is processed (and its outcome emitted) **at most once** even though delivery is
  at-least-once.

Exactly-once delivery (b) was rejected: across a queue + external object storage + Postgres it
is substantially harder and usually illusory at the boundaries, for no real gain over
at-least-once + dedup.

---

## 4. Decision D3 — Failure isolation: bounded retry → DLQ, checkpointing, manifest

- **Failure isolation (R7).** A single file failure (fetch error, detector fail-safe,
  transient DB error) **does not fail the batch**. The file is retried up to a bounded count
  (config, default 3) with backoff; on exhaustion it is moved to a **DLQ** (a dedicated Redis
  dead-letter stream) and its `batch_files` row is set `dead_lettered`. Other files proceed.
- **DLQ is audited (R6).** Every dead-letter emits `batch_file_dead_lettered` (append-only) —
  **no silent drops** (vector 15). The DLQ entry records the file key + failure class (never
  raw content / secrets / PII).
- **Checkpointing (R5/R7).** The `batch_files` terminal status **is** the checkpoint: a
  resumed or redelivered batch skips files already `done`/`blocked`/`dead_lettered` and
  processes only the remainder (vector 10). This ties resume to idempotency (D2).
- **Manifest + reconciliation (R6).** `GET /v1/batches/{id}/files` serves the per-file
  outcomes from `batch_files` (RLS-scoped, **read-only** — the serving SELECT issues zero
  writes, mirroring F-012a D5/vector 9). Every terminal per-file outcome is **also** in the
  append-only audit log (`batch_file_processed` / `batch_file_blocked` /
  `batch_file_dead_lettered` + the reused detector/policy events), so the manifest
  **reconciles** with the log and there is **no unaudited mutation** (the F-012a MED-2 lesson;
  vector 14).

---

## 5. Decision D4 — Per-file processing reuses F-005 + F-008 (no bypass, R2)

Each file runs the **same pipeline as a sync request**, never a fast lane around security:

1. Fetch the object from storage by its validated key (D6); validate **actual bytes**, ignore
   the declared content-type (vector 6); reject oversize on fetch as a backstop (vector 5).
2. `build_hook_context(...)` from the reconstructed `TenantContext` + the file content, then
   `hook_registry.run_pre_request(content, ctx)` — PII / injection / secret detection. A block
   → outcome `blocked`; a `HookFailSafeError` → the file is failed (retry → DLQ), **never
   passed as allowed** (fail-safe, ADR-0007 D3).
3. `evaluate_model_policies` / `evaluate_budget_pre_request` on the tenant session — policy
   deny / budget exceeded → outcome `blocked` (vector 13).
4. Record the per-file outcome (`allowed` / `blocked` / `redacted` + findings) in `batch_files`
   (tenant session) and emit the lifecycle event + reused findings (vector 12).

The registry is **`build_default_registry()`** — identical detectors, identical order. No
detector or policy code is copied or modified (R2/R9).

---

## 6. Decision D5 — Storage surface (presigned, tenant-namespaced, content-validated)

- **Single `Storage` interface** (`presign_put`, `presign_get`, `fetch`, `head`); the
  **MinIO/S3-compatible backend is wired v1** (Fork 3 (a)); AWS S3 is selectable behind the
  same interface by config. The client is an optional **`[bulk]` extra**, lazy-imported with a
  `pip install …[bulk]` hint (slim-image discipline, R10).
- **Keys are server-minted, tenant-namespaced, unguessable** (R3):
  `{tenant_id}/{batch_id}/{uuid4}`. The tenant prefix + a random component mean a tenant
  cannot read another tenant's objects by key guessing (vector 2). Keys are **validated** on
  every use: reject path traversal (`..`), absolute paths, URL-encoded escapes, and any key
  whose prefix is not the caller's tenant (vector 7). The server **only accepts keys it
  minted** for that tenant (recorded in `batch_files`).
- **Presigned PUT** is single-object-scoped, carries a **content-length-range** condition
  (size cap, vector 5) and a **short TTL**; it cannot be reused for another object or tenant
  and expires (vector 3). Upload **count** per batch is capped.
- **No SSRF surface (R4).** The pipeline fetches **only** from the single configured storage
  endpoint by a validated, server-minted key — it **never** fetches an arbitrary
  user-supplied URL. There is no code path that takes a host/URL from the request, so the
  internal/metadata-endpoint SSRF class is **structurally removed** (vector 8), not merely
  guarded.

---

## 7. Decision D6 — Per-tenant limits + backpressure (R8)

Per-tenant **concurrent-batch** and **in-flight-file** caps are enforced via Redis counters
(keyed per tenant), mirroring the F-009 `rate_limit.py` Redis-counter pattern. Exceeding a cap
yields backpressure (HTTP `429` on submit / deferred enqueue), so one tenant's large batch
cannot starve others of worker capacity (vector 16) — the F-009 fairness concern in batch
form. Counters are decremented as files reach a terminal state.

---

## 8. Decision D7 — Event variants (5) + honest attribution + 4-site

Five new variants, added in lockstep across the **four sites**:

| event_type | emitted when | tenant_id | team/project | agent_id | action_taken |
|---|---|---|---|---|---|
| `batch_submitted` | batch accepted at submit | submitting (real) | key's real | `bulk-worker` | `logged` |
| `batch_file_processed` | a file completes (allowed/redacted) | submitting (real) | key's real | `bulk-worker` | `logged` |
| `batch_file_blocked` | a file blocked by detector/policy | submitting (real) | key's real | `bulk-worker` | `blocked` |
| `batch_file_dead_lettered` | a file dead-lettered after retries | submitting (real) | key's real | `bulk-worker` | `logged` |
| `batch_completed` | all files reach a terminal state | submitting (real) | key's real | `bulk-worker` | `logged` |

- **Honest attribution (R6).** `tenant_id` is **always** the real submitting tenant —
  **never** `WILDCARD_UUID` (a batch belongs to a real tenant, so system attribution would be
  dishonest). `agent_id = "bulk-worker"` names the emitting subsystem (a **new reserved
  slug**, joining `admin-console`/`operator-sso`/`rate-limiter`/`all-agents`). team/project
  are the submitting key's real IDs (known at submit, carried on the job).
- **Per-file security findings are NOT new variants.** They are emitted by the **reused**
  F-005/F-008 path with the existing `pii_blocked` / `injection_detected` / `secret_leaked` /
  `policy_decision_*` variants and the tenant's own four IDs. The five `batch_*` variants are
  **lifecycle / outcome meta-events** layered on top.
- **`ck_eal_action_taken` is unchanged** — all five reuse `logged`/`blocked`, already allowed.

**4-site consistency** (the F-006 anti-pattern guard): the five variants land in lockstep
across `events_audit_log.VALID_EVENT_TYPES`, `ACTION_TAKEN_BY_EVENT_TYPE`, the
`ck_eal_event_type` CHECK (migration `0019`), and `contracts/events.schema.json`
(api-architect).

---

## 9. Decision D8 — Persistence (two reversible migrations)

- **`0018_bulk_state_schema`** (`down_revision="0017"`): create `batches` and `batch_files`.
  Both are **tenant-scoped**: a `tenant_id` column, `ENABLE` + `FORCE ROW LEVEL SECURITY`,
  and `USING` / `WITH CHECK` policies using the **exact F-003b strict predicate**
  `tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')` (no `IS NULL`
  escape). Unique constraint on `(tenant_id, idempotency_key)` for `batches`. Minimal DML
  GRANTs + sequence `USAGE`/`SELECT` to `sentinel_app` (no DDL, no BYPASSRLS), idempotent role
  guards. `down()` drops both tables.
- **`0019_bulk_event_variants`** (`down_revision="0018"`): widen `ck_eal_event_type` via the
  established DROP+ADD helper (the `0008`/`0010`/`0011`/`0012`/`0013`/`0015` pattern) adding
  the five `batch_*` variants; **no new columns** (variants use the four IDs + `action_taken`).
  `down()` narrows `ck_eal_event_type` back to the F-014 (`0015`) set — loss-free (a CHECK only
  widens an allowed set; narrowing removes only the five new values, which no pre-F-015 row
  uses). Round-trip verified at STEP 11: `0017→0018→0019→0018→0017`. Head → **`0019`**.

The split mirrors F-014 (`0014` identity schema, `0015` event variants) and keeps the
api-architect-coupled event-variant change isolated.

---

## 10. Decision D9 — Lean build, KEDA-ready, autoscale deferred (Fork 4)

Affu chose (a). The worker pool is **horizontally scalable** (run N identical Arq workers
against the same consumer group) and **KEDA-ready**: it exposes a **clean queue-depth scaling
signal** (a Prometheus gauge via the F-009 `observability/metrics` registry; Redis Streams
`XLEN`/pending of the batch stream). **No live KEDA `ScaledObject` / HPA is wired** — we do
not build autoscale infra for load that does not exist yet (the F-007 scope-creep
anti-pattern). A sample KEDA `ScaledObject` is documented (commented) in `infra/` as the
deferred upgrade. The roadmap's **5000-files/5-min @ 10–20 workers** target is treated as a
**measured design goal**: STEP 11 ships a load-test harness that reports the **honest measured
files/min at a fixed worker count** — never quoted as a production autoscale guarantee
(CLAUDE.md honest-language rule).

---

## 11. Threat Model — 16 Vectors (CANONICAL; cite these numbers)

Each test **proves the attack fails** — asserting correct behavior **and** the correct
audit/response **and** no cross-tenant/state corruption — not merely "raises". Test files
(`tests/bulk/`):

**Tenant isolation (PRIMARY) — `test_bulk_tenant_isolation_threat_model.py`:**

| # | Vector | Control | Result |
|---|---|---|---|
| 1 | `test_batch_scoped_to_submitting_tenant` | per-job `get_tenant_session` (D1) | worker reads/writes only the submitting tenant's rows; a second-tenant connection sees none |
| 2 | `test_object_key_tenant_namespaced` | tenant-prefixed + unguessable keys (D5) | tenant A cannot read tenant B's object by key guessing |
| 3 | `test_presigned_url_single_object_short_ttl` | single-object presign + TTL (D5) | a presigned URL cannot be reused for another object/tenant and expires |
| 4 | `test_worker_no_blanket_bypassrls` | code/grep + runtime assertion (D1) | no worker processing path opens a blanket BYPASSRLS session |

**Storage surface — `test_bulk_storage_threat_model.py`:**

| # | Vector | Control | Result |
|---|---|---|---|
| 5 | `test_oversized_upload_rejected` | content-length-range + fetch backstop (D5) | an oversize object is rejected |
| 6 | `test_content_type_not_trusted` | byte-level validation (D5) | a spoofed declared content-type does not bypass validation |
| 7 | `test_path_traversal_in_key_rejected` | key validation (D5) | `..` / absolute / encoded keys are rejected |
| 8 | `test_no_ssrf_via_storage_fetch` | no arbitrary-URL fetch path (D5) | an injected host/URL cannot make the worker fetch an internal/metadata endpoint |

**Idempotency + correctness — `test_bulk_idempotency_threat_model.py`:**

| # | Vector | Control | Result |
|---|---|---|---|
| 9 | `test_idempotency_replay_dedupes` | unique idempotency key (D2) | replaying a key returns the same batch; no double-process/emit/bill |
| 10 | `test_checkpoint_resume_skips_completed` | terminal-status checkpoint (D3) | a resumed batch skips completed files |
| 11 | `test_one_bad_file_does_not_fail_batch` | per-file isolation + retry/DLQ (D3) | a bad file is isolated, retried, dead-lettered; the batch completes |

**Security-pipeline reuse — `test_bulk_pipeline_threat_model.py`:**

| # | Vector | Control | Result |
|---|---|---|---|
| 12 | `test_batch_runs_full_detector_pipeline` | reused `run_pre_request` (D4) | each file runs the same F-005+F-008 pipeline; no bypass |
| 13 | `test_policy_violation_in_batch_blocked_and_audited` | reused policy eval (D4) | a policy-violating file is blocked and audited |

**Audit + fairness — `test_bulk_audit_threat_model.py`:**

| # | Vector | Control | Result |
|---|---|---|---|
| 14 | `test_every_file_outcome_audited` | manifest ⇄ log reconciliation (D3) | every file outcome is in the append-only log; the manifest reconciles; no unaudited mutation |
| 15 | `test_dlq_entries_audited` | `batch_file_dead_lettered` emit (D3) | every dead-letter is audited; no silent drop |
| 16 | `test_per_tenant_batch_limit_enforced` | Redis per-tenant caps (D7) | one tenant cannot starve others; the cap is enforced |

**Test isolation strategy.** Following F-012a §11.1 / F-014: cross-tenant proofs (1, 2, 4)
**commit real rows for two tenants across a second real `sentinel_app` RLS connection** and
assert zero cross-tenant visibility — empirical, because cross-tenant leakage is F-015's
highest-severity threat. They use a scoped, non-autouse truncate teardown. `tests/bulk/`
ships a **self-provisioning conftest** (it runs before `tests/persistence/` alphabetically,
so it must `alembic upgrade head` + SCRAM-provision `sentinel_app` itself, and
**skip-not-fail** when no DB — the F-011/F-012a/F-014 CI lesson).

---

## 12. Alternatives Considered & Honest Deferrals

- **(Fork 1 b) Privileged worker + code-level scoping — REJECTED.** The F-003b Option γ "RLS
  decorative" failure mode in async form; isolation would depend on worker-code discipline
  across thousands of per-file queries.
- **(Fork 2 b) Exactly-once delivery — REJECTED.** Harder and usually illusory across
  queue + storage + DB; no real gain over at-least-once + dedup.
- **(Fork 3 b) AWS S3 wired first — REJECTED.** Ties dev/CI to AWS; weakens self-host/offline.
  S3 remains selectable behind the interface.
- **(Fork 4 b) Full KEDA now — DEFERRED.** Autoscale infra for absent load is scope creep;
  KEDA-ready pool + documented `ScaledObject` is the clean future upgrade.
- **(Fork 5 b) Operator/admin-API submission — REJECTED.** Wrong principal for a tenant
  self-service op.
- **Out of scope (v1):** live KEDA autoscaling · a second storage backend wired · streaming /
  real-time processing (batch only) · any new detector logic · a production throughput
  guarantee (the 5000/5min number is a measured design goal). "audit-ready", never "compliant".

---

## 13. Contract Changes & Consequences

### 13.1 Contract changes (api-architect, STEP 8)
- **`contracts/openapi.yaml`:** add `/v1/batches` (submit, list), `/v1/batches/{batch_id}`
  (status), `/v1/batches/{batch_id}/files` (manifest), and the upload-URL mint endpoint, all
  under the existing tenant Bearer scheme. No existing path changes.
- **`contracts/events.schema.json`:** add five closed, fully-bounded variants to `oneOf`
  (the five `batch_*` types), each with the four stable IDs + `event_id`/`event_timestamp`/
  `request_id` + the listed `action_taken`. No existing variant changes.
- **`contracts/ids.md`:** add the `bulk-worker` reserved `agent_id` slug (the async worker
  principal; carried on every `batch_*` event; `tenant_id` is always the real submitting
  tenant, never `WILDCARD_UUID`).

> **Process note (mirrors ADR-0014 §13.1):** `contracts/` edits are gated by the protect-paths
> hook authorizing only the `api-architect` identity. STEP 8 dispatches that agent; if its
> identity is not provisioned, the patch is recorded for verbatim re-apply under that identity.
> The protection logic is never weakened.

### 13.2 Positive consequences
- A throughput lane that runs the **full** security pipeline per file — batch is not a fast
  lane around the detectors.
- Tenant isolation enforced at the DB floor for the new async principal (no new bypass).
- Honest, complete audit of every file outcome; the manifest reconciles with the log; DLQ
  entries are audited.
- Reuses every existing engine (RLS, detectors, policy, Redis, audit writer); the only new
  primitives are storage + queue + worker + state tables + 5 variants + the `bulk-worker` slug.

### 13.3 Honest scope / known limitations (v1)
**Worker-pool realization (honest note):** the dispatch named "Arq worker pool"; the
pool is realized as a **Redis Streams consumer group** (XREADGROUP + XACK + XAUTOCLAIM
reclaim) rather than arq's native list broker, because consumer groups provide the
at-least-once delivery + per-consumer pending + crash-reclaim that the DLQ / bounded-retry
/ checkpoint semantics (R5/R7) require, and item 4 mandates Redis Streams. The `arq`
dependency remains available; horizontal scale = run N identical consumer processes; KEDA
scales on `queue.queue_depth()` (D9). This is within the approved Streams-based,
KEDA-ready, autoscale-deferred envelope.

**NO** live KEDA autoscaling (KEDA-ready pool only) · **ONE** storage backend wired (S3 behind
the interface) · the **5000/5min** target is a **measured design goal**, not a production
guarantee · delivery is **at-least-once + dedup** (not exactly-once) · **NO** new detector
logic (reuse F-005) · **NO** streaming/real-time (batch only) · the privileged session is used
**only** for the global hash-chain append, never for tenant batch data.

### 13.4 Rollback
- **Whole feature:** revert `task/F-015-bulk-pipeline-native`. F-015 is purely additive (new
  `src/bulk/` package + `/v1/batches*` routes + `batches`/`batch_files` tables + 5 event
  variants + the `bulk-worker` slug + a MinIO compose service + the `[bulk]` extra + two
  reversible migrations). Reverting restores the pre-F-015 state exactly; nothing in
  F-003/F-003b/F-005/F-008/F-009/F-010 is modified.
- **Migrations:** `0019` downgrades by narrowing `ck_eal_event_type` to the F-014 set; `0018`
  downgrades by dropping the two tables. No pre-existing row violates either downgrade.
  Verified at STEP 11.
