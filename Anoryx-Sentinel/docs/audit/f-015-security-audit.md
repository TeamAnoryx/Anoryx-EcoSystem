# F-015 Bulk Processing Pipeline — Security Audit

- **Feature:** F-015 (async bulk processing pipeline) — ADR-0018
- **Branch:** `task/F-015-bulk-pipeline-native`
- **Auditor:** security-auditor (independent red-team, Opus), STEP-10 gate
- **Date:** 2026-06-22
- **Initial verdict:** **BLOCK** — 1 High, 2 Low
- **Post-remediation status:** High **FIXED + test-covered**; both Low **addressed**. Awaiting Affu APPROVED.

---

## Heavy-focus areas verified CLEAN

- **Cross-tenant DB-state isolation (PRIMARY):** worker uses `get_tenant_session(job.tenant_id)` for every state read/write + the F-008 policy read; `get_privileged_session()` is used exactly once (the hash-chain audit append), enforced by a static test. Migration `0018` applies `ENABLE`+`FORCE` RLS with the strict `NULLIF` predicate + `WITH CHECK` on `batches` and `batch_files`; `sentinel_app` is NOBYPASSRLS; scoped GRANT, no DELETE. `tenant_id` is server-resolved (`resolve_tenant_context`), never from headers, carried on the job.
- **Idempotency:** UNIQUE(tenant_id, idempotency_key); replay returns the existing batch without re-reserving/re-enqueuing; terminal-status checkpoint skips processed files.
- **Detector/policy no-fast-lane:** every file runs the reused F-005 chain; `HookFailSafeError` propagates → retry/DLQ (never a silent pass); F-008 model-deny enforced + audited.
- **Audit/attribution + DLQ:** `tenant_id` is the real submitting tenant (never WILDCARD); slug `bulk-worker`; DLQ is an audited status (no silent drop); failure records carry only a bounded class.
- **SSRF / presign / traversal:** single bound storage endpoint, key-only addressing, strict anchored key regex, presigned POST pins key + content-length-range + TTL, declared content-type untrusted.
- **Secret/PII leakage:** storage creds env-only; exception messages carry only `type(exc).__name__` / bounded constants; object keys/bytes never logged; `decode_text` never echoes bytes.

---

## Findings

### HIGH-1 — Worker trusted the queue-supplied object_key (cross-tenant object read) — FIXED

**File:** `src/bulk/worker.py` (fetch path). **Attack:** the Redis jobs stream is a trust boundary distinct from the authenticated submit path, and object storage has **no RLS** — the tenant↔object binding is the key-prefix convention, enforced only at submit (`routes.py`). A forged/replayed job pairing `tenant_id=A` + `file_id=<A's queued file>` + `object_key=<B's key>` would pass `from_fields` (valid shapes) and `validate_object_key` (shape-only), so the worker — operating its DB state correctly under A's RLS — would `storage.fetch(B's key)` and run **tenant B's bytes** through detectors under A's scope. Reachable via the shipped passwordless host-exposed Redis, or a producer bug / stream replay.

**Fix (committed):** the worker now fetches **`bf.object_key`** — the object key loaded from the RLS-protected `batch_files` row under `get_tenant_session(A)` — never `job.object_key`. It additionally fails **closed** (dead-letter, no retry, `failure_class="key_tenant_mismatch"`) when `job.object_key != bf.object_key` or the key's prefix ≠ the job tenant, so a forged key is never a fetch target. RLS guarantees `bf.object_key` is the submitting tenant's. **Covered by** `tests/bulk/test_bulk_worker_threat_model.py::test_forged_object_key_dead_lettered_not_fetched` (forged B-key → dead-lettered, B's object never fetched).

### LOW-1 — Per-tenant limit counters did not refresh TTL on release — ADDRESSED

**File:** `src/bulk/limits.py`. A batch in-flight > 24h could let the counter expire and under-count, mildly weakening the cap. **Fix:** `_decr_floor` now refreshes the counter TTL atomically inside the Lua script on every release.

### LOW-2 — Semgrep `avoid-sqlalchemy-text` on migration 0018 (benign) — NO CODE CHANGE

**File:** `src/persistence/migrations/versions/0018_bulk_state_schema.py`. The 8 hits are f-string `text()` in the RLS/GRANT helper — all interpolated values are hardcoded module constants (table names, the fixed NULLIF predicate); zero request-time input. This is the verbatim 0006/0007 RLS pattern. `try_complete_batch` uses a bound `:bid` parameter. No injection; reported for completeness so the BLOCK is not mistaken as deriving from these.

---

## Code-review (STEP 9) findings also remediated

HIGH (completion race → double `batch_completed`) fixed via an atomic `try_complete_batch` (`UPDATE … WHERE status<>'completed' AND NOT EXISTS(non-terminal) RETURNING`); HIGH (reserve fail-open breadth) narrowed to Redis connection/timeout only; HIGH (unbounded `object_keys`) given a structural `max_length`; MED (`from_fields` ID validation + poison-message discard), MED (atomic `_decr_floor`), MED (no interpolated values in exception messages), LOW (`isinstance` for `HookFailSafeError`) all fixed.

## Honest residual scope (non-blocking)

- No HTTP route-level test layer for `/v1/batches*` (the data-plane handlers are thin; security-critical logic is covered at the repo/worker level). Documented follow-up.
- Worker-pool realized as a Redis Streams consumer group (not arq's native broker) — see ADR-0018 §13.3.
- KEDA autoscaling deferred (KEDA-ready signal only); one storage backend wired; throughput is a measured design goal.

## Verdict

Initial **BLOCK** (1 High). The High is **fixed and test-covered**; both Lows addressed. Re-audit of the diff confirms no remaining High/Critical. **Pending Affu APPROVED** at the STEP-10 gate before STEP 11 (empirical verification + load test) and STEP 12 (PR).
