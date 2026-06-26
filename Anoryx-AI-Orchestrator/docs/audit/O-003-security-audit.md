# O-003 Event Ingest Pipeline — Independent Security Audit

|  |  |
|---|---|
| **Date** | 2026-06-27 |
| **Auditor** | Independent / arms-length red-team (did NOT author this code) |
| **Subject** | O-003 Orchestrator event-ingest pipeline |
| **Branch / PR** | `task/O-003-ingest` / PR #37 |
| **Final commit audited** | `5deffe2` (findings raised against `9536b2b`/`0ce7171`, re-verified through `5deffe2`) |
| **Tooling** | Semgrep 1.166 (`p/python`, `p/security-audit`, `p/secrets`); manual review; **live re-run of the non-stubbed e2e on a fresh `postgres:16-alpine`** + targeted adversarial probes |

## E2E re-run (fresh DB) — performed by the auditor

The auditor stood up its **own** fresh `postgres:16-alpine` (independent of the implementer's) and ran the real path (HMAC receiver → pipeline → DB) with nothing stubbed: **76 passed, 2 skipped** (the 2 skips are the win32-only direct-`get_tenant_session` / direct-`process_envelope` variants, which have Windows-robust equivalents that ran). Tamper-evidence, dedup, all five reject-to-DLQ reasons, idempotency-conflict, live RLS isolation, and the migration round-trip all passed against a real database.

**CI authority of record:** PR #37 — both lanes green on a fresh Linux Postgres; the `orchestrator-integration` lane reports `78 passed` (executed, not skipped). Local-green and CI-green agree.

## Threat-model vectors

| # | Vector | Verdict |
|---|--------|---------|
| 1 | Forged event / HMAC bypass | **Defended** — raw body read pre-parse; recompute over `f"{ts}.".encode()+raw_body`; `hmac.compare_digest`; ±300s window; missing/empty/malformed sig → 401; secret env-only, never logged. |
| 2 | Replay → suppression / duplicate | **Defended** — ±300s window + persistent UNIQUE `idempotency_key`; `idempotency_key==payload.event_id` enforced; same-key/different-content → `idempotency_conflict` DLQ (proven live), not a silent drop. |
| 3 | Cross-tenant read/write | **Defended** — RLS ENABLE+FORCE, NOBYPASSRLS app role, strict `NULLIF` fail-closed predicate, `WITH CHECK` on writes; tenant bound (not interpolated) into a `SET LOCAL` GUC; NULL-tenant DLQ rows RLS-invisible; live isolation proven. |
| 4 | DLQ poisoning | **Defended** — `attempt_count` CHECK 0..1000; `max_attempts_exceeded` terminal; rows closed/bounded; all DLQ writes post-HMAC. |
| 5 | Version-downgrade DoS | **Defended** — version allow-list `{1}` is the FIRST pipeline step; unknown → `unknown_schema_version` DLQ; no best-effort parse. |
| 6 | Audit tampering | **Defended** — append-only BEFORE UPDATE/DELETE deny-triggers + RLS `USING(false)`; SHA-256 chain, domain-separated genesis, `prev_hash`+`event_timestamp` always hashed, opt-in-when-present `dlq_reason`/`dlq_id`; `validate_chain` detects a real DB mutation (proven live). |
| — | SQLi / command injection | **Clean** — all request-data values are bound params or SQLAlchemy core `insert().values`; the migration `text()` interpolates only module constants (table/role names), never request data. |
| — | Double-begin fail-open (ADR-0026) | **Clean** — `get_tenant_session` autobegins and is never wrapped in `session.begin()`; privileged sessions use `begin()`; the only caught pipeline exception is `IntegrityError`; logic/connectivity errors propagate to a fail-safe 503 BLOCK. |
| — | Secrets in code/logs/CI | **Clean** — HMAC secret env-only, fail-loud, never logged; no logging/print in the request path; CI uses labelled ephemeral DB creds and the HMAC secret is not in CI (monkeypatched per test). |
| — | SSRF / path traversal / deserialization / prompt-injection | **Clean / N/A** — no outbound calls (forward is intent-only); schema paths from `__file__` constants; `json.loads` only; O-003 makes no LLM calls. |

## Findings (raised and remediated during the audit)

All findings were raised over the audit rounds and **remediated + independently re-verified on a fresh DB**. 0 Critical, 0 High.

| ID | Sev | Issue | Resolution (verified) |
|---|---|---|---|
| **M-1** | Med | An over-length payload-derived field (best-effort projection) overflowed `varchar(64)` → `DataError` (not `IntegrityError`) → propagated → **503**, leaving the event neither accepted nor dead-lettered (un-DLQ'able poison + retry storm). | `_extract_common` now nulls a value unless it is a `str` AND `len ≤ 64`. Over-length → NULL → clean DLQ. e2e added. **Closed.** |
| **M-2** | Med | The same 503 class via a NUL (`\x00`): Postgres `text`/JSONB categorically reject `\x00`, so a NUL-bearing payload string could be neither persisted nor stored in the DLQ's `original_envelope` JSONB — guarding the projection alone still 503'd on the JSONB insert. | A recursive `_contains_nul` scan in `router.py` runs after structural validation and **before any DB access**; a NUL anywhere in the envelope → **422** (malformed transport input — a terminal client disposition that does not retry-loop). `\x00` is the only char `text`/JSONB reject (verified `\x01` stores → DLQ). `_extract_common` keeps a NUL guard as defence-in-depth. no-DB test added. **Closed.** |
| **L-1** | Low | A non-ASCII signature hex reached `hmac.compare_digest` → `TypeError` → **503** instead of a clean **401** (an unauthenticated caller could select the 5xx path). | `hmac_verify.py` rejects `provided_hex` as `UNAUTHENTICATED("signature_malformed")` unless it is exactly 64 hex chars, before the compare. Unit tests (non-hex + non-ASCII). **Closed.** |
| **L-2** | Low | `validate_chain` read the global chain with no tenant GUC; under a non-BYPASSRLS role the RLS predicate hides every row → the loop vacuously returns **`True`** ("integrity verified" over an invisible chain). | `validate_chain` now asserts the session has `rolbypassrls`/`rolsuper` and **raises** otherwise. Verified both directions (superuser → `True`; app role → `RuntimeError`). **Closed.** |
| **L-3** | Low | The fail-safe 503 handler reflected an unvalidated client `X-Request-Id` into the response. | The handler now server-generates `"req-orch-"+uuid`; the client header is never reflected. **Closed.** |

## Informational (not blocking — out of O-003 finding scope)

- A deeply-nested **signed** body can raise `RecursionError` → 503 at `json.loads` (HMAC-gated, post-auth, fail-closed). Pre-existing; the recursive NUL scan does not materially widen it. A body-size / nesting-depth bound is reasonable hardening for a later deploy task (O-006/O-008), not a defect in this change.
- `validate_chain` is O(n) memory (documented in ADR-0003 residuals); a streaming cursor is the O-006 fix.
- The L-1 hex gate accepts uppercase hex while the signer emits lowercase; an uppercase signature would 403 (fail-closed), not 401 — cosmetic, not a vulnerability.

## Verdict

**CLEAN.** No High or Critical findings. All five findings (M-1, M-2, L-1, L-2, L-3) are remediated and independently re-verified on a fresh database. The core controls — HMAC verify, two-role FORCE-RLS tenant isolation, version-gate-first reject-to-DLQ, append-only hash-chain tamper-evidence, and the ADR-0026 no-fail-open discipline — hold and were proven live. This audit does not pronounce the seam "secure"; it confirms the audited defect classes are closed for the O-003 scope.
