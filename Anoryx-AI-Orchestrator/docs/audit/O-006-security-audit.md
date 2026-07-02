# O-006 Security Audit — Orchestrator Persistence Consolidation + Tenant-Scoped Read Seams

- Task: O-006
- Date: 2026-07-02
- Auditor: independent security-auditor (arms-length; did not write the code)
- Scope: the two cross-tenant READ holes O-006 closes (O-004 coarse GET distribution-status
  + inbound `tenant_id`; O-002 coarse DLQ-metadata read), the new per-tenant principal
  (`query_service_tokens`), RLS across tenant-scoped tables, and the query/bus read seams.
- Method: the auditor stood up its **own fresh Postgres 16** and re-ran the cross-tenant
  isolation e2e itself, plus independent psql/asyncpg/httpx probes and a Semgrep pass.

> Provenance note: the security-auditor operates under a harness directive that returns its
> report inline rather than writing a file. This document persists that returned report
> verbatim (deliverable #8 / acceptance #10). No source-tree files were mutated by the
> auditor; only an isolated `alembic downgrade/upgrade` was run against its throwaway DB,
> which was removed afterwards.

## Verdict: **CLEAN** (no High or Critical)

The load-bearing property — **tenant A cannot read tenant B** — holds and is enforced
structurally at the database (Postgres RLS on the NOBYPASSRLS `orchestrator_app` role),
not by application-layer filtering. The two O-004 read/write holes and the O-002 DLQ-read
prose deferral are closed and proven non-stubbed on a fresh DB.

## Environment (auditor's own fresh DB)

`docker run -d --name orch-audit-o006-pg -e POSTGRES_USER=orchestrator -e
POSTGRES_PASSWORD=orchestrator_ci_only -e POSTGRES_DB=orchestrator_ci -p 55444:5432
postgres:16-alpine` → PostgreSQL 16.14. Env mirrored from `orchestrator-ci.yml`:
`ORCH_DATABASE_URL` (owner `orchestrator`, BYPASSRLS), `ORCH_APP_DATABASE_URL` (role
`orchestrator_app`, NOBYPASSRLS), `ORCH_DB_SSL=disable`, `ORCH_PROVISION_APP_ROLE=1`,
`ORCH_REQUIRE_AUTHZ_E2E=1`, `PYTHONPATH=src`. Single alembic head confirmed:
`0005_tenant_principal_and_reads`. Container removed after the audit.

## The gate — cross-tenant e2e re-run on the auditor's own fresh DB (executed, not skipped)

`pytest tests/integration/test_authz_reads_e2e.py tests/integration/test_migration_roundtrip.py`
→ `6 passed, 1 skipped in 20.33s`.
- PASSED: `test_distribution_status_is_tenant_scoped` (A→200, B→404),
  `test_dlq_read_is_tenant_scoped`,
  `test_events_read_is_tenant_scoped_and_filter_rejects_cross_tenant` (`FilterTenantId=B`→403),
  `test_distribution_post_body_tenant_mismatch_is_403`,
  `test_direct_db_rls_blocks_cross_tenant`, `test_migration_round_trip`.
- The 1 skip is `test_rls_isolation_via_get_tenant_session` — the intentional `skipif win32`
  Linux-only runtime variant; its Windows-robust equivalent
  (`test_direct_db_rls_blocks_cross_tenant`, same NOBYPASSRLS role + RLS) executed and passed.
- `authz_ready` under `ORCH_REQUIRE_AUTHZ_E2E=1` would have failed the run had the DB been
  unreachable, so the cross-tenant assertions provably ran.
- Unit lane: `tests/unit/test_security.py test_query_router.py test_distribution_router.py`
  → `38 passed`.

## Independent probes (auditor's own psql / asyncpg / httpx — not the shipped tests)

1. **RLS is structural** (raw `orchestrator_app`, NOBYPASSRLS): GUC→B reading A's
   `ingest_events` / `dead_letter_queue` / `policy_distributions` → 0/0/0; GUC→A → 1/1/1
   with the NULL-tenant DLQ orphan invisible even to A; GUC→`''` → 0/0/0 (fail-closed
   NULLIF); `SET row_security=off` → `ERROR: query would be affected by row-level security
   policy` (a NOBYPASSRLS role cannot widen). **PASS.**
2. **Token trust root** (httpx against the real app): missing / malformed / empty / bogus /
   disabled tokens ALL → identical `(401,"unauthorized","tenant authentication required")`
   → no enumeration oracle; valid → 200. Plaintext token never in body/headers; only
   SHA-256 stored. **PASS.**
3. **Metadata-only**: 200 body contained no `payload`, no `original_envelope`, no policy
   body. Projections are constant allow-lists. **PASS.**
4. **Existence oracle**: cross-tenant GET distribution → 404 (identical to not-found).
   **PASS.**
5. **tenant_id spoof**: A-token + body `policy.tenant_id=B` → 403 before any persist.
   **PASS.**
6. **Hash-chain continuity**: seeded live ingest+distribution audit rows, validated all
   three chains True, ran `alembic downgrade 0004` then `upgrade head`, re-validated →
   ingest/distribution/registry all still True; `validate_*` fail-loud under BYPASSRLS
   confirmed. **PASS.**
7. **Auth bootstrap**: `resolve_principal_tenant` runs on the privileged session, sets no
   tenant GUC, reads only `query_service_tokens`; the data read then runs under
   `get_tenant_session(principal)`. The app role is additionally denied SELECT on
   `query_service_tokens` (`ERROR: permission denied`), so the bootstrap cannot become a
   cross-tenant data read. **PASS.**
8. **Ingest trusted-relay honesty text** present verbatim in ADR-0006 (§Honesty boundaries
   + §Residual risk). Confirmed — documented boundary, not a finding.

## Semgrep

`semgrep --config=p/python --config=p/security-audit --config=p/secrets --severity=ERROR`
over the changed files → 101 rules, 2 findings, both `avoid-sqlalchemy-text`
(`repositories.py` `list_events` / `list_dead_letters`), **both false positives**
(parameterized; only constant column/predicate fragments interpolated; every user-supplied
value is a bound parameter). No secrets flagged.

## Findings (all Low — non-blocking)

| # | Severity | Location | Issue | Disposition |
|---|----------|----------|-------|-------------|
| L-1 | Low | `query/router.py` cursor decode | A cursor that base64/JSON-decodes to a non-dict (`[1,2]`,`5`), a dlq cursor with a bad `c` timestamp, or an events cursor exceeding BIGINT range raised `TypeError`/DB `DataError` → 503 instead of the contract's 422. No cross-tenant read, no leak (cursor is the caller's own input; RLS still scopes; 503 body is generic). | **Fixed post-audit**: decoders validate type/shape/range and map all malformed cursors to 422; contract updated to document 422 on both read seams; unit tests added. |
| L-2 | Low | `repositories.py:749,805` | Semgrep `avoid-sqlalchemy-text` false positive (constant column tuples only; all values bound). | **Fixed post-audit**: scoped `# nosemgrep` + justification added. |
| L-3 | Low | `security.py` token storage | Per-tenant tokens stored as unsalted SHA-256. Acceptable for high-entropy operator-issued secrets; the app role is denied SELECT on `query_service_tokens`, so hashes are unreadable via the app. | **Accepted / documented**: ADR-0006 notes the high-entropy expectation; a minimum-entropy issuance policy / HMAC-pepper is deferred to the (out-of-scope) token-issuance admin API. |

## Bottom line

BLOCK criteria not met — **no High/Critical**. Tenant isolation is enforced by Postgres RLS
on the NOBYPASSRLS role, proven non-stubbed on a fresh DB by re-running the cross-tenant
e2e and by independent direct-DB probes. The three Low items are conformance/robustness
(L-1, L-2) and an informational hardening note (L-3); L-1/L-2 fixed post-audit, L-3
documented and deferred. **CLEAN.**
