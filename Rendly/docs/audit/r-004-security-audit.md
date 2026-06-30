# R-004 Security Audit — Rendly Persistence + Tenant Isolation

- Task: R-004 (Rendly's first DB persistence layer; identity + refresh-token families)
- Date: 2026-06-30
- Auditor: independent security red-team (rule 3 — not the code author), probing a live Postgres
- Scope: `Rendly/src/rendly/persistence/**`, migration `0001_identity_schema.py`, the R-003 auth
  seams it backs (`auth/{store,refresh,service,passwords,app}.py`), `docker-entrypoint.sh`,
  `docker-compose.yml`, `Dockerfile`, `.github/workflows/rendly-ci.yml`, `tests/persistence/**`.

## Verdict: **CLEAN** (no High/Critical)

The tenant-isolation spine — the load-bearing property of a data-sovereignty product — held under
every direct adversarial probe run as the `rendly_app` (NOBYPASSRLS) role. No cross-tenant read,
write, insert, tenant-move, GUC bypass, privilege escalation, DDL tamper, or trigger bypass
succeeded. Five Low/Info defense-in-depth and operational notes were raised; none gate the merge.

## Evidence (quoted probe output, run as `rendly_app`)
- GUC = tenant A: `SELECT * users` → only A's row; explicit `WHERE user_id=<B>` → `[]`;
  `UPDATE families WHERE tenant_id=<B>` → `rowcount=0`;
  `INSERT users (tenant_id=B)` → `InsufficientPrivilege: new row violates row-level security policy`.
- GUC unset / `''` / `'   '` / nonexistent tenant → `users visible = 0`; correct tenant → `1`
  (fail-closed, never widening).
- Tenant-move `UPDATE families SET tenant_id=B` (GUC=A) → blocked by `WITH CHECK`.
- DDL as `rendly_app` (`DISABLE/NO FORCE RLS`, `DROP/CREATE POLICY`, `DROP/DELETE/TRUNCATE TABLE`,
  `ALTER ROLE … BYPASSRLS`, `SET ROLE rendly`, `SET SESSION AUTHORIZATION`, `SELECT pg_authid`,
  `SET session_replication_role='replica'`) → all `InsufficientPrivilege`.
- Append-only triggers: `UPDATE … used=false` / `revoked=false` → `RaiseException: append-only:
  cannot revert TRUE->FALSE`.
- Pool reuse: after a tenant session closes, the same pooled connection reports
  `current_setting('app.current_tenant_id', true) = ''` and `users seen: 0` — the transaction-local
  GUC does not leak.
- `relforcerowsecurity = true` on all 5 tenant tables; `rendly_app` =
  NOSUPERUSER/NOBYPASSRLS/NOCREATEDB/NOCREATEROLE; grants exactly SELECT/INSERT on identity tables
  (+UPDATE on the two refresh tables), no DELETE/TRUNCATE/ALL.
- Refresh: SHA-256-at-rest, `SELECT … FOR UPDATE`-serialized rotation (concurrency test: loser →
  `RefreshReuse`), family-burn-on-reuse, expired/revoked-family → `RefreshInvalid` (generic 401).
- Semgrep (`p/python`, `p/security-audit`, `p/secrets`, `--severity=ERROR`) over the persistence +
  auth source + entrypoint: **0 results**.

## Findings & disposition (none gating)

| # | Sev | Location | Issue | Disposition |
|---|-----|----------|-------|-------------|
| 1 | Low | `persistence/database.py:160` | Runtime privileged path connects via `DATABASE_URL` whose bundled compose/CI owner `rendly` is SUPERUSER; the runtime only needs BYPASSRLS (superuser is needed only for migration/DDL). Not exploitable today (all privileged statements are parameterized PK lookups — no SQLi). Blast-radius note. | **ACCEPTED / deferred to deploy hardening (R-010).** In production, split a BYPASSRLS-NOSUPERUSER table-read login for `get_credentials`/`_discover_tenant` from the superuser migration owner; reserve the superuser DSN for Alembic only. Recorded so prod deploy does not reuse a superuser owner for request-serving. |
| 2 | Low | `auth/service.py:80` | Credential/rotate paths are asymmetric by DB-query count (unknown user 1 query + decoy Argon2; known user 3 queries + verify). Not a practical enumeration oracle: the ~50–100ms Argon2id verify is equalized on both branches and dominates the sub-ms PK-lookup delta; rotate's "known" branch requires possessing an unforgeable 256-bit `rt_` token. | **ACCEPTED (non-exploitable).** Optional future hardening: fetch credential+user+profile in one query so DB-touch count is branch-identical. No change required. |
| 3 | Info | `Dockerfile:18` | Image bakes `RUN_MIGRATIONS=1` + `RENDLY_PROVISION_APP_ROLE=1`, so the one-shot image auto-migrates/provisions against any reachable `DATABASE_URL`. No data exposure (verifier is client-side SCRAM via `sql.Literal`, plaintext never a SQL literal/log); a wrong password only breaks `rendly_app` login = fail-closed availability. Operational risk: wrong-cluster auto-migrate. | **ACCEPTED (documented F-010 one-shot runner).** Operators inject the intended secret + scope `DATABASE_URL`. Future: default the ENV flags to 0 and enable explicitly in the compose/k8s Job. |
| 4 | Info | `persistence/database.py:198` | `get_tenant_session` validates `tenant_id.strip()` non-empty but passes the UNSTRIPPED value to `set_config`, so a whitespace-padded id would set a padded GUC. Not reachable: every `tenant_id` originates from the `^UUID$`-anchored claim (hex+dashes, no whitespace) or a DB row derived from it; a padded GUC matches only its own exact-string row and otherwise collapses to zero rows (fail-closed). | **ACCEPTED (unreachable).** Optional defensive: pass `tenant_id.strip()` (or reject `tenant_id != tenant_id.strip()`) so stored value and GUC are byte-identical. |
| 5 | Info | `migrations/0001:72` | `FORCE ROW LEVEL SECURITY` is set on all 5 tenant tables, but the owner `rendly` has BYPASSRLS so FORCE does not constrain the owner — the privileged/login path intentionally bypasses RLS. | **ACCEPTED (by design).** The isolation boundary is the NOBYPASSRLS `rendly_app` role (proven above). FORCE is correct defense-in-depth should `rendly_app` ever own an object (it never does). |

## Conclusion
Merge is **not gated**. Items #1 and #3 are deployment-configuration hardening for the R-010 deploy
task (production must not run the request path as a superuser, and the one-shot image's auto-migrate
flags should be opt-in per environment). Items #2, #4, #5 are accepted as non-exploitable /
by-design. The cross-tenant isolation spine, refresh-token reuse-detection, append-only guards,
secret handling, and fail-closed behavior all verified under live adversarial probing.
