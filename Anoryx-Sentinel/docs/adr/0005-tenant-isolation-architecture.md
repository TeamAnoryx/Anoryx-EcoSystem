# ADR-0005: Runtime Tenant Isolation Architecture (F-003b)

**Status:** Proposed
**Date:** 2026-06-16
**Deciders:** Sentinel engineering team
**Tags:** security, multi-tenancy, rls, postgres, audit, hash-chain
**Supersedes (in part):** ADR-0004 deferral statements on tenant isolation
**Blocks:** F-004 (MUST merge before F-004 begins)

---

## Context

ADR-0004 (F-003) shipped the persistence schema and repository layer with an
explicit, documented gap: **runtime tenant isolation is not enforced**. F-003
delivered tables, triggers, append-only enforcement, the hash-chained audit log,
and a single `get_async_session()` factory that wires **no** GUC and performs
**no** role switching. The Row-Level Security (RLS) policies present in the schema
are, in F-003, decorative: the application connects as a role that is effectively
the table owner (BYPASSRLS semantics), so RLS never engages.

F-003b closes that gap. This ADR decides **how** runtime tenant isolation is
architected. It is an architecture decision record only — it does not implement
migrations or application code. The migration and code land in the F-003b
implementation task, conforming to the decisions recorded here.

### Recon facts this decision is built on (corrected from the original brief)

- **Tables WITH RLS already** (migrations 0002 / 0005): `teams`, `projects`,
  `users`, `role_assignments`, `events_audit_log`. Their policies use the pattern
  `USING (tenant_id = current_setting('app.current_tenant_id', true) OR current_setting(...) IS NULL)`
  with matching `WITH CHECK`.
- **Tenant-scoped tables WITHOUT any RLS** (F-003b must add RLS): exactly **three** —
  `virtual_api_keys`, `policies`, `policy_versions`.
- **`tenants` and `agents` have no `tenant_id` column.** They are the root / global
  registry and are intentionally **not** tenant-scoped. They need no tenant RLS.
  (The original brief's "5 unprotected tables" double-counted these two; the correct
  count of tenant tables needing **new** RLS is **3**.)
- **Current `database.py`:** async engine via `create_async_engine(DATABASE_URL → asyncpg)`,
  `pool_size=5`, `max_overflow=10`, a single `get_async_session()` asynccontextmanager.
  No role switching, no GUC injection. `DATABASE_URL` loaded from env via python-dotenv;
  `RuntimeError` if unset.
- **Two known defects** F-003b must repair (see Threat Model and the GUC Defect
  section below):
  1. The `OR current_setting('app.current_tenant_id', true) IS NULL` branch never
     fires as intended — Postgres `current_setting(name, true)` returns `''`
     (empty string) when the GUC is unset, **not** `NULL`. So the bypass branch is
     dead, and an unset GUC produces `''`, which matches no `tenant_id` and
     silently returns **zero rows** instead of failing loudly.
  2. The app connects as an owner/BYPASSRLS-equivalent role, so RLS is decorative.
- **Hash chain is global.** `audit_log_repository._get_tip_hash()` and
  `validate_chain()` read the chain across **all** tenants (`ORDER BY sequence_number`),
  and `append()` takes `pg_advisory_xact_lock`. If chain reads run under a
  tenant-scoped RLS session, the read is truncated to one tenant's rows and the
  chain appears forked / corrupt. Chain ops therefore require a privileged session
  that can see all rows.

---

## Decision

**Adopt Option α: two physically separate engines, each bound to a distinct
Postgres role.**

1. **`APP_DATABASE_URL`** — logs in with a dedicated **`sentinel_app`** login role
   (`NOSUPERUSER`, `NOBYPASSRLS`, `NOCREATEDB`, `NOCREATEROLE`). This URL backs the
   **tenant-scoped engine**. Every checkout opens a transaction that calls
   `set_config('app.current_tenant_id', :tid, true)` (transaction-local) before any
   tenant query. RLS is the enforcement boundary on this engine.

2. **`DATABASE_URL`** — the existing URL, logs in with the **privileged** role
   (owner / BYPASSRLS-capable). This URL backs the **privileged engine**, used only
   for: hash-chain ops (`append`, `_get_tip_hash`, `validate_chain`), Alembic
   migrations, and explicit administrative maintenance. It is **never** used to serve
   ordinary tenant request traffic.

`database.py` exposes two factories:

- `get_tenant_session(tenant_id: str)` — tenant-scoped engine; sets the GUC; fails
  closed if `tenant_id` is missing/empty (see GUC Defect section).
- `get_privileged_session()` — privileged engine; no GUC; used by the audit-log
  repository's chain methods and by admin tooling.

The application's hot path (auth resolution, policy reads, tenant data reads/writes)
runs exclusively through `get_tenant_session`. The audit-log `append()` path uses
`get_privileged_session` for the chain critical section.

### Why α over β and γ

We considered three options:

- **Option α** — separate `APP_DATABASE_URL` (non-BYPASSRLS `sentinel_app` login) +
  `DATABASE_URL` for admin/migrations/chain. **CHOSEN.**
- **Option β** — single `DATABASE_URL`, `SET ROLE sentinel_app` on connection
  checkout; admin/chain ops use `RESET ROLE` / `SET ROLE NONE`.
- **Option γ** — session GUC + RLS, **no role separation** (the app keeps connecting
  as owner). **REJECTED** — this is exactly what F-003 attempted; the security
  review already flagged it: the app runs as owner, so RLS is decorative and
  provides no isolation. γ is a non-starter for a security product.

**α vs β** is the real trade-off. Both can be made correct; we choose α for the
following reasons:

- **Connection-pool role staleness (the deciding factor).** β relies on
  `SET ROLE` / `RESET ROLE` being applied correctly on **every** checkout of a
  **shared, pooled** connection. A connection returned to the pool while still
  `SET ROLE sentinel_app` — or returned to the pool while still `RESET` to the
  privileged role — is a latent privilege bug: the next borrower inherits the wrong
  role. Getting this right requires a flawless reset hook on **both** checkout and
  check-in, for both the tenant path and the admin/chain path, across error and
  cancellation paths. A single missed reset is a silent cross-tenant or
  privilege-escalation hole. With α, role identity is a **property of the engine /
  pool**, fixed at login time. A `sentinel_app` pool connection is *physically
  incapable* of BYPASSRLS regardless of any forgotten reset. Fail-closed by
  construction beats fail-closed by discipline.

- **Secret / role management.** α adds one credential (`APP_DATABASE_URL`) to the
  existing `DATABASE_URL`. Both are env-injected from Vault/KMS at runtime per the
  Sentinel secrets rule; neither lives in code, config, or tests. The marginal
  cost is one more secret to rotate (covered in Operational Implications). β manages
  only one credential but pays for it with the per-checkout correctness burden above.
  We prefer the explicit, auditable second credential.

- **Emergency admin access.** With α, admin/break-glass access is the existing
  `DATABASE_URL` (privileged role) — a well-understood, already-provisioned path,
  cleanly separated from the app credential. With β, an operator under pressure
  must remember to `RESET ROLE` (or risk operating as the constrained app role) and
  reasons about role state on a shared pool. α's separation makes the emergency
  path obvious and independent of pool state.

- **Migration ergonomics.** Alembic already uses `DATABASE_URL` (psycopg sync) and
  needs DDL/owner privileges. Under α this is unchanged: migrations keep running as
  the privileged role; `sentinel_app` is only granted runtime DML on specific tables.
  Under β, migrations would also key off `DATABASE_URL` but the runtime app shares
  that same URL and toggles role per-checkout — entangling the migration credential
  with the request-serving credential. α keeps the migration boundary clean.

- **Defense-in-depth posture.** α makes the privilege boundary a network/auth
  boundary (two logins, two pools), not just an in-session SQL statement. This is the
  stronger posture for a product whose own code is a target.

**Accepted cost of α:** two engines means two pools (memory/connection budget roughly
doubles for the privileged pool, which can be sized small since it only serves chain
ops + admin), and a second secret to provision and rotate. Both are acceptable and
documented under Consequences.

---

## Threat Model

### What DB-layer RLS + FORCE + WITH CHECK reduces (primary boundary)

With `sentinel_app` (NOBYPASSRLS), `FORCE ROW LEVEL SECURITY` on every tenant table,
strict `USING` predicates, and `WITH CHECK` tenant binding on INSERT:

- **Cross-tenant SELECT (read leakage).** A tenant-A session (GUC = tenant A) cannot
  `SELECT` tenant-B rows from `teams`, `projects`, `users`, `role_assignments`,
  `virtual_api_keys`, `policies`, `policy_versions`, or `events_audit_log`. The
  `USING` predicate filters them out at the storage engine. This holds even if
  application code forgets a `WHERE tenant_id = ...` clause — RLS is the floor.
- **Cross-tenant INSERT forgery.** A tenant-A session cannot insert a row carrying
  `tenant_id = B`. The `WITH CHECK (tenant_id = current_setting('app.current_tenant_id'))`
  predicate rejects the write. This is what stops a compromised or buggy code path
  from minting another tenant's API key, policy, or audit row.
- **Cross-tenant UPDATE/DELETE.** Where applicable, `USING` (visibility) plus
  `WITH CHECK` (post-image) prevent re-homing a row into another tenant.
  (`events_audit_log` separately forbids UPDATE/DELETE entirely via triggers + `USING (false)`
  policies from F-003 — unchanged here.)

RLS is the **primary** isolation boundary. It is enforced regardless of application
correctness, which is precisely the property a security product needs.

### What still requires application-layer enforcement (belt-and-suspenders)

- **`get_by_id` IDOR.** `get_by_id(pk)` looks up a row by primary key. Under the
  tenant-scoped session, RLS **already** prevents returning another tenant's row:
  the `USING` predicate makes that row invisible, so the query returns "not found"
  even though the PK is valid. The app-layer `caller_tenant_id` check that F-003b
  adds to `get_by_id` is therefore **defense-in-depth, not the primary control** —
  it exists to (a) produce a clear, intentional "not found / forbidden" signal at
  the application boundary rather than relying on the implicit RLS empty result,
  (b) guard against a future caller accidentally invoking `get_by_id` on the
  privileged session (where RLS does not apply), and (c) make the security intent
  legible in code review. **The clarification matters:** under correct α operation,
  the RLS session *cannot* see the row anyway; the app check is the second lock on a
  door RLS has already locked.
- **`agents` and `tenants` lookups.** These tables are global by design (no
  `tenant_id`). Any authorization scoping for them (e.g., which tenant may reference
  which agent) is an application-layer concern; RLS does not cover them and is not
  intended to.
- **GUC provenance.** The value passed to `set_config('app.current_tenant_id', ...)`
  MUST originate from the authenticated `virtual_api_keys` row (the authoritative
  source per ADR-0004), **never** from a client-supplied header. RLS enforces
  "you may only touch your tenant"; the application is responsible for correctly
  determining *which* tenant the caller is. A wrong GUC value = wrong tenant; RLS
  cannot detect that the GUC itself was set from an untrusted source.

### Out of scope / honest limits

- RLS does **not** defend against a holder of the **privileged** `DATABASE_URL`
  credential (owner / BYPASSRLS). That is the documented tamper-evidence limit from
  ADR-0004 and is why the privileged credential is break-glass, narrowly scoped, and
  rotated. This is **risk reduction**, not an absolute barrier.
- This ADR isolates tenants at the **data** layer. It does not address per-tenant
  rate limiting, noisy-neighbor resource isolation, or network segmentation
  (separate concerns, separate tasks).

### Timing side-channel analysis (LOW-2)

The `get_by_id` not-found path returns a uniform `NotFoundError` regardless of
whether the row does not exist or exists but belongs to a different tenant (RLS
filters it from the result set before the application sees it). Because the
response shape is identical in both cases, there is no timing side-channel
distinguishable by the caller: both paths execute a single indexed PK + tenant_id
lookup at the storage level, filtered at the same RLS evaluation point. No
additional timing countermeasures are required under the current structure.

---

## How the Hash Chain Stays Global

The audit-log hash chain is a single global chain ordered by `sequence_number`
across all tenants (ADR-0004). Correct validation and correct `prev_hash` linkage
require visibility of **every** row.

- **Chain ops run on the privileged session only.** `append()`, `_get_tip_hash()`,
  and `validate_chain()` execute via `get_privileged_session()` (the `DATABASE_URL`
  / BYPASSRLS engine). On that session RLS does not filter rows, so the tip read sees
  the true global tip and `validate_chain()` walks the entire chain.
- **Tenant sessions MUST NOT run chain ops.** Under a tenant-scoped session, the
  `events_audit_log` `USING` predicate restricts the visible rows to the current
  tenant. A tip read would return that tenant's last row, not the global tip — so a
  new `append()` would compute `prev_hash` against the wrong predecessor and **fork
  the chain**. A `validate_chain()` would walk only one tenant's subset and either
  report a spurious break (gaps in `sequence_number`) or validate a non-global
  fragment. Both are corruption / false signals.
- **Documented behavior when `validate_chain()` is mis-called on a tenant session.**
  F-003b MUST make this fail loudly, not silently mislead. The chain methods MUST
  assert they are running on the privileged engine. Concretely: `validate_chain()`
  and `_get_tip_hash()` check that the active role is the privileged role (e.g.,
  `SELECT current_setting('app.current_tenant_id', true)` returns empty/unset AND/OR
  a session marker confirms the privileged engine) and raise a
  `PrivilegedSessionRequiredError` if invoked on a tenant session. Validation of a
  truncated tenant view must **never** be reported as a passing global validation.
  Fail-closed: if the method cannot confirm it is privileged, it refuses to run.

Reads of audit rows **for display to a tenant** (tenant-scoped audit viewing) remain
on the tenant session and are correctly filtered by RLS — that is a normal scoped
query, not a chain operation. Only the integrity operations (tip/append/validate)
are privileged.

---

## The Empty-String-vs-NULL GUC Defect and the New Predicate

### The defect

Postgres `current_setting('app.current_tenant_id', true)` (the `missing_ok = true`
form) returns the **empty string `''`** when the GUC is unset — it does **not**
return `NULL`. Consequences in the F-003 policies:

1. The `OR current_setting(...) IS NULL` bypass branch is **dead code** — it can
   never be true, so it was never a real bypass (small mercy), but it is misleading
   and must be removed.
2. With the GUC unset, the primary predicate becomes `tenant_id = ''`, which matches
   no real `tenant_id`. The result is a **silent zero-row** outcome: queries return
   nothing instead of failing. For a security product this is a fail-*quiet*, not a
   fail-*closed-and-loud*, posture. A forgotten `set_config` would manifest as
   confusing "no data" bugs rather than an explicit error.

### The new policy predicate shape (what the migration MUST use)

F-003b removes the `OR ... IS NULL` branch entirely and adopts a predicate that is
**unsatisfiable when the GUC is unset or empty**, so a missing GUC yields zero rows
*by intent* — but the application layer additionally guards the GUC at set time so a
missing tenant context raises before any query runs. The migration MUST use the
strict, no-fallback form inside tenant policies:

```sql
-- USING (visibility) and WITH CHECK (write binding), identical predicate:
USING (
  tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')
)
WITH CHECK (
  tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')
)
```

Rationale for this exact shape:

- `NULLIF(current_setting('app.current_tenant_id', true), '')` collapses the
  empty-string-when-unset case to `NULL`. Since `tenant_id = NULL` is `UNKNOWN`
  (never true), an **unset or empty** GUC makes the predicate unsatisfiable: zero
  rows visible, zero writes permitted. There is no `OR ... IS NULL` escape hatch.
- `missing_ok = true` is retained **only** inside `NULLIF` so the predicate does not
  throw `unrecognized configuration parameter` on a connection where the GUC was
  never touched — it degrades to "no access" rather than a SQL error mid-policy.
  The loud failure is provided at the application layer instead (next bullet).
- **Application-layer fail-closed guard (the loud half).** `get_tenant_session`
  MUST reject a missing/empty/whitespace `tenant_id` **before** opening the
  transaction and raise an explicit error (e.g., `TenantContextRequiredError`). The
  app never relies on the silent zero-row behavior as its primary signal; it raises.
  The strict policy predicate is the database-layer backstop for the case where a
  query somehow reaches the DB without the GUC.

This gives a two-layer fail-closed: **loud** at the application boundary (raises if
no tenant context) and **silent-deny** at the database boundary (zero rows if the
GUC is somehow unset). Neither layer ever silently *grants* cross-tenant access.

### Scope of the predicate change

- `teams`, `projects`, `users`, `role_assignments`, `events_audit_log` (the
  `eal_select` policy): **drop** the `OR ... IS NULL` branch, replace with the
  `NULLIF` form above.
- `virtual_api_keys`, `policies`, `policy_versions`: **add** RLS, `FORCE ROW LEVEL
  SECURITY`, and policies using the `NULLIF` form (these had no RLS at all in F-003).
- `events_audit_log` append-only policies (`eal_deny_update`/`eal_deny_delete` =
  `USING (false)`, `eal_insert` = `WITH CHECK (true)`): unchanged. Note `eal_insert`
  stays `WITH CHECK (true)` because audit inserts run on the **privileged** session
  (chain ops), not the tenant session; tenant binding for audit rows is enforced in
  the repository, and the privileged session is trusted to write the correct
  `tenant_id` value resolved from the authenticated context.

---

## GUC Lifetime and Mid-Transaction Clear (MED-1)

The tenant GUC (`app.current_tenant_id`) is set via `set_config(name, value, is_local=true)`,
which makes it **transaction-local**: Postgres automatically restores the prior value
(typically `''`) at transaction end (commit or rollback). This is equivalent to
`SET LOCAL` and prevents stale context from leaking across pool-reused connections.

A mid-transaction `RESET app.current_tenant_id` by attacker-controlled SQL is not
exploitable under the current architecture for two independent reasons:

1. **Role-based privilege gate.** `_assert_privileged_session()` checks
   `SELECT current_user` against `SENTINEL_APP_ROLE` ("sentinel_app"). A
   sentinel_app session clearing its own GUC does not change its Postgres role
   identity. Chain ops remain blocked regardless of GUC state.

2. **RLS NULLIF predicate.** The USING/WITH CHECK predicate evaluates
   `NULLIF(current_setting('app.current_tenant_id', true), '')`, which collapses
   `''` to `NULL`. A mid-tx clear results in zero-row reads and rejected writes —
   fail-closed, never cross-tenant access.

The transaction-local GUC is therefore acceptably pinned: a mid-tx clear silently
narrows scope to zero rows rather than widening it to another tenant's data.

**Decision:** retain `set_config(..., is_local=true)` (equivalent to `SET LOCAL`)
with explanatory comments in `database.py` (see `get_tenant_session` docstring).

---

## Operational Implications

- **Secret rotation for `sentinel_app`.** `APP_DATABASE_URL` carries the
  `sentinel_app` login credential and is injected from Vault/KMS at runtime — never
  in code, config, logs, or tests (Sentinel secrets rule). Rotation:
  `ALTER ROLE sentinel_app WITH PASSWORD :new` (run via the privileged credential),
  update the Vault secret, roll the app pods. Because α uses a separate pool, rotating
  the app credential does not touch the privileged/admin credential and vice versa.
  Rotate the two credentials independently on their own schedules.
- **Role migration / idempotency.** The F-003b migration that creates `sentinel_app`
  MUST be idempotent and safe to re-run: guard role creation
  (`DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='sentinel_app')
  THEN CREATE ROLE sentinel_app LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE; END IF; END $$;`),
  and make GRANTs/policy creation re-runnable (`DROP POLICY IF EXISTS` then `CREATE
  POLICY`). The login password is **not** set in the migration SQL (no secrets in
  migrations); it is provisioned out-of-band via Vault-driven `ALTER ROLE`. The
  `downgrade()` reverses GRANTs/policies and may `DROP ROLE` only if no objects are
  owned — never destructive to data.
- **GRANTs.** `sentinel_app` receives the **minimum** runtime DML on tenant tables
  (`SELECT`, `INSERT`, and `UPDATE`/`DELETE` only where the repository actually needs
  them), plus `USAGE`/`SELECT` on the sequences those tables depend on (the F-003b
  "scoped sequence grants" item). It receives **no** DDL, no privileges on `tenants`
  beyond what auth requires, and is never granted BYPASSRLS.
- **Emergency / break-glass admin access.** The privileged `DATABASE_URL` role is the
  break-glass path. It is held in Vault under tighter access controls than the app
  credential, its use is itself an audit-worthy event, and it is the only path that
  can bypass RLS or run DDL. Document it as break-glass: not for routine traffic.
- **Pool sizing.** The privileged engine pool can be small (chain ops are serialized
  by the advisory lock and admin use is infrequent). The tenant engine keeps the
  existing `pool_size=5 / max_overflow=10` budget. Total connection budget rises
  modestly; size the privileged pool conservatively (e.g., `pool_size=2`).

---

## Test Strategy (Fail-Closed)

**The single most important test rule:** the isolation test fixture MUST connect as
**`sentinel_app`** (the non-BYPASSRLS role), **NOT** as the admin/owner role. If the
fixture connects as the owner, RLS is bypassed and **every isolation test passes
spuriously** — the suite would be green while providing zero real coverage. The
fixture MUST also actually set `app.current_tenant_id` via the tenant-session path
under test, not by hand-injecting a bypass.

Enumerated reject cases (each MUST fail closed):

1. **Cross-tenant SELECT denied.** As `sentinel_app` with GUC = tenant A, selecting
   a known tenant-B row from each of the eight tenant tables returns **zero rows**.
2. **Cross-tenant INSERT forgery denied.** As `sentinel_app` with GUC = tenant A,
   inserting a row with `tenant_id = B` raises a `WITH CHECK` violation.
3. **Cross-tenant re-home denied.** As tenant A, `UPDATE ... SET tenant_id = B`
   (where update is permitted at all) is rejected by `WITH CHECK`.
4. **Unset GUC denies, not grants.** As `sentinel_app` with **no** GUC set, every
   tenant-table SELECT returns zero rows (never another tenant's rows), and the
   application `get_tenant_session(None/'')` raises `TenantContextRequiredError`
   before issuing a query.
5. **Empty-string GUC denies.** GUC explicitly set to `''` behaves identically to
   unset: zero rows, no grant (proves the `NULLIF` predicate, not the dead
   `IS NULL` branch).
6. **`get_by_id` IDOR denied.** `get_by_id` of a tenant-B PK under a tenant-A
   session returns not-found (RLS) **and** the app-layer `caller_tenant_id` check
   rejects it (proves both locks).
7. **New-RLS tables covered.** Cases 1–3 explicitly include `virtual_api_keys`,
   `policies`, and `policy_versions` (the three tables that had no RLS in F-003).
8. **Chain ops refuse tenant sessions.** Calling `validate_chain()` or
   `_get_tip_hash()` on a tenant session raises `PrivilegedSessionRequiredError`;
   it never reports a truncated/forked chain as valid.
9. **Chain stays global on privileged session.** `append()` across rows belonging to
   different tenants produces one contiguous chain; `validate_chain()` on the
   privileged session passes end-to-end across all tenants.
10. **`agents` / `tenants` unaffected.** Global tables remain readable as designed
    (no tenant RLS regression introduced).

**Existing 88 tests:** kept passing via **fixture updates only** — repoint the
session fixtures to the two new factories and ensure the privileged-path tests
(chain) use `get_privileged_session`. No production contract fields
(`events.schema.json`, `policy.schema.json`, `openapi.yaml`) and no stable IDs
(`contracts/ids.md`) are altered by this work.

---

## Consequences

### Positive

- RLS becomes a **real** isolation boundary instead of decorative: `sentinel_app`
  is physically incapable of bypassing it.
- Cross-tenant read leakage and write forgery are reduced at the database floor,
  independent of application-code correctness.
- The empty-string GUC defect is repaired; missing tenant context fails closed
  (loud at the app, silent-deny at the DB) instead of silently returning zero rows.
- The global hash chain remains correct and globally validatable, with explicit
  guards preventing accidental tenant-scoped chain operations.
- Privilege identity is a property of the engine/pool, eliminating the
  `SET ROLE` reset-discipline failure mode entirely.
- Audit-ready posture: clear separation of app vs privileged credentials, explicit
  fail-closed predicates, and an enumerated isolation test matrix.

### Negative / costs

- Two engines and two pools: higher connection-budget footprint and a second
  credential (`APP_DATABASE_URL`) to provision and rotate.
- `database.py` gains complexity (two factories, GUC wiring, privileged-session
  assertions) versus F-003's single factory.
- Developers must choose the correct session for each operation; choosing wrong is
  guarded (chain ops assert privileged; tenant ops require GUC) but is a new
  cognitive cost.
- The privileged credential remains an absolute-trust escape hatch — isolation is
  **risk reduction**, not an absolute guarantee against a privileged-credential
  compromise (consistent with ADR-0004's tamper-evidence honesty).

### What stays deferred

- External WORM attestation of chain tips / tail-truncation gap — **F-035**
  (unchanged from ADR-0004).
- Cryptographic policy JWS verification and scope-resolve-and-reject — **F-008**.
- Per-tenant rate limiting / noisy-neighbor resource isolation — separate task.
- Network-level tenant segmentation — separate task.

---

## Summary of Decisions

| Decision | Choice | Primary Rationale |
|----------|--------|-------------------|
| Isolation architecture | Option α: two engines, two roles | Privilege = pool property; no `SET ROLE` reset-discipline failure mode |
| App role | `sentinel_app` (LOGIN, NOSUPERUSER, NOBYPASSRLS) | Physically cannot bypass RLS |
| App connection | `APP_DATABASE_URL` (Vault-injected) | Separate credential, independent rotation |
| Privileged/admin/chain/migrations | existing `DATABASE_URL` | Owner/BYPASSRLS; break-glass + DDL + global chain |
| New RLS tables | `virtual_api_keys`, `policies`, `policy_versions` (3) | Only tenant tables lacking RLS in F-003 |
| Non-RLS tables | `tenants`, `agents` | Global registry, no `tenant_id`, by design |
| Policy predicate | `tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')` | Unsatisfiable when GUC unset/empty; no `IS NULL` escape |
| Missing tenant context | App raises `TenantContextRequiredError` + DB silent-deny | Two-layer fail-closed |
| Hash chain ops | privileged session only; assert + raise on tenant session | Chain is global; tenant view truncates/forks it |
| `get_by_id` app check | defense-in-depth (RLS is primary) | Second lock on a door RLS already locked |
| Test fixture | connects as `sentinel_app`, not admin | Owner connection passes isolation tests spuriously |
| Contracts / stable IDs | unchanged | This work alters no contract fields |
| Existing 88 tests | fixture updates only | Keep green without weakening coverage |
| Isolation claim | risk reduction, not absolute | Honest language per CLAUDE.md |
