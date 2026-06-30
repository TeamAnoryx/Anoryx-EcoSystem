# ADR-0004 — Rendly Persistence (User Profiles + Identity Store)

- Status: Accepted
- Date: 2026-06-30
- Task: R-004 (first Rendly database task)
- Builds on: ADR-0001 (core contract), ADR-0002 (domain model), ADR-0003 (auth)
- Mirrors: Anoryx-Sentinel F-003b tenant isolation (ADR-0005) as replicated by Delta D-003 (ADR-0003)

## Context

R-002 shipped frozen, storage-agnostic Pydantic v2 domain types. R-003 shipped self-contained
OAuth2 + JWT auth on top of **two explicit in-memory seams** — `UserStore` and `RefreshTokenStore`
— whose docstrings name R-004 as the task that backs them with a real database *"with NO contract
change."* R-004 gives the identity types a Postgres persistence layer, fills both seams against
real Postgres, and **retires R-003's fixture-store honesty boundary**. Tenant isolation is the
load-bearing security property of a data-sovereignty product, so this is a security task with a
persistent audit artifact (`docs/audit/r-004-security-audit.md`).

The proven pattern is Sentinel F-003b RLS (own schema, `*_app` NOBYPASSRLS role, RLS on every
tenant-scoped table, a per-tenant GUC, a privileged role for migrations/admin, and the "F-010 SCRAM
landmine" entrypoint fix), already replicated by Delta D-003. R-004 mirrors that design with
Rendly's own schema/role.

## Decisions (one per resolved fork)

### Fork A — database topology: **OWNED `rendly` schema**
Rendly owns its persistence: a dedicated `rendly` Postgres schema, its own Alembic chain starting
at `0001`, and its own `alembic_version` pinned into the `rendly` schema
(`version_table_schema="rendly"`). The identical migration runs whether Rendly uses its own
Postgres (local/CI, `Rendly/docker-compose.yml` on host port **5546** to avoid Sentinel 5432/5433
and Delta 5544) or shares Sentinel's cluster in production (different schema, same instance).
**Tradeoff:** clean product isolation + independent deploy (R-010), `tenant_id` a logical key, zero
coupling to Sentinel's migration lifecycle. The MVP cross-product path is Orchestrator events
(X-001..X-003), **not** DB joins — so a shared single schema buys nothing the event bus does not
already provide, at the cost of lifecycle coupling. Shared-schema rejected.

### Fork B — isolation enforcement: **RLS, mirroring F-003b**
RLS on every tenant-scoped table (`users`, `profiles`, `credentials`, `refresh_token_families`,
`refresh_tokens`) plus a `rendly_app` login role created `NOSUPERUSER NOBYPASSRLS NOCREATEDB
NOCREATEROLE`. Predicate (NULLIF form — the corrected F-003b form, not the dead `OR … IS NULL`
branch), in **both** `USING` and `WITH CHECK`:
`tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')`.
The `tenants` table is a **global registry** and intentionally carries **no RLS** (mirrors
Sentinel's RLS-exempt `tenants`/`agents`). **Tradeoff:** RLS is fail-closed at the database even if
an application query forgets a `WHERE` clause; app-level filtering leaks on one missed clause —
unacceptable for a data-sovereignty product. Two-layer fail-closed is retained: the app raises
`TenantContextRequiredError` (loud) before any query when `tenant_id` is blank, and the DB predicate
is unsatisfiable (silent zero-row deny) when the GUC is unset/empty.

### Fork C — persistence scope: **identity + refresh families; Channel/Membership DEFERRED**
Persisted now: `Tenant`, `User`, `Profile` (with **one-profile-per-user** enforced via
`UNIQUE(tenant_id, user_id)` — R-002 deferred that uniqueness to R-004), `credentials`, and the
refresh-token family state (`refresh_token_families` + `refresh_tokens`).

> **Honesty boundary (verbatim):** Channel and Membership are modeled in R-002 but are **NOT
> persisted in R-004**. Their tables and the `bind_membership` cross-tenant invariant at the DB
> layer are **deferred to R-005**, where chat actually uses them and re-proves the invariant
> against the database. The `source` + `external_ref` Delta seam therefore does not yet exist as
> columns; R-005 adds it as nullable columns. R-004 persists **identity only**.

Refresh-token families are persisted (not deferred): R-003's reuse-detection was in-memory ("lost
on restart — the documented R-004 seam"). Persisting it makes reuse-detection survive restart and
work multi-instance — a real auth security property — and the session/DB machinery is built anyway.
The persisted form replicates the in-memory semantics exactly: SHA-256-at-rest, `rt_`-prefixed
opaque tokens, `family_id`/`generation`/`used`/`expires_at`, and reuse-of-a-used-token revokes the
whole family.

### Fork D — session/engine pattern: **SYNC machinery mirroring F-003b's safety design**
R-003's seams (`UserStore`, `RefreshTokenStore`) and the `TokenService` that calls them are
**synchronous**. Implementing them byte-for-byte therefore requires **synchronous** DB access, so
R-004 uses sync SQLAlchemy `Session` + **psycopg** (the same driver Alembic already uses across the
ecosystem) rather than the async `asyncpg` path Sentinel/Delta use at runtime. The sync
`get_tenant_session(tenant_id)` mirrors the async one's *safety design*: fail-closed
(`TenantContextRequiredError` before opening on blank tenant), sets the transaction-local GUC via
`SELECT set_config('app.current_tenant_id', :tid, true)`, and **autobegins** — a sync `Session` also
begins a transaction on first `execute`, so reads are never wrapped in `session.begin()` (the F-007
double-begin class) and writes commit explicitly. A `get_privileged_session()` (BYPASSRLS owner)
serves migrations/admin and the login credential bootstrap. Module-lazy-singleton engines are reset
by `reset_engines()` called at test **setup** (the F-019 stale-DSN-pollution guard). **Tradeoff:**
keeps R-003 byte-for-byte sync, avoids the async-in-sync event-loop footgun, and inherits every
F-003b safety property.

> **Forward boundary (verbatim):** Rendly's runtime DB driver is **sync (psycopg)** in R-004 where
> Sentinel/Delta are async. When R-005's chat runtime needs async DB access (WebSockets), it adds
> its **own async session layer** alongside this one; the RLS/role/GUC design is driver-agnostic and
> ports directly. No async runtime DB code is shipped in R-004.

### Fork E — UserStore reconciliation: **VERIFIED satisfiable byte-for-byte; no R-003 change**
Both seams were implemented against the existing ABC signatures with **no signature change**:
`UserStore.get_credentials(username) -> StoredCredential | None`,
`UserStore.get_user(user_id, tenant_id) -> User | None`,
`RefreshTokenStore.issue(*, user_id, tenant_id, scopes, roles, ttl_seconds) -> str`,
`RefreshTokenStore.rotate(raw_token, *, ttl_seconds) -> RotationResult`,
`RefreshTokenStore.revoke(raw_token) -> None`. This is **not** an R-003 contract issue; the sync
nature of the seams simply drove Fork D to sync. R-003's auth now runs end-to-end against real
Postgres (password grant, `/users/me`, refresh rotate, reuse→family-revoke).

> **Login cross-tenant bootstrap (verbatim):** `get_credentials(username)` takes no `tenant_id` —
> the username is a **global** key and the tenant claim is read from the matched row. That lookup is
> therefore an inherent **cross-tenant read at login** (the tenant is unknown until the user is
> found). It is served by the **privileged** session, returns exactly one credential row, and the
> tenant claim is bound from that row — **never** from request input. Every subsequent `get_user`
> and refresh operation is tenant-scoped via `rendly_app` under RLS. This mirrors Sentinel's
> privileged-for-global / app-for-tenant-scoped split. R-001's structural property — no client field
> carries `tenant_id` — is preserved: `tenant_id` is server-resolved, set on the session GUC, never
> trusted from request input.

## The SCRAM landmine fix (inherited from F-010 / Delta D-003)
Migration `0001` creates `rendly_app` via an idempotent `DO`-block with **NO password in SQL** (a
credential must never appear in a migration). A passwordless `LOGIN` role cannot authenticate over a
SCRAM-SHA-256 `APP_DATABASE_URL`, so on a fresh DB every tenant connection would fail.
`Rendly/docker-entrypoint.sh`, gated by `RENDLY_PROVISION_APP_ROLE=1`, runs **after**
`alembic upgrade head`, computes the SCRAM-SHA-256 verifier **client-side**, and runs
`ALTER ROLE rendly_app WITH LOGIN PASSWORD '<verifier>'` over the privileged connection — plaintext
is never a SQL literal and is never logged. Idempotent. The test conftest runs the same routine
per-test (loud `pytest.fail` on any provisioning error, with a self-login check).

## Consequences
- R-003's fixture-store honesty boundary is **retired** for the DB path: auth runs on real
  persistence. R-005 can read persisted users/profiles with no contract change.
- A new `rendly-db` CI lane runs the persistence/RLS/auth-DB suite against a fresh Postgres, plus a
  `rendly-migration-roundtrip` lane proving up→down→up and a DROP-SCHEMA rebuild.
- Verified locally: 22 persistence tests pass (incl. cross-tenant RLS deny, forged-tenant zero-row,
  no-GUC/empty-GUC fail-closed, reuse→family-revoke across a fresh connection, uncanonicalized-id
  round-trip, tokens-hashed-at-rest), full suite 172 pass, coverage 98.44% (gate 90). CI is the
  authoritative gate (fresh Linux + Postgres).

## Deferred to later tasks
- Channel + Membership persistence and the `bind_membership` DB-layer invariant → R-005.
- Async runtime DB session layer → R-005 (chat/WebSocket).
- `source` + `external_ref` Delta-team seam columns → R-005/R-006.
