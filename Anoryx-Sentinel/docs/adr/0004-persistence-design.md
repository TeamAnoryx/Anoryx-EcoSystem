# ADR-0004: Persistence Layer Design for Anoryx-Sentinel (F-003)

**Status:** Accepted  
**Date:** 2026-06-15  
**Deciders:** Sentinel engineering team  
**Tags:** database, security, audit, hash-chain, rbac

---

## Context

Anoryx-Sentinel requires a persistence layer that:
1. Stores multi-tenant organizational hierarchy (tenants, teams, projects, agents).
2. Authenticates requests via virtual API keys without storing plaintext credentials.
3. Enforces RBAC at the database layer, not just the application layer.
4. Stores policies flowing down from Delta/Orchestrator with full version history.
5. Maintains a tamper-evident audit log for all events that cross the gateway.
6. Supports the contracts/ids.md stable identifier schema (UUID v4 for three of four IDs; slug for agent_id).

---

## F-003 Scope Statement

**F-003 establishes the schema and repository layer ONLY. Runtime tenant isolation is NOT enforced by F-003 and is deferred to F-003b, which MUST merge before F-004.**

What F-003 delivers:
- Alembic migrations 0001 through 0005: all tables, CHECK constraints, triggers, indexes, and append-only enforcement for events_audit_log.
- ORM models for all tables.
- Repository classes with `create`, `get_by_id` (PK-only, no tenant scoping), `list_*`, and lifecycle methods.
- HMAC-based virtual API key fingerprinting and lifecycle management.
- Hash-chain append, tip-read, and validate_chain in AuditLogRepository.
- `get_async_session()` — a single, simple async session factory with no GUC wiring and no role switching.

What F-003b owns (deferred, MUST merge before F-004):
- The `sentinel_app` Postgres role (NOLOGIN, NOSUPERUSER, NOBYPASSRLS).
- Table-level GRANT statements scoped to `sentinel_app`.
- RLS FORCE on all tenant-scoped tables (teams, projects, users, role_assignments, virtual_api_keys, policies, policy_versions, agents, events_audit_log).
- Strict RLS policies with no NULL/empty-string bypass for the app role.
- WITH CHECK tenant binding on INSERT for all tenant-scoped tables.
- Privileged session wiring (BYPASSRLS connection URL) for hash-chain ops.
- Tenant-scoped session wiring (`set_config('app.current_tenant_id', ..., true)`) for application queries.
- Application-layer `caller_tenant_id` scoping on all `get_by_id` methods.
- A `sentinel_app`-connected fail-closed isolation test matrix.
- Scoped sequence grants.

**Honest language:** The RLS policies present in migration 0002 (tenant_isolation on teams, projects, users, role_assignments) and migration 0005 (eal_select on events_audit_log) are present in the schema but are NOT the enforcement boundary in F-003. Those policies use an `OR current_setting(...) IS NULL` branch that is unreachable in practice (Postgres `current_setting()` returns `''`, not NULL, when unset) but is not actively enforced against any app role. F-003b removes this branch and wires the app role that makes the policies binding.

---

## Database Engine Decision: PostgreSQL 16

**Alternatives considered:** DynamoDB, ScyllaDB.

| Criterion | PostgreSQL 16 | DynamoDB | ScyllaDB |
|-----------|--------------|----------|----------|
| ACID transactions | Full | Limited (optimistic) | Limited |
| Row-Level Security (RLS) | Native, mature | No | No |
| CHECK constraints | Full DDL support | No | Limited |
| Triggers (BEFORE INSERT/UPDATE/DELETE) | Full | No | No |
| JOIN queries for audit correlation | Full SQL | Requires secondary index + scatter-gather | CQL, limited JOINs |
| Schema migrations (Alembic) | Excellent | Manual | Manual |
| Ecosystem (asyncpg, psycopg, SQLAlchemy) | Mature | Separate SDK | Separate SDK |
| BRIN / GIN indexes | Available | No | No |

**Decision:** PostgreSQL 16. Its native RLS, trigger system, full ACID semantics, and rich ecosystem make it the correct choice for a security product where tenant isolation must be enforced at the database layer. That enforcement arrives in F-003b, not F-003.

---

## ID Storage Decision: VARCHAR(64) for All Four Stable IDs

Per contracts/ids.md:
- tenant_id, team_id, project_id: UUID v4, maxLength 64.
- agent_id: lowercase slug `^[a-z0-9]+(-[a-z0-9]+)*$`, maxLength 64.

**Decision:** VARCHAR(64) for all four IDs (not native UUID for the three UUID fields).

**Rationale:** Using the same column type across all four IDs simplifies schema consistency, avoids implicit casts in JOINs, and keeps the column size predictable. The trade-off is that UUID format is not enforced at the DB level — it is enforced by the Pydantic schemas and repository layer. This is acceptable because the IDs are always server-generated (never client-supplied) so format guarantees come from the generation code, not DB constraints.

---

## Password Hashing: Argon2id via argon2-cffi

**Decision:** Argon2id (the `argon2-cffi` library) for user passwords.

**Rationale:** Argon2id is the winner of the Password Hashing Competition (2015) and is the recommended algorithm by OWASP for new systems. It provides memory-hardness and side-channel resistance. The password_hash column stores the full Argon2 PHC string (prefix + parameters + salt + digest). Plaintext passwords are NEVER stored, logged, or returned.

Alternatives: bcrypt (acceptable but lacks memory-hardness), PBKDF2 (older, weaker than Argon2id).

---

## Virtual API Key Storage: HMAC-SHA256 Fingerprint Only

**Decision:** Store only the HMAC-SHA256 hexdigest of the plaintext key, keyed on `SENTINEL_KEY_SECRET` from the environment.

**Rationale:**
- Plaintext storage: disqualified — a DB compromise exposes all keys.
- Encrypted storage (AES-encrypt-then-store): would require key management for the encryption key, and decryption on every auth call.
- HMAC fingerprint: the server computes HMAC(plaintext, secret) at key creation and at auth time. Auth compares HMACs using `hmac.compare_digest` (constant-time). A DB compromise reveals only fingerprints, not plaintexts. There is no decryption path, so the plaintext can never be recovered from the DB.
- The row is the **authoritative source** of tenant/team/project/agent IDs. Auth resolves IDs from this row, never from client-supplied headers (F-001 lesson).

---

## RBAC: Row-Level Security at the Database Layer

**Decision:** Postgres native RLS with `FORCE ROW LEVEL SECURITY` on all tenant-scoped tables.

**Tenant-scoped tables with RLS enabled (schema present in F-003, enforcement wired in F-003b):**
- teams, projects, users, role_assignments, events_audit_log

**RLS policies in F-003 (migration 0002 and 0005):**
Migration 0002 creates `tenant_isolation` policies on teams, projects, users, and role_assignments. Migration 0005 creates `eal_select` on events_audit_log. These policies use `USING (tenant_id = current_setting('app.current_tenant_id', true) OR current_setting(...) IS NULL)`. The `OR ... IS NULL` branch is unreachable in practice but is not yet a security gap in F-003 because the `sentinel_app` role does not exist yet and no application connections are wired through RLS enforcement.

**What F-003b changes:**
- Creates the `sentinel_app` role (NOLOGIN, NOSUPERUSER, NOBYPASSRLS) — the role used by application connections at runtime.
- Grants minimum table-level privileges to `sentinel_app`.
- Drops the `OR ... IS NULL` branch and replaces policies with strict versions: `USING (tenant_id = current_setting('app.current_tenant_id', true))`.
- Adds `WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true))` on INSERT for all tenant-scoped tables.
- Wires two session types in database.py:
  1. **Tenant-scoped session:** connects as `sentinel_app`, calls `set_config('app.current_tenant_id', :tid, true)` at transaction start (transaction-local, clears on commit/rollback).
  2. **Privileged session:** connects as a BYPASSRLS role, used only for hash-chain tip reads, validate_chain(), and admin ops.
- Adds `caller_tenant_id` scoping to all `get_by_id` repository methods.
- Delivers a fail-closed isolation test matrix.

**In F-003:** `get_async_session()` is a single, simple session that does not set any GUC and does not switch roles. No tenant isolation is enforced at the application session layer.

---

## Policy Versioning: Full History + Monotonic Version Enforcement

**Decision:** Two tables: `policies` (current state, one row per policy_id) and `policy_versions` (full history, append-only, (policy_id, policy_version) unique).

**Monotonicity:** Enforced at two layers:
1. **Repository layer:** `PolicyRepository.upsert_policy()` queries the current max version before insert and raises `PolicyMonotonicityError` if the incoming version is not strictly greater.
2. **Database trigger:** `trg_policy_versions_monotonicity` (BEFORE INSERT on policy_versions) raises a Postgres exception if the new version is not strictly greater than the current max for that policy_id. This is defense-in-depth — even a direct SQL insert cannot bypass monotonicity.

**Signature column:** Stored as VARCHAR(4096) with a CHECK constraint enforcing minLength 16 and maxLength 4096. The compact-JWS format (three dot-separated base64url segments) is validated at the repository + Pydantic layer. Cryptographic signature verification is deferred to F-008.

---

## Hash-Chain Audit Log: Design and Honest Limits

### Single-table Design

**Decision:** Single table (`events_audit_log`) with nullable variant-specific columns, discriminated by `event_type`.

**Alternatives considered:** Per-event-type tables (7 tables), JSONB payload column.

| Criterion | Single table (nullable cols) | Per-type tables | JSONB payload |
|-----------|------------------------------|-----------------|---------------|
| Schema correctness | DB CHECK per column | Full column constraints | No DB enforcement |
| Query simplicity | Simple (one table scan) | Requires UNION or views | Simple |
| Hash-chain ordering | Single bigserial sequence | Complex cross-table sequence | Simple |
| Alembic migration count | 1 migration | 7 migrations | 1 migration |
| Required contract fields | Strict columns (all 7 variants) | Strict columns per table | Catch-all anti-pattern |

**Decision rationale:** The single-table design provides a single bigserial sequence number for unambiguous chain ordering, a single validate_chain() scan, and strict per-column CHECK constraints for all required contract fields. Per-type tables would complicate chain ordering. JSONB for required fields is explicitly prohibited by the F-001 audit findings ("closed schemas remove a silent smuggling channel").

### Contract Conformance: Column Names

Column names in `events_audit_log` match `contracts/events.schema.json` field names exactly:
- `severity` — PiiBlockedEvent.severity (not `pii_severity`)
- `status` — ComplianceCheckedEvent.status (not `compliance_status`)

F-003 conforms to F-002 (the contract). The contract is authoritative; the persistence layer is not.

These column names are present from migration 0005 creation — there is no rename step. Migration 0005 is born with the final contract names.

### Canonical JSON Specification

The fields included in the hash content are fixed at the application layer (not variable). The canonical form is:

1. **Fields included:** All content fields listed in `persistence.hash_chain.CANONICAL_FIELDS`. Missing fields produce a `null` value in the JSON (not omission) to prevent omission attacks.
2. **Serialization:** `json.dumps(data, sort_keys=True, separators=(',', ':'))` — alphabetically sorted keys, no whitespace, UTF-8 encoded. `sort_keys=True` is the authoritative determinism mechanism. CANONICAL_FIELDS defines *which* fields are included, not their serialization order (which is alphabetical).
3. **Required in hash:** `event_timestamp` and `prev_hash` are always included and required. Including `event_timestamp` in the hash prevents reordering attacks (swapping two rows with the same content but different timestamps).
4. **SHA-256:** Applied to the UTF-8 bytes of the canonical JSON. Output is a 64-character lowercase hex string.

### Genesis Constant

The first row's `prev_hash` is:
```
SHA-256("anoryx-sentinel:events:genesis:v1")
= 8d7c3ee31ce45808a8871f3a844adf13622e17ef348c857d0cb9c7e066424607
```
This is a **documented** constant, not all-zeros or a random secret. It is reproducible from the domain-separation string and unambiguous in audit records. The value is computed dynamically at import time in `persistence/hash_chain.py` via `hashlib.sha256(b"anoryx-sentinel:events:genesis:v1").hexdigest()` — it is never hardcoded as a string literal. The 64-character hex value above is cited here for audit reference; the authoritative computed value is always the single source of truth in `hash_chain.GENESIS_HASH`.

### Append-Only Enforcement (Dual-Layer)

**Layer 1 (DB triggers):**
- `trg_eal_deny_update`: BEFORE UPDATE, raises `"events_audit_log is append-only: UPDATE is forbidden"`.
- `trg_eal_deny_delete`: BEFORE DELETE, raises `"events_audit_log is append-only: DELETE is forbidden"`.

**Layer 2 (RLS):**
- `eal_deny_update` policy: `USING (false)` — no rows are eligible for UPDATE.
- `eal_deny_delete` policy: `USING (false)` — no rows are eligible for DELETE.
- `eal_insert` policy: `WITH CHECK (true)` — all inserts allowed (repository validates content).
- `eal_select` policy: tenant-scoped visibility (F-003 form includes OR IS NULL branch; strict form arrives in F-003b).

**No application-layer UPDATE or DELETE methods exist** in `AuditLogRepository`.

### Concurrent Insert Safety

**Decision:** Transaction-scoped advisory lock (`pg_advisory_xact_lock(_CHAIN_ADVISORY_LOCK_ID)`) acquired at the start of every `append()` call. The lock id constant `_CHAIN_ADVISORY_LOCK_ID = 5347209814718263` is defined in `audit_log_repository.py`.

**Rationale:** Without serialization, two concurrent transactions can both read the same "tip" (last row_hash), both compute `prev_hash = that hash`, and both insert rows with the same `prev_hash`, producing a forked chain. The advisory lock serializes the critical section (tip fetch → insert) globally within the DB. The lock is automatically released at transaction end, so it does not persist across transactions.

**Alternative considered:** `SELECT ... FOR UPDATE` on an `audit_chain_tip` table. This is equivalent in effect; the advisory lock is simpler to implement and avoids an extra table.

### Tamper-Evidence: Honest Limits

The audit log is **tamper-EVIDENT**, not **tamper-PROOF**. An attacker with full Postgres superuser access (or BYPASSRLS + direct psql) can:
1. Update a row's content.
2. Recompute that row's `row_hash`.
3. Update all subsequent rows' `prev_hash` + `row_hash` values.
4. Produce a chain that validates again.

**What tamper-evidence provides:**
- An attacker with only read access cannot forge a valid chain (SHA-256 preimage resistance).
- An attacker who modifies rows but does not rebuild the chain produces a detectable break.
- `validate_chain()` detects any unrepaired tampering in O(n) time.
- Rapid detection: if chain validation runs frequently (e.g., scheduled job), the window between tampering and detection is bounded.

**Tail-truncation undetectability (deferred — F-035):**
Sentinel's hash chain is tamper-evident for in-row modifications and reordering, but **cannot detect truncation of trailing rows** without external attestation. If an attacker with full DB access deletes the last N rows, `validate_chain()` will report the chain as valid (it validates what it can see). F-035 will introduce immutable storage replication (S3 Object Lock or equivalent Write-Once ledger) that closes this gap by periodically exporting chain tips to an external store that cannot be modified by DB-level access.

**Planned defenses (deferred):**
- External WORM attestation: periodic export of chain tip to an immutable external store (S3 Object Lock, Write-Once ledger). Closes tail-truncation gap.
- Audit log shipping to immutable storage (CloudTrail-equivalent).
- Advanced chain-break threat detection and alerting.

---

## Deferred to Future Tasks

| Item | Task |
|------|------|
| sentinel_app role + strict RLS + two session types + app-layer tenant scoping | F-003b (MUST merge before F-004) |
| Cryptographic signature verification of policy JWS | F-008 |
| Scope-resolve-and-reject obligation for policy cross-tenant poisoning | F-008 |
| External WORM replication of audit log chain tips (tail-truncation gap) | F-035 |
| Audit log shipping to immutable storage | Future |
| Advanced chain-break threat detection | Future |
| provider_key_refs table (Vault path references only) | Future |
| pii_policies, pii_policy_versions, compliance_controls, compliance_evidence | Future |
| bulk_jobs, bulk_job_files tables | F-bulk |

---

## Migration Tooling

**Tool:** Alembic 1.13+ with hand-written migration files (not autogenerate). Hand-written migrations are preferred for security-sensitive DDL (triggers, RLS, CHECK constraints) where autogenerate may produce incorrect or incomplete SQL.

**Migration chain (F-003 head = 0005):**
```
0001_initial_schema -> 0002_rbac -> 0003_virtual_api_keys -> 0004_policies -> 0005_events_audit_log
```

**Driver split:**
- Migrations (Alembic `env.py`): psycopg (sync) — Alembic requires a sync connection.
- Application repositories: asyncpg via SQLAlchemy async engine.

**No destructive migration** (DROP TABLE without prior ADR + human sign-off). Every migration has a correct `downgrade()` that reverses all DDL.

---

## Summary of Decisions

| Decision | Choice | Primary Rationale |
|----------|--------|-------------------|
| Database engine | PostgreSQL 16 | RLS, triggers, ACID, ecosystem |
| ID column type | VARCHAR(64) all four IDs | Consistency, server-generated |
| Password hashing | Argon2id (argon2-cffi) | OWASP-recommended, memory-hard |
| API key storage | HMAC-SHA256 fingerprint only | No plaintext, no decryption path |
| Tenant isolation (F-003) | Schema present; enforcement deferred to F-003b | F-003 ships schema + repo layer only |
| Tenant isolation (F-003b) | Postgres RLS FORCE + app-role + GUC session | DB-layer + app-layer defense-in-depth |
| Session type (F-003) | Single get_async_session(), no GUC, no role switch | Scoped to F-003 deliverable |
| Policy history | Full version table + trigger | Monotonicity + full history preserved |
| Audit log design | Single table, nullable variants | Simple chain ordering, strict columns |
| Hash algorithm | SHA-256 | Standard, widely supported |
| Canonical JSON | sort_keys=True + no whitespace + UTF-8 | Deterministic, language-agnostic |
| Genesis hash | SHA-256("anoryx-sentinel:events:genesis:v1"), single source in hash_chain.py | Reproducible, documented, no string literal duplication |
| Concurrent insert safety | Advisory lock (named constant) | Simple, effective, auto-released |
| Tamper-evidence claim | Tamper-evident (not tamper-proof) | Honest language per CLAUDE.md |
| Tail-truncation gap | Acknowledged, deferred to F-035 | Honest language per CLAUDE.md |
