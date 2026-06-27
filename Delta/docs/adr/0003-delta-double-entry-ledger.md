# ADR-0003 — Delta Double-Entry Ledger (durable persistence)

- **Status:** Proposed (awaiting Affu approval)
- **Date:** 2026-06-26
- **Task:** D-003 (third Delta task; first Delta DDL / migrations / RLS roles)
- **Scope:** The authoritative, durable, append-only double-entry **ledger** —
  Postgres schema, RLS isolation, atomic balanced-transaction writes, append-only +
  reversal, and the balance / time-window **read primitives** later Delta tasks consume.
- **Depends on:** shipped D-001 (`ADR-0001`, financial domain model: `Account`,
  `LedgerEntry`, `Transaction`, the balanced-entry invariant, integer-cents `Money`).
  Mirrors the shipped F-003b RLS pattern (`Anoryx-Sentinel` ADR-0005) and the F-010
  SCRAM role-provisioning fix (Sentinel ADR-0012).
- **Numbering:** Delta-scoped sequence — this is Delta ADR **0003** (0001 = D-001 domain
  model, 0002 = D-002 budget policy). Delta does not extend Sentinel's global sequence.

---

## Context

D-001 fixed Delta's financial **vocabulary** and integrity **invariants** as Pydantic v2
types, and deliberately shipped **no DDL** — ADR-0001 Fork 5 deferred the authoritative
ledger schema here and states plainly: *"enforcement lives in **D-003**."* Today the
balanced-entry invariant (`Σdebit == Σcredit`, single currency, single tenant) is enforced
**only** in a Pydantic `@model_validator`. That is a real but narrow guarantee: Pydantic's
`model_construct()` skips it, and **any direct SQL `INSERT` bypasses it entirely** because
there is no ledger table yet.

D-003 makes the model real and **flips the honesty boundary**: the **database itself**
becomes the authority that enforces ledger correctness, not the application. This is the
ecosystem's defining loop made durable:

```
Sentinel → (usage/cost events) → Anoryx-AI-Orchestrator → Delta   (D-004 ingest writes here)
Delta → (budget policies) → Anoryx-AI-Orchestrator → (enforcement) → Sentinel
```

The budget loop cannot run until cost is **recorded** somewhere sound. D-003 is that
store: a high-throughput, append-only, double-entry ledger with sub-second commit under
concurrent load, RLS tenant isolation, atomic reversible entries, and the read primitives
(point-in-time + windowed balance) that the budget engine (D-005) and dashboards (D-008)
derive from.

D-003 is the **first Delta task that ships real DDL, Alembic migrations, and RLS roles.**
Ledger correctness is non-negotiable: a financial ledger that can commit an unbalanced,
mutable, or cross-tenant state is worse than no ledger. The decisions below are therefore
biased toward enforcement living at the **data layer**, where neither an application bug
nor a direct SQL path can bypass it.

---

## Decision

### Fork 1 — Double-entry enforcement: **(a) DB-enforced (deferred constraint trigger)**

"`debits = credits`" is enforced by the **database**, so it cannot be bypassed by an
application bug, a `model_construct()` escape hatch, or a direct `INSERT`.

A `CONSTRAINT TRIGGER ... DEFERRABLE INITIALLY DEFERRED` on `delta.ledger_entries` fires at
**COMMIT**. For each `txn_id` touched in the transaction it re-aggregates the **full** set
of that transaction's entries (including any previously committed) and rejects unless:

1. `SUM(signed minor_units) = 0` — debits net credits exactly (signed: debit `+`, credit `−`),
2. `COUNT(*) ≥ 2` — a real double-entry, not a single dangling leg,
3. exactly one `currency` across the entry set (no silent cross-currency netting),
4. exactly one `tenant_id`, equal to the parent `delta.transactions.tenant_id`.

Any violation → `RAISE EXCEPTION`, which aborts the COMMIT. The append API writes a whole
balanced transaction (the `transactions` row + all its `ledger_entries`) in **one** DB
transaction; the deferred check validates the complete set at the end.

**Why deferred, and why it is non-bypassable.** A non-deferred per-row check could never
admit a balanced multi-row transaction (the first row alone is unbalanced). Deferring to
COMMIT lets a balanced set commit while still rejecting an unbalanced one. Because the
trigger re-sums **all** entries for the touched `txn_id`, it also rejects a direct
single-row `INSERT INTO delta.ledger_entries` committed alone — the parent txn's set no
longer nets to zero, so the COMMIT aborts. Correctness is a property of the data, not of
any code path that reaches it.

**Closing the balanced-amendment hole.** The deferred SUM=0 check alone does *not* stop a
later transaction from appending a **balanced pair** (e.g. +100 debit / −100 credit) to an
*already-committed* `txn_id`: the re-sum stays zero, so the amendment would slip through
and silently mutate a committed transaction's entry set. A second guard closes this — a
**`BEFORE INSERT` trigger** (`assert_entry_in_txn_creation`) requires every entry to be
inserted in the **same DB transaction that created its parent `transactions` row**, by
comparing the parent row's `xmin` (a 32-bit xid, cast to `bigint`) to `txid_current()`
masked to its low 32 bits (`txid_current() & 4294967295`). The mask is the epoch-safe
form — a naïve `txid_current()::text::xid` raises once the xid epoch ≥ 1, so it is avoided.
A legitimate append (txn row + entries in one transaction) passes; any later amendment —
balanced or not — is rejected at INSERT. Together with the append-only guard below, a
committed transaction's entry set is genuinely immutable (vector 4b).

```sql
CREATE CONSTRAINT TRIGGER trg_le_balanced
  AFTER INSERT ON delta.ledger_entries
  DEFERRABLE INITIALLY DEFERRED
  FOR EACH ROW EXECUTE FUNCTION delta.assert_txn_balanced();
-- delta.assert_txn_balanced(): per NEW.txn_id, re-aggregate ALL entries; verify
-- SUM(signed)=0, count>=2, one currency, one tenant == parent txn tenant; else RAISE.
```

Rejected alternatives: **(b) application-layer only** — a direct `INSERT` or any app bug
commits an unbalanced txn; unacceptable for a financial ledger. **(c) stored-procedure-only
writes** — strong, but moves the invariant into a plpgsql function that callers must be
forced through (still needs grants/triggers to block direct INSERT), and is heavier to
version and unit-test than a single constraint trigger that is *always* on regardless of
write path.

### Fork 2 — Redis: **(b) no Redis in D-003**

Postgres is the sole write authority. Balances and burn-rate are derived by indexed `SUM`
over the append-only entries (Fork 3), which meets the sub-second bar at expected volume.
No cache is introduced now. A read-through cache (option a, Postgres-authoritative,
invalidated on append) can be added later **only if** reads measurably miss the bar; a
Redis **write-buffer** (option c) is rejected outright because an ack'd write not yet in
Postgres is a durability gap — an ack'd write must always be in Postgres first. Choosing
(b) eliminates an entire class of staleness/durability findings for this task.

### Fork 3 — Balance computation: **pure derivation**

A balance is `SUM` over the append-only entries, never a stored running-balance column.
Point-in-time = `WHERE timestamp <= t`; windowed = `WHERE timestamp >= start AND < end`
(half-open, matching D-001 `burn_rate`). The sign of each entry is `direction × account
normal-balance` (debit increases an asset/expense, credit increases a
liability/equity/revenue — classical double-entry). A derivation is always correct under
concurrency (it reads a single MVCC snapshot) and cannot desync from the source of truth;
a maintained running-balance column would add row-level locking and a lost-update
correctness risk on concurrent appends for a read-speed gain we do not yet need.

### Fork 4 — DB topology: **separate `delta` schema + `delta_app` RLS role**

All ledger DDL is **schema-qualified** into a `delta` schema, served by a `delta_app`
NOBYPASSRLS role. The same migration runs unchanged whether Delta uses its **own** Postgres
(local dev / CI) or **shares** Sentinel's Postgres *instance* in production (a different
schema in the same cluster). **Wiring nuance:** the shared Postgres service lives in
`Anoryx-Sentinel/docker-compose.yml`, which the cross-project protect-paths hook forbids
Delta from editing. So D-003 ships its **own** `Delta/docker-compose.yml` + entrypoint
(own Postgres, for the local/CI fresh-compose-up path); production points Delta at the
shared instance's `delta` schema with no code change. This honours both the "separate
schema, one Postgres" recommendation and the cross-project write boundary.

### Fork 5 — Idempotency: **UNIQUE (tenant_id, idempotency_key) now**

`delta.transactions` carries a nullable `idempotency_key`, with a **partial** unique index
`(tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL`. A replayed event that
reuses a key is rejected at the ledger (one replayed event = exactly one debit). D-004's
event ingest depends on this; it is cheap to add now and expensive to retrofit once ingest
exists. Transactions written without a key (e.g. manual adjustments) are unaffected.

### Fork 6 — CI load posture: **deterministic correctness-under-concurrency in CI + local benchmark**

A deterministic **correctness**-under-concurrency test (N concurrent writers; assert the
ledger stays balanced and every balance is correct) runs in CI against a real Postgres
service and **must execute** (it is not allowed to skip). The **p95 < 1s** commit-latency
number is measured by a heavier local/manual benchmark, not asserted in CI — perf
thresholds flake on shared GitHub runners (noisy neighbours) and would produce false reds.

---

## The double-entry enforcement mechanism (central artifact)

The schema (the `delta` schema; integer cents only — **no float / NUMERIC anywhere in the
money path**):

- **`delta.accounts`** — `account_id` PK `VARCHAR(64)`, `tenant_id`, `type` CHECK ∈
  {asset, liability, equity, revenue, expense}, `currency` `CHAR(3)`, `name`. RLS.
- **`delta.transactions`** — `txn_id` PK, `tenant_id`, `currency` `CHAR(3)`, `timestamp`
  `timestamptz`, `description`, `reversal_of` nullable FK → `transactions.txn_id`,
  `idempotency_key` nullable. Partial UNIQUE `(tenant_id, idempotency_key)`. RLS.
- **`delta.ledger_entries`** — `entry_id` PK, `txn_id` FK → `transactions`, `tenant_id`,
  `account_id`, `direction` CHECK ∈ {debit, credit}, `amount_minor_units` `BIGINT`
  CHECK `0 ≤ amount ≤ 100_000_000_000` (the D-001 wire max; integer cents),
  `currency` `CHAR(3)`, `team_id`, `project_id`, `agent_id`, `timestamp` `timestamptz`.
  Indexes `(tenant_id, account_id, timestamp)` (balance scans) and `(txn_id)` (the
  deferred re-sum). RLS.

The deferred balanced-constraint trigger (Fork 1) is the load-bearing integrity gate. The
atomic append API (`ledger_store.append_transaction`) validates the candidate against the
D-001 `Transaction` Pydantic type (catching obvious imbalance early with a legible error),
then writes the `transactions` row and all `ledger_entries` in a single DB transaction; the
deferred trigger is the **authority** that admits or rejects at COMMIT. The Pydantic check
is a convenience, not the guarantee — the guarantee is the DB.

Money is stored as `BIGINT` integer cents. There is deliberately **no floating-point or
`NUMERIC` column** in the ledger money path, so the float-smuggling vector D-001 guards in
Pydantic is also structurally impossible at the DB layer.

---

## RLS + role-provisioning design (the part to scrutinise — F-010 SCRAM lesson applied)

This is the highest-risk surface and the one the F-010 migration-0006 post-mortem warns
about. The design copies the **proven** Sentinel mechanism exactly.

**Two roles, two URLs** (mirror of `Anoryx-Sentinel/src/persistence/database.py`):
`DATABASE_URL` = the privileged owner role (BYPASSRLS) used for migrations and admin /
break-glass only; `APP_DATABASE_URL` = the `delta_app` role
(`LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE`) used for **all** tenant traffic.
`get_tenant_session(tenant_id)` **autobegins** and sets the transaction-local GUC
`set_config('app.current_tenant_id', tenant_id, true)` before any query; it is fail-closed
(raises before opening a transaction if `tenant_id` is empty/whitespace). Reads run on the
autobegun transaction — **never** wrapped in `session.begin()` (that is the F-007
double-begin class, ADR-0026).

**RLS on every tenant-scoped table:** `ENABLE` + `FORCE ROW LEVEL SECURITY`, with the
strict NULLIF predicate (USING **and** WITH CHECK):

```sql
tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')
```

Unsatisfiable when the GUC is unset or empty (`NULLIF('', '')` → `NULL`; `tenant_id = NULL`
is `UNKNOWN`), so a missing or mid-transaction-cleared context yields **zero rows**, never
cross-tenant access. `FORCE` makes the policy apply even to the table owner, and `delta_app`
is `NOBYPASSRLS` so the application cannot bypass it regardless of query correctness.

**The SCRAM landmine and its fix.** Migration `0001_ledger_schema` creates `delta_app` via
an idempotent `DO`-block with **NO password in SQL** (the secrets rule — a credential must
never appear in a migration). A passwordless `LOGIN` role cannot authenticate over a
SCRAM-SHA-256 `APP_DATABASE_URL`, so on a fresh `compose up` **every tenant connection would
fail** — the exact migration-0006 defect that broke F-010 until the entrypoint fix. D-003
applies that fix: `Delta/docker-entrypoint.sh`, gated by `DELTA_PROVISION_APP_ROLE=1`, runs
**after** `alembic upgrade head`, extracts the plaintext from `APP_DATABASE_URL`, computes
the SCRAM-SHA-256 verifier **client-side**, and runs `ALTER ROLE delta_app WITH LOGIN
PASSWORD '<verifier>'` over the privileged connection. The plaintext is never a SQL literal
(only the opaque verifier is interpolated) and is never logged. The provision is idempotent
(`ALTER ROLE` is always safe to re-run). The same routine runs per-test in the persistence
conftest (loud `pytest.fail` on any provisioning error — never a silent swallow), and a
self-check logs in as `delta_app` with the plaintext to prove authentication works before
any test runs.

**Fresh-`compose up` authentication path (verified testable):**

```
clean volume → postgres healthy
 → entrypoint: alembic upgrade head   (delta schema, tables, RLS policies,
                                        delta_app role *passwordless*, append-only triggers,
                                        deferred balanced constraint, idempotency index)
 → entrypoint: DELTA_PROVISION_APP_ROLE=1 → ALTER ROLE delta_app WITH PASSWORD '<verifier>'
 → delta_app (APP_DATABASE_URL, NOBYPASSRLS) connection AUTHENTICATES
 → get_tenant_session(tenant_id) sets app.current_tenant_id
 → a real balanced Transaction commits, governed by RLS
```

STEP-10 runs this on a clean volume and asserts the delta_app tenant connection
authenticates and commits a balanced txn under RLS — the precise F-010 failure mode, now a
green test.

---

## Append-only + reversal-as-compensating-transaction (no UPDATE / DELETE, ever)

The ledger is **append-only**, mirroring the F-003 `events_audit_log` (migration 0005).
Triple-layered, per table (`transactions`, `ledger_entries`):

1. A `deny_ledger_modification()` plpgsql trigger on `BEFORE UPDATE` and `BEFORE DELETE`
   that always `RAISE EXCEPTION`.
2. RLS policies `USING (false)` for UPDATE and DELETE (no row is ever eligible).
3. `delta_app` is granted only `SELECT` + `INSERT` on the two append-only tables —
   **never** `UPDATE` or `DELETE`.

A correction is **never** a mutation. A reversal is a **new, separate, balanced
compensating transaction** whose `reversal_of` points at the original `txn_id` and whose
entries swap debit↔credit for the same amounts. The original transaction is left exactly as
written; the ledger remains balanced after the reversal (the compensating txn is itself
balanced, and a balanced set plus a balanced set is balanced). This is the same
append-only foundation D-009 will hash-chain — but D-003 ships **only** the append-only
property; the tamper-evident hash-chain is explicitly D-009's, not ours.

---

## Concurrency / isolation argument (no torn or unbalanced committed state)

`READ COMMITTED` (Postgres default) is sufficient, and the argument is structural:

- **Each append is self-contained.** A transaction's balance depends only on its own
  entries. Two concurrent appends to **different** `txn_id`s never interfere; the deferred
  trigger validates each `txn_id`'s set independently at its own COMMIT. There is no
  shared mutable aggregate (no running-balance column — Fork 3) for them to race on.
- **No torn / unbalanced intermediate is ever committed.** The whole transaction (txn row
  + all entries) is written in one DB transaction; the deferred check runs at COMMIT. A
  crash or rollback before COMMIT leaves nothing; a COMMIT only succeeds if the set
  balances. Other sessions never observe a partially-written transaction (MVCC isolates
  uncommitted rows).
- **No lost update.** Balances are derivations over committed rows on a single snapshot, so
  there is no read-modify-write of a balance to lose. The only contended write is the
  idempotency unique index, which Postgres serialises (the second concurrent insert of the
  same `(tenant_id, idempotency_key)` raises a unique violation — exactly one debit wins).
- **Reversal** is just another balanced append; it cannot create an unbalanced state.

STEP-10's N-writer concurrency test proves the committed ledger is balanced and every
balance is correct after concurrent load; the local benchmark records p95 commit latency.

---

## Performance target + how it is proven

Target: **p95 commit latency < 1s** for an atomic balanced-transaction append under
concurrent load. Proven by a local/manual benchmark (N concurrent writers, measure the
commit-latency distribution, record p95). The deferred constraint adds one indexed re-sum
per touched `txn_id` at COMMIT — `O(entries-in-txn)` on the `(txn_id)` index, negligible
for the ≤1024-entry transactions D-001 bounds. Balance reads are indexed `SUM`s on
`(tenant_id, account_id, timestamp)`. CI runs the **correctness** half (Fork 6); the perf
number is recorded out of CI to avoid runner-noise false reds.

---

## DB topology + migration chain

Delta owns its own Alembic chain, rooted at `0001_ledger_schema` (Delta-scoped, like its
ADRs — it does not extend Sentinel's chain). The single migration creates the `delta`
schema, the three tables, all RLS policies, the `delta_app` role (passwordless), the
append-only triggers, the deferred balanced-constraint trigger + function, and the
idempotency index. `downgrade()` reverses **every** object in dependency order (triggers →
functions → policies → role-if-unowned → tables → schema) and never touches tenant data;
the role is dropped only if it owns no objects (the Sentinel guard). Reversibility is proven
by an upgrade→downgrade→upgrade round-trip on a **fresh** DB (drop the schema and rebuild —
not `downgrade base`, which is a different starting state).

---

## Honesty boundary (mandatory)

D-003 ships the **ledger persistence and its read primitives only**. It does **not** ingest
events (**D-004**), enforce a budget (**D-005**), render dashboards (**D-008**), or
hash-chain the ledger (**D-009** — append-only is its foundation, but the tamper-evident
chain is D-009's). Monetary figures recorded here are *client-side cost estimates* sourced
from Sentinel, never authoritative bills. The integrity guarantees here are **risk
reduction through structural correctness** (balanced, append-only, tenant-isolated,
idempotent), not a guarantee of the financial correctness of upstream inputs.

---

## Threat model (12 integrity vectors, with test paths)

| # | Vector | Defense | Test |
|---|---|---|---|
| 1 | **Cross-tenant read** — `delta_app` reads another tenant's rows | RLS NULLIF predicate (USING); `delta_app` NOBYPASSRLS | `test_isolation.py` (A cannot see B) |
| 2 | **Cross-tenant write** — insert a row with a foreign `tenant_id` | RLS WITH CHECK rejects it | `test_isolation.py` |
| 3 | **Fresh-DB tenant auth fails** (migration-0006 mode) | entrypoint provisions `delta_app` SCRAM password post-migrate | `test_fresh_compose_up` |
| 4 | **Single unbalanced INSERT** committed directly | deferred balanced constraint RAISEs at COMMIT | `test_balanced_constraint.py` (non-stubbed) |
| 5 | **Atomicity** — a partial txn (entries without parent, or vice-versa) | FK + single-transaction append + deferred check | `test_atomic_append.py` |
| 6 | **Unbalanced multi-entry txn** | deferred `SUM=0` check | `test_balanced_constraint.py` |
| 4b | **Balanced amendment of a committed txn** — append a balanced pair to an already-committed `txn_id` (deferred SUM stays 0) | `BEFORE INSERT` trigger: entry's parent txn `xmin` must equal `txid_current()` (same DB transaction) | `test_append_only.py` (blocked) |
| 7 | **UPDATE a committed entry** | BEFORE UPDATE trigger + RLS USING(false) + no grant | `test_append_only.py` (blocked) |
| 8 | **DELETE a committed entry** | BEFORE DELETE trigger + RLS USING(false) + no grant | `test_append_only.py` (blocked) |
| 9 | **Reversal correctness** | reversal = new balanced compensating txn (`reversal_of`); original untouched; ledger still balances | `test_reversal.py` |
| 10 | **Double-debit via replay** | partial UNIQUE `(tenant_id, idempotency_key)` | `test_idempotency.py` (exactly one debit) |
| 11 | **Torn write under concurrency** | atomic per-txn append; deferred check; MVCC | `test_concurrency.py` |
| 12 | **Lost update / wrong balance under concurrency** | derivation (no running-balance column); snapshot `SUM` | `test_concurrency.py` (N writers → balanced + correct) |

(Float-smuggling — a money field accepting a float — is closed by the D-001 `Money`
validator **and** the BIGINT-only money columns; no float/NUMERIC type exists in the ledger
schema. Covered structurally, not a runtime vector here.)

---

## Consequences

**Positive:** the balanced invariant is enforced by the database (non-bypassable by app
bug, `model_construct`, or direct SQL); append-only + reversal give a correct, auditable
history with no destructive path; RLS gives tenant isolation that the application cannot
bypass; integer-cents-only money is exact; idempotency is ready for D-004; balances are
always-correct derivations; the F-010 SCRAM fix is applied so a fresh `compose up`
authenticates. Smallest durable surface that makes the budget loop real.

**Negative / accepted:** the deferred constraint adds one indexed re-sum per txn at COMMIT
(negligible at D-001's transaction sizes); no read cache yet (Fork 2b — added only if
measured); no running-balance column, so very large windowed reads scan more rows (indexed;
revisit with a materialised rollup in a later task if needed); Delta runs its own Postgres
in local/CI (own compose), co-locating in the shared instance is a prod deployment choice.

**Security-audit residual notes (all Low, accepted):** (L-3) a stolen `delta_app`
credential can `set_config('app.current_tenant_id', …)` to any tenant — this is the
inherited F-003b boundary: RLS defends against application bugs and pooled-connection
leakage, **not** against credential theft; the tenant_id must come from an authenticated
source and is treated as a tenant-spanning secret (load-bearing in D-004). (L-4) a
transaction can be reversed more than once unless the caller passes an `idempotency_key`;
the ledger stays balanced either way, and reversal **deduplication is a posting-semantics
policy deferred to D-004/D-005**. (L-1/L-2 were fixed: the immutability trigger's xid
comparison is now epoch-safe, and the deferred trigger rejects entries whose currency
differs from their transaction's currency.)

**Out of scope (explicit):** event ingest (D-004), budget enforcement engine (D-005),
dashboards (D-008), hash-chained financial audit trail (D-009), pricing tables,
multi-currency / FX, organisational hierarchy. **Account referential integrity** is also
deferred: `ledger_entries.account_id` is **not** FK-constrained to `delta.accounts`. A
Sentinel event carries no `account_id` (only the four stable IDs), so deciding *which*
accounts a cost posts to — and managing the chart-of-accounts lifecycle — is the posting
layer's policy (D-004 ingest / D-005), which will own that integrity. The D-003 ledger
primitive accepts any well-formed `account_id`; the balanced/append-only/tenant-isolated
guarantees are independent of whether an `account_id` names a registered account.

---

## Rollback

D-003 is additive within `Delta/`: new `Delta/src/delta/persistence/` package, one Alembic
migration, deploy files (`Dockerfile`, `docker-compose.yml`, `docker-entrypoint.sh`,
`.env.example`), tests, this ADR + the audit doc, and edits to `Delta/pyproject.toml` and
`.github/workflows/delta-ci.yml`. It touches no Sentinel code and no other product.
Rollback at the schema level = `alembic downgrade` (reverses every object, never touches
data). Rollback at the source level = revert the single squashed D-003 commit. Nothing else
in the monorepo depends on the `delta` schema yet (D-004/D-005 are not built), so revert is
clean and total.
