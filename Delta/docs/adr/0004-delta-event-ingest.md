# ADR-0004 — Delta Event Ingest from the Orchestrator (consume + posting)

- **Status:** Proposed (awaiting Affu approval)
- **Task:** D-004 — Delta Event Ingest. Builder: orchestration-hooks. Risk: Medium.
- **Builds on:** D-003 double-entry ledger (#39), D-001 domain model (#30),
  O-003 Orchestrator ingest pipeline (#37), O-001 internal API contract (#28),
  O-002 event-bus contract (#35).
- **Delta-scoped numbering:** this is Delta ADR **0004** (0001 = domain model,
  0002 = budget policy, 0003 = double-entry ledger). Delta does not extend
  Sentinel's or the Orchestrator's global ADR sequence.

---

## 1. Context

The Anoryx FinOps loop is `Sentinel → (usage events) → Orchestrator → Delta →
(ledger)`. D-003 shipped the balanced double-entry ledger. D-004 makes the
**consume** side real: a Sentinel `usage` event, carried via the Orchestrator,
becomes an **idempotent, balanced double-entry debit** in the ledger. A replayed
event must produce **exactly one** debit; an event carrying tenant A's identity
must **never** post into tenant B's ledger.

**Scope is consume + posting ONLY.** Budget enforcement is D-005, the kill-switch
is D-006, dashboards are D-008. D-004 reads usage and records spend; it makes no
policy decision and blocks nothing.

### 1.1 The CONFIRM finding that shaped this ADR

D-004's design began with a gating check: does the Orchestrator actually expose a
Delta-consumable seam that is implemented and runnable? **It does not.** The
shipped Orchestrator app (`Anoryx-AI-Orchestrator/src/orchestrator/app.py`) mounts
only `POST /v1/ingest/events` (inbound, Sentinel→Orchestrator) and `GET /health`.
The contracted Delta read seam, `GET /v1/events` (O-001 Seam #3), is:

1. **Unregistered** — deferred to a later "O-006" task (`app.py:8-11` docstring);
   it is contract-only (`Anoryx-AI-Orchestrator/contracts/openapi.yaml:14-17`).
2. **Structurally insufficient even once implemented** — it is deliberately
   metadata-only and "does not return full event payloads" (O-001 honesty boundary
   (c), `openapi.yaml:61-63`). It carries no `cost_estimate_cents`. A financial
   debit cannot be built from it.

There is no event-bus producer, no Redis Stream, no webhook-out, no push-to-Delta
anywhere in the Orchestrator runtime. Ingested events ARE durably persisted
(`ingest_events`, full payload JSONB, `idempotency_key == payload.event_id`) and an
accept writes a `forward_outbox` row recording forward-**intent** — but that outbox
has no consumer or dispatcher (`forward_outbox.py:1-6`: "forwards nothing"; O-005
owns the unbuilt routing).

The producer interface D-004 needs does not exist. This was surfaced as a
dependency blocker. **The accepted resolution (Affu) is scope C: D-004 also builds
the missing consume seam** — a minimal Orchestrator→Delta push dispatcher — so the
loop becomes a real runtime path. The protect-paths hook permits the cross-project
write (it performs no subproject scoping); both `delta-ci` and `orchestrator-ci`
fire on a `→main` PR touching both trees, so the seam is exercised by real CI, not
a stub.

### 1.2 Honesty boundary

- The Orchestrator dispatcher built here is a **minimal seam to make the loop
  runnable**, not the full O-005 distribution engine (no registry, no
  KEDA-scaled worker pool, no multi-subscriber fan-out).
- Cost is Sentinel's **client-side cost estimate** (`cost_estimate_cents`), never
  an authoritative bill. Delta **records** it and does **not** recompute pricing
  (D-001 Fork 3).
- No enforcement, no kill-switch, no dashboards.

---

## 2. Decision summary (forks)

| Fork | Decision | One-line rationale |
|------|----------|--------------------|
| Scope | **C — build the seam** | The producer seam does not exist; building a minimal one makes the loop real and CI-testable. Cross-project against unenforced `CLAUDE.md:16-18` intent; Affu-approved. |
| 2 — transport | **Push** (outbox dispatcher → Delta inbound) | Reuses `forward_outbox` (built for exactly this) + the proven inbound HMAC pattern in the outbound direction; carries full payload incl cost natively; no metadata-only-contract amendment. |
| 1 — account FK | **(a) same-tenant FK + chart-of-accounts now** | Closes D-003's deferred HIGH#2 before any posting volume; cross-tenant/dangling account refs become impossible at the DB. |
| 3 — posting model | **two-leg** (DEBIT expense, CREDIT contra) | Minimal balanced transaction matching D-003's invariant. |
| 4 — idempotency key | **Sentinel `event_id`** | UUID, schema-labeled "dedup key on the bus"; the ledger's partial-UNIQUE `(tenant_id, idempotency_key)` enforces exactly-once. |
| 5 — unmappable | **dead-letter + bounded retry** | Financial events must be auditable; never silently dropped. |
| 6 — dispatch-state | **push: outbox owns it** | `forward_outbox` row flips to `forwarded` only on a verified 2xx ack; no Delta cursor. |

---

## 3. The consume seam (Fork 2 = push) + auth

### 3.1 Producer — minimal Orchestrator dispatcher

A single-pass drain (`dispatch_pending(limit)`), **not** a long-running daemon, so
it is deterministically testable in CI:

1. Via the Orchestrator **privileged** (owner / `BYPASSRLS`) session
   (`get_privileged_session()`), select `forward_outbox` rows with `status='pending'`
   **across all tenants**, oldest first. `forward_outbox` is `FORCE ROW LEVEL SECURITY`
   and the `orchestrator_app` role has no `UPDATE` grant on it, so only the owner can
   read and transition these rows. The RLS bypass is **intentional and correct here**:
   this is a single GLOBAL forwarder draining one cross-tenant outbox, not per-tenant
   request traffic (which always runs on the NOBYPASSRLS tenant session). The tenant a
   given row posts under is still carried by the row's payload, not the session.
2. Join `ingest_events` on `idempotency_key`/`event_id` to obtain the full envelope
   (`payload` JSONB, which carries the `UsageEvent` incl `cost_estimate_cents`).
3. HMAC-sign and `POST` the envelope to the Delta inbound endpoint.
4. On a verified **2xx ack** → set `status='forwarded'` (dispatch-state, Fork 6).
   On a **transient** failure → bump `attempt_count`, leave `pending` (retried next
   drain). On a **permanent** failure or `attempt_count` exhaustion → `status='failed'`.

This consumes the rows `forward_outbox` was explicitly built to feed
(`forward_outbox.py:1-6`). Because the drain is a global cross-tenant forwarder, it runs
on the privileged owner session by design; tenant isolation on the WRITE side is enforced
by Delta (the consumer derives its RLS context from the validated payload `tenant_id`).

### 3.2 Consumer — Delta's first runtime app

A new FastAPI app exposes `POST /v1/ingest/usage`. Pipeline:

1. **HMAC verify** → reject forged/unauthenticated (§3.3).
2. **Structural validate** the body against the envelope / `UsageEvent` shape;
   malformed → 422. Select strictly on `event_type == "usage"` (the `UsageEvent`
   variant; `JudgeBillingEvent` also carries `cost_estimate_cents` but is a distinct
   event and is **not** ingested as usage).
3. **Quantize cost** — the wire `cost_estimate_cents` is a JSON `number`; convert to
   integer cents via `delta.money.Money.from_wire_cents()` (ROUND_HALF_EVEN, the only
   sanctioned float→int seam; rejects non-finite and negative).
4. **Resolve accounts** (§5) and **build a balanced two-leg `Transaction`** (§4).
5. **Post** via `append_transaction(get_tenant_session(tenant_id), txn,
   idempotency_key=event_id)` (§6).
6. **Unmappable** → dead-letter (§7).

### 3.3 Auth (mirrors the inbound HMAC pattern; mTLS deferred)

The Orchestrator→Delta channel is authenticated with **HMAC-SHA256** over
`"{timestamp}.{raw_body}"`, headers `X-Orchestrator-Signature: sha256=<hex>` and
`X-Orchestrator-Timestamp`, with a shared secret env `DELTA_INGEST_HMAC_SECRET`
(fail-loud at startup, never logged), a ±300 s replay window, and a constant-time
comparison. This is the inbound `hmac_verify.py` pattern (F-020 signer lineage)
applied in the outbound direction. mTLS is deferred to a later infra task (O-008),
consistent with the existing inbound seam; until then the HMAC secret-holder is the
peer authenticator. A request that fails HMAC verification is rejected with **401**
and never reaches the ledger.

---

## 4. Double-entry posting model (Fork 3 = two-leg) — central artifact

Each `usage` event maps to **one balanced transaction with exactly two entries**:

```
Transaction(tenant_id = E.tenant_id, idempotency_key = E.event_id):
  DEBIT   account = <tenant cost-center EXPENSE account>   amount = cost_cents
  CREDIT  account = <tenant SPEND-CLEARING CONTRA account> amount = cost_cents
```

- **Why a debit to expense, credit to contra:** AI spend is an expense; the
  offsetting credit lands in a spend-clearing **contra** account (a liability/clearing
  node) that a later budget/settlement layer (D-005+) reconciles. The two legs are
  equal and opposite, so `Σdebit == Σcredit` by construction.
- **Both legs are same-tenant, single-currency** (the event's currency, default USD).
  The D-001 `Transaction` validator and the D-003 DEFERRABLE balanced-constraint
  trigger (`trg_le_balanced`) independently re-check `count>=2`, single tenant,
  single currency, and `Σdebit==Σcredit` at COMMIT. D-004 constructs the transaction
  balanced; the DB is the authority.
- **Integer cents only.** Amounts are `Money.minor_units: int`; floats are forbidden
  everywhere except the single `from_wire_cents` quantization seam. A negative or
  non-finite wire cost is rejected before any posting.
- A multi-leg split (by token type / model) is **deferred** (YAGNI for ingest).

---

## 5. Account resolution + the same-tenant FK (Fork 1 = a) — closes HIGH#2

D-003 shipped `ledger_entries.account_id` with **no** FK to `accounts`, explicitly
deferring "the event→account posting mapping and the chart-of-accounts lifecycle …
to the posting layer (D-004 ingest)" (`persistence/balances.py:18-21`). D-004 owns
that referential integrity.

### 5.1 Resolution rule (deterministic, same-tenant, payload cannot spoof)

For a given tenant, the two canonical account ids are **derived deterministically**,
never taken from the payload:

```
expense_account_id = uuid5(DELTA_ACCOUNT_NS, f"{tenant_id}:{currency}:expense")
contra_account_id   = uuid5(DELTA_ACCOUNT_NS, f"{tenant_id}:{currency}:spend_clearing")
```

The resolver **get-or-creates** both accounts (one `AccountType.EXPENSE`, one contra)
tenant-scoped on first use, then resolves to them on every subsequent event. Because
the ids are a pure function of the validated `tenant_id` and a fixed role string, a
malicious payload cannot name an arbitrary or cross-tenant account (vector 7). The
account currency is the event currency.

### 5.2 The migration (Delta `0002`, off head `0001`, reversible)

- Add `UNIQUE (tenant_id, account_id)` on `delta.accounts` (the composite FK target;
  `account_id` is already PK, so this is an added composite unique key).
- Add the composite same-tenant FK
  `ledger_entries(tenant_id, account_id) → accounts(tenant_id, account_id)`.
- Downgrade drops the FK then the unique key (round-trip verified on a fresh DB).

With this FK in place, an entry can only reference an account that exists **and**
shares the entry's `tenant_id`. Combined with RLS, a cross-tenant or dangling
account reference is impossible at the database (vectors 1, 7).

---

## 6. Idempotency (Fork 4) — exactly-once under at-least-once delivery

O-002 delivery is at-least-once; consumers must dedupe. D-004 passes the Sentinel
`event_id` (UUID, "dedup key on the bus") as the ledger `idempotency_key`. The D-003
ledger holds a **partial-UNIQUE index** `(tenant_id, idempotency_key)` on
`delta.transactions` and inserts with `ON CONFLICT DO NOTHING`. On a redelivered
event the insert is a no-op: **zero entries written**, the transaction commits
cleanly, and `append_transaction` returns `applied=False, idempotent_replay=True`.
The Delta inbound endpoint maps both the first-write and the replay to a **200
idempotent ack** so the dispatcher marks the outbox row `forwarded` either way.

**Exactly-once guarantee:** the uniqueness is enforced by the database, not by
application logic, and is keyed on `(tenant_id, event_id)`. No code path can write a
second debit for the same `(tenant, event_id)`. A replayed event produces exactly
one debit (vector 2).

---

## 7. Dead-letter + retry (Fork 5)

An event that cannot be posted is never silently dropped. A new Delta
`ingest_dead_letter` table (mirroring the Orchestrator `dead_letter_queue`) records:
`dlq_id`, `tenant_id` (nullable for unknown-tenant rows, written via the privileged
session), `original_payload` JSONB (full event preserved), `reason` (a closed set:
`unknown_tenant`, `invalid_cost`, `unresolvable_account`, `malformed_payload`),
`attempt_count` (bounded), `first_failed_at`, `last_failed_at`. RLS applies when
`tenant_id` is present. Dispatcher retry-exhaustion is audited by the Orchestrator
`forward_outbox` 'failed' row, not a Delta DLQ row — Delta's DLQ holds only events it
received and could not post.

**Transient vs permanent classification:**
- **Transient** — database connectivity (`OperationalError`, `InterfaceError`,
  `OSError` (a down DB raises `ConnectionRefusedError`), `TimeoutError`). The endpoint
  returns **503**; the dispatcher leaves the outbox row `pending` and retries on the
  next drain, bounded by `attempt_count`. A transient failure is NOT dead-lettered
  immediately.
- **Permanent** — unknown tenant, invalid/negative cost, unresolvable account,
  malformed payload. The event is dead-lettered **immediately** and the endpoint
  returns a terminal **4xx** so the dispatcher marks the row `failed` and does not
  retry. This bounds poison-message work (vector 8) — a permanently bad event reaches
  the DLQ at most once and cannot crash-loop the pipeline.

A lost financial event is unauditable, so "drop + log" was rejected (vector 4).

---

## 8. Tenant-isolation argument (the property Affu verifies by hand)

> **An event carrying tenant A cannot post into tenant B's ledger.**

Three independent layers enforce this:

1. **RLS context is derived from the validated payload `tenant_id`**, set via
   `get_tenant_session(tenant_id)` as a transaction-local GUC
   (`app.current_tenant_id`). The payload cannot override the session context; the
   `delta_app` role is NOBYPASSRLS, and every table's RLS predicate is
   `tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')`. An unset
   GUC matches no rows (fail-closed).
2. **The composite same-tenant FK (§5.2)** makes an entry referencing an account of a
   different tenant structurally impossible — the FK target is
   `(tenant_id, account_id)`, both columns.
3. **The D-003 balanced trigger** re-checks at COMMIT that every entry's `tenant_id`
   equals the transaction's `tenant_id`.

> **A replayed event produces exactly one debit.** — see §6: DB-enforced
> partial-UNIQUE `(tenant_id, event_id)`, `ON CONFLICT DO NOTHING`.

---

## 9. Threat model (10 vectors → guard → test path)

| # | Vector | Guard | Test |
|---|--------|-------|------|
| 1 | cross-tenant write (event A → ledger B) | RLS from validated payload + same-tenant FK | e2e: tenant-A-spoofed event blocked from tenant-B ledger |
| 2 | double-debit via replay | `event_id` partial-UNIQUE, `ON CONFLICT DO NOTHING` | e2e: same event ×2 → one debit, `applied=False` on replay |
| 3 | unbalanced posting | two-leg construction + D-003 deferred balance trigger | unit: forced single-leg → trigger RAISE at commit |
| 4 | lost event | dead-letter, never drop | unit: unmappable → row in `ingest_dead_letter` |
| 5 | cost tamper / float | `Money.from_wire_cents` strict, int cents, negative/non-finite rejected | unit: float/negative/NaN cost → reject, no post |
| 6 | seam auth | HMAC verify, reject forged/unauth | e2e: bad/missing signature → 401, no post |
| 7 | account-resolution spoof | deterministic same-tenant `uuid5` ids, FK-guarded | unit: payload-named account ignored; resolver yields tenant ids |
| 8 | poison-message DoS | bounded `attempt_count`, permanent→DLQ immediately | unit: permanent-fail event → one DLQ row, no retry loop |
| 9 | out-of-order / partial batch | per-event atomic transaction | e2e: mid-batch failure → no partial committed, others posted |
| 10 | dispatch-state integrity | outbox→`forwarded` only on verified 2xx ack | unit: non-2xx / unverified ack → row stays `pending`/`failed` |

---

## 10. Rollback + migration reversibility

- **Delta migration `0002`** (FK + unique + `ingest_dead_letter`) is reversible:
  `upgrade → downgrade → upgrade` on a fresh DB (DROP SCHEMA + rebuild, not
  `downgrade base`). Downgrade drops the FK, the composite unique key, and the
  dead-letter table.
- **Orchestrator migration** (adds `attempt_count`, `last_attempt_at`, `last_error`
  to `forward_outbox`) is off Orchestrator head `0001`, reversible, with a **distinct
  revision id** (not blind `0002`) because a concurrent Orchestrator task (O-004) may
  add a sibling migration off `0001`; resolve any multi-head with `alembic merge` /
  `down_revision` rebase at integration.
- The consume seam is additive: disabling the dispatcher (not draining the outbox)
  halts posting without data loss — `forward_outbox` rows simply remain `pending`.

---

## 11. Cross-project & collision notes (scope C)

- Writing `Anoryx-AI-Orchestrator/**` from a Delta task is **mechanically allowed**
  (the protect-paths hook does no subproject scoping) but is **against the documented
  intent** of `CLAUDE.md:16-18`. This is an explicit, Affu-approved exception to
  unblock the FinOps loop; it does not set a precedent for unscoped cross-project work.
- **No new Orchestrator ADR is numbered 0004** — O-004 owns Orchestrator ADR-0004.
  The dispatcher's rationale lives here, in Delta ADR-0004.
- All commits originate from `worktrees/d-004`. Files owned by the live O-004 session
  (policy-distribution engine, its ADR) are not touched.

---

## 12. What D-004 explicitly does NOT do

Budget evaluation/enforcement (D-005), the spend kill-switch (D-006), dashboards
(D-008), pricing/cost recomputation (Sentinel owns cost; Delta records it), the full
O-005 distribution engine (registry, fan-out, autoscaling), and mTLS (O-008). D-004
is the consume + posting seam and nothing more.
