# Follow-up: enforce passive-region write-exclusion (F-022 audit H1)

**Status:** RESOLVED (app-tier enforcement, option 2) — the High is closed; one
lower-priority L2 hardening item remains open (see bottom). **Severity:** High
(security) — remediated. **Owner:** was app-tier design decision; decided below.

---

## Resolution (app-tier fail-closed gate — option 2)

H1 is now **enforced**, not operator-owned. `GatewaySettings` reads
`SENTINEL_REGION_ROLE` (`active` | `passive`; an invalid value fails startup), and
`PassiveRegionGuardMiddleware` (`src/gateway/middleware/region_guard.py`) — the
**outermost** middleware, sitting OUTSIDE the terminal-audit middleware — refuses
every governed / audit-generating request on a `passive` region with **`503`
before any audit row is written**. A passive region therefore cannot append to its
local `events_audit_log` and cannot fork the hash chain or collide on the
replicated sequence PK. Only the audit-exempt k8s probes stay served (so the pod
is promotable on failover); promotion flips the role to `active`.

**Design decision made (resolves the D2 tension in "Options" below).** We took
option 2 (app-tier gate) with the strict posture from option 1: a passive region
serves **no** governed traffic — **including reads**. This deliberately
**supersedes ADR-0028 D2's "passive MAY serve residency-local reads"**, because
the non-bypassable terminal audit writes the chain on *every* governed request
(reads included), so any served read would reintroduce H1. Serving passive reads
safely still needs option 3 (a global audit sequencer), which stays deferred.
ADR-0028 D2 + the Known-limitation section were updated to state this enforced
reality.

**Acceptance criteria (below) — met:**
- `tests/region/test_passive_no_audit_realdb.py` — real Postgres: a governed
  request to a passive region returns 503 and the `events_audit_log` row count is
  unchanged.
- `tests/gateway/test_region_guard.py` — passive refuses governed traffic with no
  audit `append`; probes still served; active still serves + audits (control);
  unset defaults to active; invalid role fails startup.
- The ADR/runbook read-only claim is restored **as an enforced** claim (passive
  serves nothing governed), not the old unenforced one.

Remaining open: only the **L2 identifier-hardening** item (bottom), lower
priority.

---

## Original analysis (retained for context)

**Status (original):** OPEN — escalated to human. **Severity:** High (security).

## The gap
F-022 (multi-region, ADR-0028) ships an active/passive posture where a passive region
is meant to be a read-only replica + failover standby. That read-only posture is
**not enforced** by anything F-022 ships:

- `SENTINEL_REGION_ROLE` is context env only — `GatewaySettings` uses
  `extra="ignore"` and no code reads it.
- There is no DB-role `REVOKE` on `policies` / `policy_versions` / `events_audit_log`
  for the serving `sentinel_app` role on a passive region.
- The passive Service/Ingress still accept and serve traffic.

## Why it matters (concrete failure)
The terminal audit middleware is non-bypassable and appends a row to the **local**
`events_audit_log` on **every** governed request (including reads). `events_audit_log`
is hash-chained (`prev_hash`/`row_hash`) and its `sequence_number` is a **per-database
`bigserial`** (`src/persistence/migrations/versions/0005_events_audit_log.py`).
Postgres **logical replication does not carry sequence values.** So a passive region
that serves even one governed request:

1. **Forks the tamper-evident chain** — the local row chains off the last *replicated*
   `row_hash`, creating a second branch. On failover, that fork becomes the region's
   record of record and `validate_chain()` reports a break **indistinguishable from
   tampering** — defeating the core promise of a security product.
2. **Halts replication** — the locally-consumed `sequence_number` collides with the PK
   the active region later replicates → duplicate-key error stops the subscription
   apply worker (passive then silently enforces a stale policy set).

## Interim mitigation (shipped in the reconciliation PR)
The false "read-only ⇒ cannot fork" guarantee was **removed** from the ConfigMap,
ADR-0028 (D2/D3 + Consequences), `values.yaml`, and `deploy/MULTI-REGION.md`, and
replaced with an explicit operator boundary: **do not route governed / audit-
generating traffic to a passive region** (keep its geo-routing weight at 0; treat it
strictly as a promote-on-failover standby) until enforcement lands. This makes the
posture honest but leaves enforcement to the operator.

## Options for real enforcement (pick one; needs human design)
1. **DB-role read-only on passive** — `ALTER ROLE sentinel_app SET
   default_transaction_read_only = on` (or `REVOKE INSERT/UPDATE/DELETE` on the three
   tables) on passive regions. *Caveat:* the audit middleware writes on every request,
   so this makes a passive region unable to serve **any** governed request
   (fail-closed) — which may be the correct posture, but it contradicts ADR-0028 D2's
   "passive MAY serve residency-local reads." Resolve that tension explicitly.
2. **App-tier role gate** — have the serve/audit-write path read `SENTINEL_REGION_ROLE`
   and refuse to serve governed traffic (or route audit writes appropriately) on a
   passive region. This is the "app-tier residency enforcement" named deferral in
   ADR-0028.
3. **Global audit sequencer** — make cross-region audit a single logical chain (a real
   distributed-systems change; out of scope for a Helm chart and likely for the MVP).

## Related hardening (audit L2, lower priority)
If region config (`publicationName` / `subscriptionName` / `activePrimaryConninfo`)
is ever populated from a self-service / GitOps source rather than a trusted operator,
add identifier-regex validation (`^[a-z_][a-z0-9_]*$`) and SQL `squote` escaping in
`region-replication-configmap.yaml` before those values reach the CONNECTION literal /
identifier positions executed by the bootstrap Job as the Postgres superuser.

## Acceptance criteria for closing this follow-up
- A non-stubbed test proves a passive region **cannot** write `events_audit_log`
  (or cannot serve governed traffic) on the real DB path.
- The ADR/runbook read-only claim is restored **only** once it is enforced.
- Failover promotion is proven to yield a `validate_chain()`-valid single chain.
