# ADR-0024: Advanced Governance UI (F-021)

- Status: Proposed
- Date: 2026-06-25
- Builds on: ADR-0022 (F-019 model-approval policies), ADR-0016 (F-013
  dashboards), ADR-0015 (F-012 admin frontend)
- Supersedes: none

## Context

F-019 shipped a per-tenant model-approval engine: an inventory state machine
(`pending → approved/denied`), operator-only approve/deny endpoints, and a
default-deny enforcement gate in `evaluate_model_policies`. Operators today have
**no UI** — they must call the admin API directly to see a tenant's inventory or
decide a model. There is also **no way to retire** an approved model: once
approved it stays usable indefinitely.

F-021 adds three things on top of the F-019 backend and the F-013 governance
dashboard shell (neither is rebuilt):

1. A per-tenant **model inventory dashboard** (read).
2. The existing **approve/deny operator actions surfaced as UI controls**.
3. A NEW **model-retirement workflow with grace periods** — an operator marks an
   approved model for retirement with a deadline; after the deadline the model is
   denied at the gateway.

The central decision is the retirement architecture: whether "grace period" is
backend-enforced, a UI-only reminder, or a new inventory state.

## Decision

### Fork 1 — retirement architecture: **A (backend-enforced, minimal)**

A nullable `retire_at TIMESTAMPTZ` column is added to the `model_inventory`
**row** (not the policy). Enforcement in `evaluate_model_policies` denies an
approved model once `now > retire_at`, failing CLOSED. The inventory `state`
column is **not** changed — it stays `{pending, approved, denied}`. The UI
derives a "retiring" presentation from `state == approved && retire_at is set`.

Rationale:
- **Honest.** The grace period is actually enforced at the gateway, not a
  cosmetic label. UI option B (UI-only reminder) would imply enforcement the
  backend does not perform — rejected on honesty grounds.
- **Minimal + correct placement.** `retire_at` lives on the per-model inventory
  row, the natural unit an operator retires. It is deliberately **not** put on
  the `model_approval` policy: the policy variant
  (`src/policy/variants/model_approval.py`) already documents that a time-bound
  on the policy is FAIL-OPEN (a malformed stored date silently disables the
  gate). The row-level deadline is read explicitly and checked fail-closed.
- **No state CHECK widen.** Because `state` stays the three F-019 values, the
  F-016 CRIT-2 countermeasure (widen constraint + reversible migration +
  non-stubbed persist FIRST) does **not** apply (option C would have triggered
  it). The only schema change is the additive nullable column.

Enforcement (`src/policy/enforcement.py`, the F-019 seam, lines ~289-298):
the call switches from `get_state` to `get_row`; the existing fail-closed
try/except is kept; and after the `state != "approved"` denial we add:

```
if row.retire_at is not None and now > row.retire_at:
    return ModelDeny(policy_id=approval.policy_id, reason="model_retired")
```

The new `model_retired` reason flows through the existing
`_policy_deny → policy_blocked` 403 seam — no new gateway wiring and no new
error code (mirrors F-016's reuse of `policy_blocked`).

### Audit granularity: **action-only**

Retire / un-retire are audited via the existing `emit_admin_event`
(`event_type`, `target_tenant_id`, `request_id`, `actor_id`, `model`). Migration
0031 widens the event_type set with `model_retirement_scheduled` and
`model_retirement_cancelled`. The grace **deadline is not folded into the audit
event** — it lives on `model_inventory.retire_at` (the enforceable source of
truth, surfaced in the UI). This means **no new hash-folded audit column** and
therefore no 4-site hash-chain wiring, avoiding the F-020 contract-conformance
trap. The audit row records who retired what, in which tenant, and when the
action occurred.

### Fork 2 — API additions

F-019's `GET .../models`, `POST .../approve`, `POST .../deny` cover the read
dashboard and the approval UI as-is. Retirement needs new operator endpoints,
built deliberately in `src/admin/model_approval.py` (never smuggled from the
frontend — R2):
- `POST /admin/tenants/{tenant_id}/models/retire` — body `{model_id, retire_at}`;
  requires the model to be `approved`; `retire_at` must parse and be in the
  future (else 400). Sets the deadline, emits `model_retirement_scheduled`.
- `POST /admin/tenants/{tenant_id}/models/unretire` — body `{model_id}`; clears
  the deadline, emits `model_retirement_cancelled`.

Both reuse the F-019 `_decide` shape (audit-FIRST in a privileged session, then
tenant commit) and the same operator dependencies (`require_admin` +
`enforce_admin_scope` + `validate_tenant_id_path`). `ModelInventoryItem` gains a
`retire_at` field so the UI can render it. If the admin model surface is defined
in `contracts/openapi.yaml` (and `model_*` event types in
`contracts/events.schema.json`), the api-architect adds these first — the
contract is the law.

### Fork 3 — v1 scope

IN: read inventory dashboard, approve/deny UI, single-model retire/un-retire with
grace. DEFERRED and stated honestly (ADR + UI): bulk / multi-select retire,
multi-approver workflow, notifications (email/Slack), request-for-approval flow.

### Fork 4 — placement

A new model-governance panel (client island, mirroring `ShadowAiFeed`) on the
F-013 governance dashboard page, consuming the admin API through the existing BFF
proxy and reusing the auth spine (signed httpOnly `admin_session`, server-side
token injection, CSP nonce, `check:token`). The auth spine is not rebuilt.

## Operator-only / non-forgeable model (the F-019 R1 lesson)

Approve, deny, retire, and un-retire are operator actions. Authentication is the
F-012a admin break-glass token or the F-014 SSO operator session, resolved
server-side in the BFF and enforced by the admin router dependencies. No
data-plane / tenant / virtual-key path — through the UI or its BFF — can trigger
any of these actions. The operator acts on a single named **target tenant**;
there is no blanket cross-tenant grant. Operator identity is stamped from the
authenticated principal (`actor_id`), never caller-supplied.

## Threat model (≥12 vectors → test paths)

| # | Vector | Where proven |
|---|--------|--------------|
| 1 | data-plane / virtual-key cannot approve or retire via the BFF | pytest (admin auth) |
| 2 | approve/deny/retire require operator auth; tenant principal → 401/403 | pytest |
| 3 | admin token absent from the client bundle | frontend `check:token` |
| 4 | operator action scoped to the named target tenant; no blanket cross-tenant grant | pytest |
| 5 | `retire_at` in the past → request DENIED at the gateway (REAL path, fail-closed) | pytest NON-STUBBED |
| 6 | retiring within grace → still allowed | pytest |
| 7 | enforcement fails CLOSED on eval error → DENY | pytest |
| 8 | retire action persists and loads (real config path) | pytest NON-STUBBED |
| 9 | retiring-in-grace renders "usable until <date>"; no implied extra enforcement | render lane (gated) |
| 10 | one tenant's inventory invisible cross-tenant | pytest (RLS) |
| 11 | UI calls go only through the BFF / known admin routes (no silent endpoint) | frontend + pytest |
| 12 | e2e: operator approves → retires; a past-grace model is actually denied | pytest NON-STUBBED, zero stubs |

## Consequences

Positive: operators get a real governance UI; retirement is genuinely enforced
and honestly labelled; the change is additive (one nullable column, two event
types, two endpoints, one frontend panel) with no state-machine churn and no /v1
auth change.

Negative / accepted: retirement is single-model only in v1 (no bulk); no
notification when a grace window elapses (the operator/UI must observe it); the
deadline is not itself in the audit event (it is on the inventory row). These are
stated in the UI and deferred deliberately.

## Rollback

- Frontend: revert the governance page change + remove the panel — pure UI, no
  data effect.
- Backend enforcement: the `retire_at` branch is additive; reverting it returns
  enforcement to F-019 behaviour (approved models never auto-deny). Existing
  `retire_at` values become inert (no enforcement reads them).
- Schema: migration 0031 downgrade drops the `retire_at` column and reverts the
  event_type widening. Reversible round-trip is part of STEP 9.
- The retire/unretire endpoints can be removed independently; they touch only the
  new column and emit only the two new event types.
