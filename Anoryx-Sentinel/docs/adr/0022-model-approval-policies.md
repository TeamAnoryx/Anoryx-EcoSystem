# ADR-0022 — Custom Model + Fine-Tune Approval Policies (default-deny model governance on F-008's seam)

- **Status:** Proposed
- **Feature:** F-019
- **Date:** 2026-06-24
- **Extends:** ADR-0009 (F-008 — the model-policy enforcement seam this builds on)
- **Builds on:** ADR-0014 (F-012a admin auth), ADR-0017 (F-014 SSO operator identity), ADR-0005/0006 (tenant isolation / RLS), ADR-0001 (F-003 hash-chained audit)

---

## 1. Context

F-008 (ADR-0009 §6) shipped two model `policy_type`s — `model_allowlist` and
`model_denylist` — evaluated at one seam, `evaluate_model_policies()`
(`src/policy/enforcement.py:210`), which the F-006 router calls at
`src/gateway/router/selection.py:191` (non-stream) and `:514` (stream), and which
the bulk pipeline (`src/bulk/pipeline.py:128`) and the orchestration judge
(`src/orchestration/judge/invoker.py:150`) reuse. A `ModelDeny` from that seam
flows through `_policy_deny` (`selection.py:202`) to `GatewayError("policy_blocked")`
→ **403** before the upstream provider call.

The F-008 `model_allowlist` is **opt-in by design**: `enforcement.py:5-6` states
that absence of a matching allow-list means the request is *not* constrained, and
`resolve_model_decision()` returns `ModelAllow()` when no allow-list matches. That is
the correct default for an *optional* allow-list, but it is the **wrong default for
model approval**: an enterprise governing custom models / fine-tunes wants *nothing
usable until an operator approves it*.

F-019 adds a **default-deny** governance layer **on top of** F-008: a per-tenant
**inventory** of models/fine-tunes, an **operator-only approval state machine**
(pending → approved/denied), and gateway enforcement where a request for a
non-approved model is **rejected before the upstream call**. It is the
security-critical inverse of F-008. The two primary threats are therefore (a)
**data-plane self-approval** (a virtual-API-key caller granting itself a model) and
(b) **inert / fail-open enforcement** — the F-016 lesson that an enforcement layer
which silently allows is worse than none, and here it is a security hole, not merely
an inert feature.

**This ADR extends F-008; it does not fork a parallel model-policy engine (R5).**

---

## 2. Fork decisions (STEP 0 — approved by Affu)

| # | Fork | Decision | Why |
|---|---|---|---|
| D1 | **policy_type** | **NEW `model_approval` policy_type.** Its *presence* for a tenant flips that tenant to default-deny against the inventory (pending/denied/unknown → DENY). F-008 `model_allowlist` opt-in semantics stay **untouched**. | Reusing `model_allowlist` would mutate F-008's well-tested opt-in evaluation on the security-critical path (higher blast radius), and a 3-state machine (pending/approved/denied) does not map onto a flat allow-string list. A dedicated policy_type is a clean per-tenant switch routed through the *existing* `evaluate_model_policies` → `policy_blocked` seam — the correct EXTEND. **Cost: the F-016 CRIT-2 countermeasure (§5.1), done FIRST.** |
| D2 | **Workflow depth** | **Minimal state machine, hardened.** pending→approved/denied + approved↔denied; a single authenticated-operator transition; every transition audited. Defer multi-approver, request-for-approval, notifications. | Each deferred mechanism adds tenant-reachable or cross-tenant surface for no v1 demand. Leaner = tighter trust boundary = more secure. The "more secure" is spent on hardening the ONE transition (§7), not on more workflow. |
| D3 | **Inventory scope** | **Per-tenant**, RLS-scoped. Each tenant's operator approves for that tenant only; never visible/usable by another. | Platform-wide rejected: a model approved for tenant A usable by tenant B breaks tenant isolation (R4) — disqualifying for a zero-trust product. |
| D4 | **Enforcement seam + error_code** | **Extend `evaluate_model_policies`**; reuse `policy_blocked` (403). Default-deny returns `ModelDeny(reason="model_not_approved")` → existing `_policy_deny` → `GatewayError("policy_blocked")`, **pre-upstream**, **fail-closed**. `model_not_approved` lives only in the audit reason. | One real seam, already covering non-stream/stream/bulk/judge. Zero new gateway wiring; consistent with F-016/F-017 reusing `policy_blocked`. No contract/error_code change → no wire-surface expansion. |
| D5 | **Approver identity** | **Operator-only, non-forgeable.** `require_admin` (`src/admin/auth.py:105`) → admin break-glass token or F-014 SSO operator. Identity stamped from the authenticated principal via `actor_id(request)` (`src/admin/util.py:46`) → `emit_admin_event`. No data-plane / virtual-key / tenant path reaches the admin routes. | R1 hard rule. The admin router is the only surface that can transition state; it is reached only with operator auth. |

---

## 3. What F-008 provides vs what F-019 adds (anti-rebuild, R5)

| Concern | F-008 (REUSE — do not fork) | F-019 (this feature) |
|---|---|---|
| Decision seam | `evaluate_model_policies()` + `ModelDeny`/`ModelAllow` types (`enforcement.py:210`) | a default-deny branch *inside* that seam, gated on an active `model_approval` policy |
| Wire result | `_policy_deny` → `GatewayError("policy_blocked")` 403 + stream error-frame (`selection.py:202,339,524`) | a new `ModelDeny` reason string `model_not_approved` (audit only) |
| Policy machinery | `PolicyRepository`, signed/versioned intake, per-scope load, RLS | the `model_approval` policy_type (the per-tenant switch) |
| Model state | — | `model_inventory` table + repo (the pending/approved/denied state machine) |
| Admin pattern | `require_admin`, `get_tenant_session(target)`, `emit_admin_event`, `actor_id` | operator approve/deny/list endpoints + 3 operator event variants (runtime denials reuse `policy_decision_deny`) |

---

## 4. Honesty boundary (mandatory)

- **"operator-approved model governance,"** not "blocks all unauthorized model use." F-019
  governs models **routed through Sentinel's `/v1` surface**; a caller bypassing the
  gateway entirely is out of scope (that is the gateway's perimeter, not this feature).
- **"default-deny against the tenant inventory,"** not "knows every model in existence."
  An unknown model (absent from the inventory) is **denied**, which is the safe default,
  but the inventory reflects only what has been adopted/observed for that tenant.
- The approval workflow is **single-operator, single-transition** in v1 — not a
  multi-party governance process. State this in the PR and any UI copy.

---

## 5. Enforcement & persistence design

### 5.1 CRIT-2 countermeasure — done FIRST (R5; F-016 lesson)

A new `policy_type` is unstorable until **every** gate accepts it. Before any
enforcement code:

1. `src/persistence/repositories/policy_repository.py:34` — add `"model_approval"` to
   `_VALID_POLICY_TYPES`.
2. `src/persistence/models/policy.py` — widen **BOTH** CHECK constraints:
   `ck_policies_policy_type` (~line 93) **and** `ck_pv_policy_type` (~line 157); update
   the discriminator comment at `policy.py:52`.
3. **Migration 0025** (`0025_model_approval_policy_type.py`, `down_revision="0024"`) —
   drop+recreate both CHECK constraints with `model_approval` added; reversible. Mirror
   `0021_code_scan_policy_type.py` / `0022_data_lock_policy_type.py`.
4. `contracts/policy.schema.json` — add the `model_approval` payload (api-architect only).
5. **Vector 9 (NON-STUBBED):** store a `model_approval` policy via
   `PolicyRepository.create_version`, load via
   `get_active_policies_for_scope(tenant, "model_approval")`, assert it parses and
   signals default-deny. **No enforcement code merges until this test is green.**

The `model_approval` payload is **minimal** — its presence is the switch; it carries
the scope IDs + a default-deny marker, not the per-model state (that is the inventory).

### 5.2 Inventory (per-tenant state machine)

`model_inventory` table — `tenant_id`, scope (`team_id`/`project_id`), `model_id`,
`model_type` (`base`|`fine_tune`), `state` (`pending`|`approved`|`denied`),
`approved_by` (operator `actor_id`, nullable), `approved_at` (nullable), `created_at`,
`updated_at`. **Tenant-scoped RLS** (mirror an existing tenant table). Migration 0026.
`get_state(model_id)` returns `"unknown"` for an absent row → default-deny at
enforcement. Valid transitions: pending→approved, pending→denied, approved↔denied;
illegal edges rejected.

### 5.3 Default-deny enforcement (the seam extension, D4)

Inside `evaluate_model_policies`: after the existing F-008 allow/deny resolution, if a
`model_approval` policy is **active for the scope**, load the inventory state for
`model_id`. If state != `approved` (pending/denied/unknown) **OR** any
inventory-load/eval error → return `ModelDeny(reason="model_not_approved")`. The load
is wrapped `try/except` → `ModelDeny` (fail-closed, R3). Precedence: an explicit
`model_denylist` deny stays absolute; `model_approval` default-deny then applies when
active and the model is not approved; `model_allowlist` continues to govern its own
opt-in set. A not-approved model is denied regardless of allow-list state. The block is
**pre-upstream** and reaches non-stream/stream/bulk/judge unchanged.

### 5.4 Events & attribution (4-site, no new audit columns)

**Three** operator-action variants: `model_approved`, `model_denied`, `model_adopted`.
Runtime use-denials are NOT a separate variant — a not-approved model is audited by the
**existing** `policy_decision_deny` event (with `reason="model_not_approved"`,
`requested_model` set), exactly as F-008 allowlist/denylist denials are; emitting a
distinct `model_use_denied` would double-log the same fact and touch the generic deny
seam (R8), so it is deliberately omitted. 4 sites for the three new types:
`VALID_EVENT_TYPES`, `ACTION_TAKEN_BY_EVENT_TYPE`, `ck_eal_event_type` (migration 0027,
`down_revision="0026"`, head=0027), `contracts/events.schema.json` (api-architect).
Operator events: `emit_admin_event(actor_id=actor_id(request), target_tenant_id=...)`
— attributed to operator + target tenant, `agent_id="admin-console"`, `actor_id` None
for break-glass; never nil-UUID, never the tenant's own id (R6). **No new audit
columns** — reuse `actor_id` (opt-in hash rule, `hash_chain.py:138`) and the existing
`model` column for `model_id`. That `model` column is in `CANONICAL_FIELDS`, so
`model_id` IS folded into the row hash (tamper-evident); the decision itself is encoded
by `event_type`, so no `state` column is needed. The F-003 hash chain is untouched and
no new column is added (R7 column rule N/A).

---

## 6. Adversarial threat model (≥12 vectors, empirical)

| # | Vector | Test |
|---|---|---|
| 1 | data-plane caller approves a model via any header/body/claim | test_data_plane_cannot_approve_model |
| 2 | tenant principal hits approve/deny | test_only_operator_can_approve (401/403) |
| 3 | approval audit attribution | test_approval_attributed_to_operator (operator+target, not nil-UUID/not tenant) |
| 4 | operator approval leaks cross-tenant | test_cross_tenant_approval_denied (scoped to named target) |
| 5 | unapproved/pending/unknown model at gateway | test_unapproved_model_denied_at_gateway (pre-upstream, real path) |
| 6 | approved model | test_approved_model_allowed |
| 7 | inventory-load / approval-check error | test_enforcement_fails_closed (→ DENY) |
| 8 | model moved to denied | test_denied_model_blocked (next request) |
| 9 | policy persistence (CRIT-2) | test_model_policy_persists_and_loads (NON-STUBBED) |
| 10 | cross-tenant inventory visibility | test_inventory_tenant_scoped |
| 11 | migration reversibility | test_migration_reversible (0025/0026/0027) |
| 12 | full real path | test_e2e_nonstubbed (register→approve→ALLOW; deny/unknown→DENY; ZERO stubs) |

---

## 7. Five hardening points (applied to the single transition — the D2 "more secure")

1. **Operator-only, non-forgeable** — no header/body/claim lets a data-plane caller
   reach approval state (vectors 1,2).
2. **Authenticated-principal stamp** — operator identity is taken from the
   authenticated principal, never caller-supplied; attributed to operator + target
   tenant, never nil-UUID, never the tenant's own id (vector 3).
3. **Default-DENY + fail-CLOSED** — pending/denied/unknown model, or any
   approval-check/inventory-load error → DENIED before upstream (vectors 5,7,8).
4. **Atomic transition + audit** — the inventory state change and its audit append
   commit in **one transaction** (F-012a MED-2 lesson — no state change without a
   committed audit row); cross-tenant approval is scoped to the named target only
   (vector 4).
5. **Append-only history** — a denied→approved (or reverse) transition mutates the
   inventory `state` to current AND appends a new audited event; the tamper-evident
   history lives in the append-only hash-chained audit log — prior rows are never erased.

---

## 8. Deferred scope (explicit)

Multi-approver / quorum; request-for-approval flow (tenant requests, operator
approves); notifications; auto-discovery of models beyond adopt-on-observe;
per-model expiry windows; a tenant self-service read of its own inventory (admin-only
in v1). No new auth model. No `/v1` auth change. No new audit columns.

---

## 9. Rollback

Each migration is reversible. `alembic downgrade 0024` removes the event-type
widening (0027), the `model_inventory` table (0026), and the `model_approval`
policy_type from both CHECK constraints (0025), in order. With no `model_approval`
policy rows present, `evaluate_model_policies` takes no default-deny branch and
behaviour is exactly F-008. Reverting the code (the seam branch + admin routes + variant)
restores pre-F-019 behaviour with no residual enforcement.

---

## 10. Incidental F-008 repair (surfaced by the vector-12 non-stubbed e2e)

F-019's non-stubbed e2e (vector 12) is the first test to drive the **real**
`_enforce_policies_pre_request` path end-to-end; every prior gateway test stubbed it
(e.g. `tests/gateway/router/test_policy_enforcement.py`, and the F-017 e2e whose
comment explicitly mocks `_resolve_policy` to "avoid the double-begin"). Doing so
exposed a **latent F-008/F-006 bug**: `_enforce_policies_pre_request`
(`selection.py`) and `_resolve_policy` both wrapped their reads in
`async with session.begin()` **after** `get_tenant_session` had already autobegun the
transaction (its `set_config` runs an `execute`). The nested `begin()` raised
`InvalidRequestError: A transaction is already begun`, which the live path caught and
converted to a fail-safe **500** — meaning F-008 model/budget enforcement never
actually executed on real `/v1` traffic (an inert-enforcement bug of exactly the
F-016 class).

Fix (approved by Affu, beyond F-019's R8 "extend-only" boundary): remove the
redundant `async with session.begin()` at both sites — the blocks are read-only, so
the reads run in the autobegun transaction (the established read pattern in
`admin/control.py` / `bulk/worker.py`). No behaviour change other than the path now
executing. With the fix, F-019 default-deny **and** the pre-existing F-008
allow/deny + budget enforcement both run for real, proven by vector 12 (real
approve→allow, deny→block, zero stubs on the enforcement path).
