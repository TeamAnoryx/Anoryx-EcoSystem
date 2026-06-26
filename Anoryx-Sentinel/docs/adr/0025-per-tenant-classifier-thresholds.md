# ADR-0025: Per-Tenant Classifier Thresholds (F-007 enhancement)

- Status: Proposed
- Date: 2026-06-26
- Builds on: ADR-0010 (F-007 LLM-as-judge injection classifier), ADR-0008 (F-006
  routing policy / `tenant_routing_policy` config home)
- Supersedes: none

## Context

F-007 shipped (commit `6a386c3`, ADR-0010): the `InjectionHook` runs the F-005
regex detector, and when a tenant has a judge configured (`classifier_model_id`
set) and the request lands in the uncertain band, it invokes an LLM-as-judge
through the F-006 provider layer and blends `final = max(regex_score,
judge_score)` — escalation-only, fail-closed.

Three of the judge's tuning knobs are **global** (or hardcoded), so every
classifier-enabled tenant gets the same band/floor regardless of its risk
tolerance or cost budget:

| knob | today | location |
|---|---|---|
| confidence floor (judge verdict ignored below) | **hardcoded `0.5`** | `injection_detector.py` `_judge_verdict` |
| obvious-attack skip (regex ≥ → skip judge) | global setting `judge_skip_score = 0.9` | `orchestration/config.py` |
| obvious-clean skip (regex < → skip judge) | **does not exist** — the judge runs on *every* benign request for an enabled tenant | — |
| block threshold (final ≥ → block) | global setting `injection_score_threshold = 0.75` | `orchestration/config.py` |

Two pressures motivate per-tenant control:

1. **Risk tolerance.** A high-security tenant wants the judge trusted even when it
   is only moderately confident (a *low* confidence floor → more escalations). A
   low-friction tenant wants the judge to count only when very confident (a *high*
   floor).
2. **Cost.** An enabled tenant currently pays a judge LLM call on every benign
   prompt because there is no obvious-clean lower band. A per-tenant floor lets a
   cost-sensitive tenant skip the judge on near-zero-regex prompts.

This ADR makes the **judge band + confidence floor per-tenant**. The **block
threshold stays global** (see Fork 2): it is shared with the F-005 regex-only
path, so making it per-tenant would change F-005 behavior and break R8
(classifier-off byte-identical).

## Decision

Add **three nullable per-tenant columns** to `tenant_routing_policy`, each
defaulting (when NULL) to today's constant. The judge runs only in the per-tenant
uncertain band `[floor, skip)`, and its verdict counts only when `confidence ≥
confidence_threshold`.

| column | type | NULL default | effect |
|---|---|---|---|
| `classifier_confidence_threshold` | NUMERIC(4,3) | `0.5` | judge ignored when `confidence < this` |
| `classifier_skip_threshold` | NUMERIC(4,3) | `0.9` | judge skipped when `regex_score ≥ this` (obvious attack) |
| `classifier_floor_threshold` | NUMERIC(4,3) | `0.0` | judge skipped when `regex_score < this` (obvious clean) |

### Fork 1 — config home: **reuse `tenant_routing_policy`, new migration 0032**

The classifier's existing config home is `tenant_routing_policy` (migration 0009
added `classifier_model_id` + `audit_mode` there). 0009/0010 added **no threshold
columns**, so three new columns are genuinely needed. `policy.schema.json` (LOCKED
at F-008) is untouched — classifier config has never ridden in the policy schema.
`tenant_routing_policy` already carries F-003b RLS, so no new RLS policy.

### Fork 2 — which knobs: **confidence floor + both band boundaries; block threshold excluded**

The named gap is the confidence floor. The two band boundaries (skip, floor) are
the same column+resolver shape and complete the "judge band per tenant" story
(ADR-0010 §5 Fork-2). The **block threshold is excluded** — it governs the F-005
regex-only verdict too; a per-tenant block threshold is a separate, riskier
feature (would make the regex path tenant-dependent → R8 risk). Named as a
deferral.

### Fork 3 — defaults: **NULL ⇒ today's constants**

A NULL column resolves to the current constant (`0.5` / `0.9` / `0.0`). Therefore:
- classifier-off tenants: unchanged (the judge never runs → no column is read).
- classifier-on, thresholds-unset tenants: **byte-identical** to pre-enhancement
  (`0.5` floor, `0.9` skip, no clean-skip).

This makes the enhancement strictly additive: no existing tenant changes behavior
until an operator sets a threshold.

### Fork 4 — enforcement seam: **resolve config once, past the cheap global gates**

The per-tenant band requires the tenant's config (an RLS DB read). To preserve R8
and avoid a read on hot/irrelevant paths, the **cheap global gates run first** (no
DB): `classifier_enabled is True`, `provider_registry` present, `first_rule` not a
known jailbreak-family rule. Only past those gates is the config resolved **once**
and the per-tenant band applied. The classifier-off / non-gateway path does **no**
DB read. One indexed RLS read per classifier-enabled request is negligible against
the judge LLM call it precedes (request-scoped caching deferred).

### Fork 5 — settable: **extend the existing admin config endpoint; frontend deferred**

Operators already view/set `classifier_model_id` / `audit_mode` via the admin
tenant-config endpoint (`src/admin/control.py`, repo `update_classifier_config`).
The three thresholds are added to that GET/PATCH surface (contract-bound →
api-architect extends `openapi.yaml` first). The frontend control to set them is
**deferred** — operators use the admin API in v1.

## Why no threshold can downgrade (the security core)

The thresholds gate **whether the judge runs** and **whether its verdict is
counted** — they never enter the score blend. The blend is unchanged:

```
final = max(regex_score, judge_score)        # only when the verdict is counted
verdict counted  iff  confidence ≥ confidence_threshold
judge runs       iff  floor ≤ regex_score < skip   (and the global gates pass)
```

- If a threshold *skips* the judge or *ignores* its verdict → the result is the
  **regex verdict** (`_regex_verdict`), exactly the F-005 outcome. Never "allow".
- If the verdict is counted → it goes through `max()`, which can only **raise**
  the score. A judge that returns a *low* score cannot lower `final` below
  `regex_score`.

Therefore **every reachable threshold setting yields `final ≥ regex_score`**
(R1 preserved). The worst an operator can do with thresholds is make the judge
*never* escalate (e.g. `confidence_threshold = 1.0`), which degrades to F-005
regex-only — still fail-closed, never weaker than today. Fail-closed (R2) is
untouched: `JudgeFellBack` / errors still fall back to the regex verdict.

## Threat model (≥10 vectors → test paths)

| # | vector | expectation | test |
|---|---|---|---|
| 1 | extreme thresholds (`confidence_threshold=1.0`) | `final == regex`, never below | `test_threshold_cannot_downgrade` |
| 2 | per-tenant confidence floor | conf 0.5 verdict ignored for A(floor 0.8), counted for B(floor 0.2); RLS-isolated | `test_confidence_floor_per_tenant` |
| 3 | obvious-clean floor | regex < floor → judge NOT invoked (no router call); regex stands | `test_floor_skips_judge_obvious_clean` |
| 4 | per-tenant skip band | regex ≥ per-tenant skip → judge skipped (tenant value, not global) | `test_skip_band_per_tenant` |
| 5 | NULL ⇒ defaults | NULL cols → 0.5 / 0.9 / 0.0 → identical to pre-enhancement | `test_null_thresholds_use_global_defaults` |
| 6 | classifier-off untouched | disabled → no DB read, regex path byte-identical (R8) | `test_classifier_off_byte_identical_no_db_read` |
| 7 | band sanity CHECK | DB rejects `floor > skip` | `test_band_check_rejects_floor_gt_skip` |
| 8 | range CHECK + resolver fail-safe | DB rejects outside [0,1]; resolver defaults a bad value, never weakens | `test_out_of_range_rejected` |
| 9 | migration round-trip (CRIT-2, non-stubbed persist FIRST) | upgrade+persist+downgrade clean | `test_migration_0032_roundtrip` |
| 10 | admin set | PATCH sets thresholds; invalid → 4xx; RLS-scoped | `test_admin_set_thresholds` |
| 11 | non-stubbed e2e | enabled tenant; judge score > regex but confidence just below the tenant floor → IGNORED, regex stands; a 2nd tenant with a lower floor → counted → escalates → 403 + `prompt_injection_detected_ml`. Zero stubs on resolve→band→combine→block→audit | `test_e2e_with_gateway` |

## Consequences

- **+** Per-tenant cost/coverage control of the judge; closes the ADR-0010 §5
  Fork-2 "band boundaries per tenant" gap and the hardcoded `0.5` floor.
- **+** Strictly additive: classifier-off and enabled-but-unset tenants unchanged.
- **−** One RLS config read per classifier-enabled request past the gates
  (negligible vs the judge call; cache deferred).
- **−** Migration 0032 bumps the head → three prior-feature head-pin tests
  (`persistence`, `model_approval`, `shadow_ai`) re-pin 0031 → 0032; the
  `model_approval` reversibility test switches its downgrade target to the
  explicit revision `0024` (not a step count).
- Contract: `openapi.yaml` admin config schema gains 3 fields (api-architect).
  `events.schema.json` / `policy.schema.json` untouched — thresholds are config,
  not emitted, and the locked policy schema is not the classifier's home.

## Honest residual

- Per-tenant control covers the **judge band + confidence floor only**. The block
  threshold (`0.75`) stays global (shared with F-005; per-tenant block deferred).
- `max()` floor + fail-closed are untouched: no threshold lowers `final` below
  the regex score — escalation-only preserved.
- Frontend UI to set thresholds is deferred; operators use the admin API.
- This does not improve detection *quality* — it only tunes when the existing
  judge runs/counts. No classifier catches every injection (ADR-0010 residual
  still stands).

## Rollback

`alembic downgrade -1` drops migration 0032 (3 columns + 4 CHECKs); the columns
are additive + nullable so no row is invalidated. Operationally, leaving every
threshold NULL (the default) is behaviorally identical to pre-enhancement, so the
feature can be shipped dark and adopted per-tenant.
