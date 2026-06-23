# ADR-0021 — Shadow-AI Detection (detection + attribution layer on F-007's egress seam)

- **Status:** Proposed
- **Feature:** F-018
- **Date:** 2026-06-24
- **Supersedes / extends:** ADR-0010 (F-007 — the egress sensor this builds on)
- **Builds on:** ADR-0009 (F-008 policy), ADR-0014/0017 (F-012/F-014 admin auth), ADR-0016 (F-013 dashboards)

---

## 1. Context

F-007 (ADR-0010 §5) shipped the **egress sensor**: an httpx `request` event-hook
(`src/gateway/middleware/egress_monitor.py`) registered on Sentinel's outbound
OpenAI/Anthropic httpx clients. On each outbound call it resolves the destination
host → provider, compares against the request's tenant `allowed_providers`, and —
when a call leaves Sentinel toward a known provider **not** in that allow-list —
emits `shadow_ai_detected_outbound` via `emit_shadow_ai_outbound_event`
(`src/orchestration/detectors/shadow_ai_detector.py:123`). It **detects + audits
only; it never blocks** (blocking is a future F-019 concern). The F-013 governance
dashboard already renders a thin feed of those raw events (seq / type / team /
agent / time).

F-018 adds the **detection intelligence + attribution + honest UI** on top of that
sensor. It does **not** rebuild the hook (R2).

### 1.1 Code-read correction that shapes this ADR

`resolve_provider()` (`egress_monitor.py:47`) recognises exactly **three** hosts:
`api.openai.com`→openai, `api.anthropic.com`→anthropic, and a region-anchored
Bedrock regex. Any other host resolves to `None` and **emits nothing**. The audit
column `selected_provider` is itself CHECK-constrained (`ck_eal_selected_provider`)
to `('openai','anthropic','bedrock')`.

**Therefore the seam can only surface *disallowed known-provider* egress** — e.g. a
tenant whose allow-list contains only `openai` making a call to `api.anthropic.com`.
Arbitrary consumer-AI hosts (chatgpt.com, claude.ai, gemini, a random proxy) never
produce an event. Two consequences, both load-bearing for honesty:

1. The originally-envisioned **"known shadow-AI signature" heuristic is not
   computable** on this seam — those hosts never emit. Implementing it would mean
   expanding F-007's host table, which is modifying F-007 engine logic (R9 forbids)
   and is out of scope. **Signal 4 (signature) and `signatures.py` are dropped.**
2. The honesty boundary (§4) must say **disallowed known-provider egress through
   Sentinel**, not "any shadow-AI tool". Over-claiming here is the single biggest
   mis-sell risk for this feature.

---

## 2. Fork decisions (STEP 0 — approved by Affu)

| # | Fork | Decision | Why |
|---|---|---|---|
| D1 | DNS-resolver detection | **Deferred** | Requires running Sentinel as the corporate DNS resolver — heavy infra, zero current demand. v1 = httpx-egress only; documented future enhancement. |
| D2 | Detection model | **Heuristic v1** | Bounded, explainable rules. No labelled training data exists; an opaque ML score is a poor basis for a claim that implicates a team. Accuracy iterates with real data. |
| D3 | Endpoint-policy source | **Reuse F-007 provider allow-list** | The per-tenant `allowed_providers` (on `tenant_routing_policy`) is already what the sensor checks. **No new `policy_type`** → the F-016 CRIT-2 trap does not apply (no `_VALID_POLICY_TYPES` change, no CHECK-constraint widening, no policy migration). |
| D4 | F-007 event reconciliation | **Add one new variant** `shadow_ai_candidate_detected`; keep F-007's raw `shadow_ai_detected_outbound`. **Drop `shadow_ai_attributed`.** | Attribution is intrinsic — every audit row already carries the four server-stamped IDs. A separate "attributed" event would duplicate data already on the candidate event (R2). One new event type, attribution embedded. |
| D5 | Confidence model | **Banded Low/Med/High + explainable** | Each candidate lists the signals that fired. The UI shows "Candidate · confidence: Medium", never "confirmed/verdict" (R3). |
| D6 | Aggregation timing | **Read-triggered analysis, audit-log dedup** | The detection is an *analysis* layer over already-emitted events, not a request-path detector. No new state table; dedup by querying the audit log for an existing candidate with the same `candidate_key`. |
| D7 | Read surface | **New admin endpoint** `GET /tenants/{tenant_id}/shadow-ai/candidates` (api-architect → `openapi.yaml`) | Purpose-built shape carries confidence band, fired signals, attribution, and the disclaimer the thin audit feed cannot. Admin-authed, per-target RLS (F-012 pattern). The frontend consumes it via the existing BFF — backend adds the route, the frontend does not (R8). |

---

## 3. What F-007 provides vs what F-018 adds (anti-rebuild, R2)

| Concern | F-007 (REUSE — do not touch) | F-018 (this feature) |
|---|---|---|
| Outbound observation | httpx `egress_request_hook` | — (consumed, never rebuilt) |
| host→provider + allow-list check | `resolve_provider`, `_resolve_allowed_providers` | — |
| raw per-call event | emits `shadow_ai_detected_outbound` {detected_endpoint, traffic_volume, first_seen_at, selected_provider} + 4 stamped IDs | — (consumed as input) |
| Classification | none (raw signal only) | `classifier.py` — group by (team, endpoint), apply volume/frequency signals → **candidate + band** |
| Attribution | IDs stamped on the event | `attribution.py` — group by server-stamped team/agent; **confidence**, never verdict |
| Persistence of detection | none | new `shadow_ai_candidate_detected` event (deduped) |
| Surface | thin governance feed (no endpoint/confidence) | new admin endpoint + enriched panel with the honesty disclaimer |

F-018 imports and reads; it adds `src/shadow_ai/`, one event variant, one admin
endpoint, and one frontend panel enrichment. It changes **no** F-007/F-008/F-013
engine logic and **no** `/v1` auth (R9).

---

## 4. The Honesty Boundary (R1 — stated verbatim in the ADR, the API payload, and the UI)

> **Shadow-AI detection covers only traffic that flows _through Sentinel_ to a
> known model provider that is not on the tenant's allow-list.** It does **not**
> detect tools that bypass Sentinel — a personal device, a phone, a browser tab,
> or any client not routed through the gateway. Detecting those requires a
> CASB or network/DNS control and is **out of scope**. It also does not yet
> observe Bedrock/aioboto3 egress (inherited F-007 gap). Detections are
> **review candidates with a confidence band, not verdicts**; a candidate
> attributes likely shadow-AI use to a team for human review, and may be a
> false positive.

This string lives in `src/shadow_ai/constants.py::HONESTY_DISCLAIMER`, is returned
on every `GET …/shadow-ai/candidates` response, and is rendered (non-removable) on
the governance panel. Tests assert its presence at both the API and UI layers
(vectors 1, 3).

This is a **risk-reduction / high-coverage** control, not comprehensive shadow-AI
coverage — per the mandatory honest-language rule.

---

## 5. Detection heuristics (D2 — bounded, explainable, computable on the real seam)

Input: the tenant's recent `shadow_ai_detected_outbound` rows (RLS-scoped), each a
single disallowed known-provider egress (`traffic_volume` is always `1` per emit).
The classifier groups by `(team_id, agent_id, detected_endpoint)` and applies:

| Signal | Fires when | Effect |
|---|---|---|
| `disallowed_provider` | inherent — the group exists only because a known provider was off the tenant allow-list | base band **Low** |
| `volume` | group event-count ≥ `VOLUME_THRESHOLD` over the analysis window | → **Medium** |
| `frequency` | events clustered (rate ≥ `FREQUENCY_THRESHOLD` within a sub-window) | → **Medium** |

**Band:** Low (only `disallowed_provider`) · Medium (`+volume` or `+frequency`) ·
High (`volume` **and** `frequency`). All thresholds and the window are named
constants in `constants.py` (no inline magic numbers). Each candidate carries the
exact list of fired signals (explainability → the reviewer can see *why*).

No ML, no signature list, no payload inspection — only endpoint, identity, counts,
and timestamps (metadata only, R7).

---

## 6. Attribution + confidence (D5 — candidates, not verdicts, R3/R4)

- **Non-forgeable (R4):** the grouping key is taken from the four IDs the audit
  layer stamps on every event from the verified virtual-key identity. A
  caller-supplied team/agent claim in a request body never reaches these fields,
  so it cannot change attribution (vector 2).
- **False-attribution guard (R3):** an allow-listed call emits **no**
  `shadow_ai_detected_outbound` row, so it can never become a candidate and a
  benign team is never implicated (vector 4).
- **Confidence, not verdict:** the response and UI label every row `"candidate"`
  with a band; the words "confirmed", "verdict", "violation", and "guilty" never
  appear on this surface (vector 3).

---

## 7. Events — one new variant, 4 sites (D4; api-architect owns `events.schema.json`)

New event `shadow_ai_candidate_detected`, `action_taken = "logged"` (detect-only):

| Site | Change |
|---|---|
| `events_audit_log.py:40` `VALID_EVENT_TYPES` | add `shadow_ai_candidate_detected` |
| `events_audit_log.py:109` `ACTION_TAKEN_BY_EVENT_TYPE` | `{"logged"}` (reuses existing action value → `ck_eal_action_taken` UNCHANGED) |
| `events_audit_log.py:305` inline `ck_eal_event_type` literal **+** migration **0024** | DROP+CREATE the CHECK with the new value (model literal and migration kept in sync) |
| `contracts/events.schema.json` | new **closed** `oneOf` variant (api-architect) |

**Migration 0024** (revises 0023; reversible):
- widen `ck_eal_event_type` to include `shadow_ai_candidate_detected`;
- add 3 nullable columns: `confidence_band` (String 16, CHECK `IN ('low','medium','high')`),
  `fired_signals` (String 128, sorted comma-joined for a stable hash),
  `candidate_key` (String 64) + a partial index for dedup lookups;
- **reuse** existing columns: `detected_endpoint`, `traffic_volume` (group count),
  `first_seen_at` (window start), `selected_provider` (the disallowed provider),
  and the four stamped IDs;
- `down`: drop the index + 3 columns, restore the prior CHECK literal.

`candidate_key` = a stable digest of `(tenant_id, team_id, agent_id,
detected_endpoint, window_bucket)`. Before emitting, the service queries the audit
log for an existing `shadow_ai_candidate_detected` with that key in the window and
**skips if present** (D6 dedup — no new state table; per-poll lookup cost accepted
for v1).

---

## 8. Admin endpoint (D7) + frontend (R8)

**`GET /tenants/{tenant_id}/shadow-ai/candidates`** (api-architect → `openapi.yaml`),
admin-authed with per-target-tenant RLS, co-located with the existing
`tenants/{id}/audit` admin route. Response:

```
{ "candidates": [ { "team_id", "agent_id", "endpoint", "provider",
                    "call_count", "first_seen", "last_seen",
                    "confidence_band", "fired_signals": [...],
                    "label": "candidate" } ],
  "disclaimer": "<HONESTY_DISCLAIMER>" }
```

**Frontend:** enrich `frontend/src/components/dashboards/shadow-ai-feed.tsx` to
render attributed candidates + band + fired signals, each labelled "Candidate",
and render `disclaimer` prominently and non-removably. It polls
`tenants/{id}/shadow-ai/candidates` through the existing BFF (`clientApi`); the
root `tenants` is already allow-listed in `bff.ts`, so **no `bff.ts` change** and
**no silent frontend backend route** (R8).

---

## 9. Adversarial / correctness threat model (12 vectors → test paths)

| # | Vector | Test (path) |
|---|---|---|
| 1 | Honesty boundary rendered + non-removable | `frontend/tests/unit/dashboards.test.ts` (disclaimer text present) + `frontend/tests/e2e/dashboards.spec.ts`; API: `tests/shadow_ai/test_endpoint.py::test_disclaimer_present` |
| 2 | Attribution uses server identity (caller claim ignored) | `tests/shadow_ai/test_attribution.py::test_attribution_uses_server_identity` |
| 3 | Surfaced as candidate w/ confidence, never verdict | `tests/shadow_ai/test_classifier.py::test_detection_surfaced_as_candidate` + FE label test |
| 4 | Benign allow-listed call not attributed | `tests/shadow_ai/test_classifier.py::test_false_attribution_guard` |
| 5 | Disallowed known-provider egress → candidate | `tests/shadow_ai/test_classifier.py::test_disallowed_endpoint_flagged` |
| 6 | Allow-listed egress not flagged | `…::test_allowlisted_endpoint_not_flagged` |
| 7 | Built on the F-007 seam (no rebuilt hook, no duplicate raw event) | `tests/shadow_ai/test_seam.py::test_detection_consumes_f007_seam` |
| 8 | Reused provider-allowlist config path proven (non-stubbed) | `tests/shadow_ai/test_endpoint_policy.py::test_endpoint_policy_persists_and_loads` |
| 9 | Migration 0024 reversible | `tests/shadow_ai/test_migration.py::test_migration_reversible` (alembic up/down round-trip) |
| 10 | Detections tenant-scoped (cross-tenant invisible) | `tests/shadow_ai/test_isolation.py::test_shadow_ai_data_tenant_scoped` |
| 11 | Observes metadata, not payload | `tests/shadow_ai/test_classifier.py::test_detection_observes_metadata_not_payload` |
| 12 | Non-stubbed e2e: real egress event → classify → attribute → candidate emitted → surfaced in endpoint | `tests/shadow_ai/test_e2e_nonstubbed.py::test_e2e_nonstubbed` (ZERO stubs on detect/attribute/persist path) |

---

## 10. Honest scope / deferrals (carried into the PR DO-NOT-MERGE checklist)

- through-Sentinel-only; **bypass traffic is not detected** (CASB/firewall, out of scope);
- only **disallowed known-provider** egress is observable on the seam (host table = openai/anthropic/bedrock);
- **Bedrock/aioboto3 egress unobserved** (inherited F-007 gap);
- **DNS detection deferred** (D1);
- **heuristic v1** — candidates, false ± expected, accuracy iterates with real data;
- attribution is a **confidence-scored claim, not a verdict** (R3);
- **no blocking** — F-007/F-018 detect-only; blocking is F-019;
- **no new auth model**, **no new `policy_type`** (D3), **no contract endpoint invented** outside api-architect;
- per-poll audit-log dedup cost accepted for v1.

---

## 11. Rollback

- New event variant + columns are additive and nullable; `alembic downgrade -1`
  drops them and restores the prior `ck_eal_event_type` (vector 9).
- `src/shadow_ai/` is a self-contained module; removing the admin route + the
  panel enrichment + migration 0024 fully reverts F-018 with no effect on
  F-007's sensor or any other detector.
- No data migration of existing rows; existing `shadow_ai_detected_outbound`
  rows are read-only inputs and are untouched.

---

## 12. Consequences

- **Positive:** the existing raw egress signal becomes a reviewable, attributed,
  confidence-scored candidate feed with an explicit honesty boundary — high-value
  governance surface, additive, low blast radius.
- **Negative / accepted:** detection is narrow (disallowed known-provider only);
  read-triggered emit puts a small dedup query on each poll; heuristic v1 will
  have false positives/negatives. All disclosed in the UI and the audit.
- **Follow-ups:** expand the host table / signatures (needs F-007 change), DNS
  detection (D1), Bedrock egress (F-007 gap), blocking (F-019).
