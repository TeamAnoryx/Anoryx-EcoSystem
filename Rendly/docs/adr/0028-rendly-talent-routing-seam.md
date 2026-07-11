# ADR-0028 — Talent Routing + Skills Inventory: a Permission-Gated, Intra-Tenant Composition Seam (R-028)

Status: Accepted
Date: 2026-07-11
Builds on: ADR-0016 (`intent.py`'s `IntentProfile` — "what I can offer" as a skill
declaration, R-016), ADR-0021 (`opportunity.py`'s deterministic set-intersection
scorer + its OWN deliberate cross-tenant matching, R-021), ADR-0027 (`platform_rbac.py`'s
fixed `OrgRole` -> `PlatformPermission` matrix + its cross-tenant fail-loud guard,
R-027), and the whole post-investment tier's established "scoped seam, ADR-disclosed
limitation, honesty boundary" discipline (ADR-0012, ADR-0016 through ADR-0027).

## Context

The roadmap names R-028 "Intent-driven talent routing + skills inventory (B2B)
🏦 POST-INVESTMENT", the second task of Rendly's Phase 4 "Platform-as-a-Service
(VISION)" tier — the first still-unchecked `R-` line in
`anoryx-ecosystem-roadmap-v3.md`'s checklist as of this run (R-001 through R-027 are
all checked). Like every task in this tier, R-028 is not given its own descriptive
paragraph — it appears only as a name in the tier's shared task list, with the shared
estimate/dependency/risk line ("~12-22h each · Depends on: R-005/R-007/R-008 + Delta ·
Risk: Medium-High"). This run resolves that absence of detail the same way every prior
unattended run in this tier has: the most conservative, smallest honestly-buildable
reading, named explicitly, with no scope widening to fill in the blanks.

"Intent-driven talent routing + skills inventory (B2B)" as a full PaaS primitive is a
large product space (a persisted skills catalog, resume/profile ingestion, an internal
job board with posting/approval workflows, a staffing/transfer decision pipeline). This
codebase already has real pieces of BOTH halves of the task's name:
`intent.IntentProfile.offering` (R-016) already models "what I can offer" as a tag set
— `opportunity.py`'s own ADR (ADR-0021) already named this a skill declaration — and
`opportunity.py` (R-021) already ships a deterministic set-intersection scorer between
an `IntentProfile` and a caller-supplied `Opportunity`. What R-021 explicitly does NOT
do, by its own design (ADR-0021 "DELIBERATE DIVERGENCE"), is respect tenant boundaries
— it is a B2C freelance/full-time board where cross-company matching is the point. "(B2B)"
in R-028's task name is the signal that this task is the OPPOSITE shape: routing
talent INSIDE one's own organization, which is a fundamentally intra-tenant operation.
R-027 (just shipped) supplies the missing piece to gate it: a fixed, checkable
tenant-level permission a caller can be required to hold before it sees or acts on
other members' data in bulk.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure, deterministic composition of the EXISTING `intent.IntentProfile`, `opportunity.Opportunity`/`suggest_opportunity_match`, and `platform_rbac.has_platform_permission` — NOT a persisted skills catalog, NOT an internal job board/posting workflow, NOT a staffing/transfer decision pipeline, NOT any REST/wire/UI surface)**

`src/rendly/talent_routing.py` adds one new read-model type
(`SkillsInventoryEntry`) and two pure, permission-gated functions
(`build_skills_inventory`, `route_talent`) composing three EXISTING modules — no
change to `intent.py`, `opportunity.py`, or `platform_rbac.py`.

Rejected: A2 (a new, persisted `Skill`/`SkillsInventory` entity with its own
opt-in/table). `opportunity.py`'s own ADR (ADR-0021 Fork A/NOT-BUILT-HERE) already
established that `IntentProfile.offering` IS the skill declaration this codebase
uses — inventing a second, parallel skill-tag concept here would fork that decision
for no product reason. Rejected: A3 (a real internal job-board/posting workflow with
approval, expiry, applicant tracking). Exactly the kind of invented, unrequested
scope this tier's own precedent (ADR-0018 Fork A, ADR-0025 Fork A/A4, ADR-0026 Fork
A/A3, ADR-0027 Fork A/A2) already rejects — `opportunity.py` already supplies the
`Opportunity` entity this module composes against unchanged; a posting workflow is a
distinct, larger feature with no existing behavior to compose against. Rejected: A4
(wire this into a REST/token layer, e.g. a new `contracts/openapi.yaml` endpoint). No
wire surface is requested; every prior seam task in this tier shipped as pure domain
composition with zero contract change, and this ADR follows the same discipline.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is a DETERMINISTIC,
PERMISSION-GATED, SAME-TENANT-ONLY composition of three already-shipped seams — no
ML, no resume parsing, no applicant-tracking workflow, no new skill-tag concept, and
no persistence. "Intent-driven talent routing + skills inventory (B2B)" as a full PaaS
primitive remains almost entirely unbuilt; this ADR closes one narrow, real
sub-problem of it and names everything else explicitly below.

### Fork B — the gating permission: **B1 (reuse R-027's EXISTING `PlatformPermission.MANAGE_TENANT_MEMBERS` — no new permission)**

Both `build_skills_inventory` (reading many members' skills at once) and
`route_talent` (routing a member toward an internal opportunity) are
tenant-wide-visibility operations materially more sensitive than a single
opt-in-to-opt-in match (R-016/R-021/R-022's own model, which requires no permission
check at all because each call only ever touches the two parties in the pair).
`MANAGE_TENANT_MEMBERS` (ADR-0027 Fork B) is already the closest existing capability
to "may act on the tenant's member roster in bulk" — reusing it needs no change to
`platform_rbac.py`'s closed `PlatformPermission` enum or its fixed
`_ORG_ROLE_PERMISSIONS` matrix.

Rejected: B2 (add a new, dedicated `PlatformPermission.ROUTE_TALENT` or
`VIEW_SKILLS_INVENTORY` member). Would widen R-027's closed enum and its matrix for a
capability this task can already express with the existing member — new enum growth
is exactly the kind of scope creep Fork A already rejects for the skill-tag concept,
and the same discipline applies to the permission catalog. A future task that
genuinely needs a FINER-grained split (e.g. "may view the inventory but not act on
it") can add that member then, against a real product requirement.

### Fork C — the cross-tenant guard: **C1 (every function RAISES `ValueError` on ANY cross-tenant `tenant`/`actor`/`opportunity`/candidate mismatch — never a silent filter-out or empty result)**

Mirrors the EXISTING precedent in `platform_rbac.resolve_platform_permissions`
(ADR-0027 Fork D): a caller passing mismatched tenant-scoped objects together is a
caller bug, not a security decision this module is positioned to make quietly.
Failing loud is more conservative than silently dropping the offending entry from a
ranked/roster result, which could mask the bug behind what looks like a legitimate
"no match"/"not in inventory" outcome — especially dangerous here because a silently
dropped cross-tenant CANDIDATE would look identical to "this candidate just didn't
match," hiding a tenant-isolation bug behind ordinary product behavior.

Rejected: C2 (silently exclude a cross-tenant candidate from `route_talent`'s ranked
list, mirroring `opportunity.rank_opportunities`'s own permissiveness). Explicitly
the WRONG precedent to mirror here — `opportunity.py`'s cross-tenant permissiveness is
correct for ITS product (a B2C freelance board where cross-tenant matches are the
entire point, ADR-0021 "DELIBERATE DIVERGENCE"), but R-028's product is the opposite:
intra-org routing, where a cross-tenant entry is never a legitimate result to
silently omit, only ever a caller bug to surface.

### Fork D — the roster's ordering: **D1 (`build_skills_inventory` preserves caller-supplied order — it is a roster, not a ranking, so there is no score to sort by)**

A skills inventory answers "who has which skills," not "who is the best match for
X" — there is no scalar to rank by until a caller pairs it with a specific
`Opportunity` via `route_talent` (which DOES rank, by matched-skill count, exactly
as `opportunity.rank_opportunities` already does).

Rejected: D2 (sort the inventory alphabetically by `user_id`, mirroring the
tie-break order every `rank_*` function in this codebase uses). Would imply a
canonical ordering this read-model does not actually need or claim — a future
caller building an actual roster UI can sort a `tuple[SkillsInventoryEntry, ...]`
itself however it likes; inventing a sort order here is unrequested scope with no
product motivation, unlike the `rank_*` functions' tie-break, which exists to make a
SCORE-based ranking deterministic.

## What is deliberately NOT built here (named, not silently skipped)

- **No new skill-tag concept or persisted skills catalog.** Reuses
  `intent.IntentProfile.offering` unchanged — no new table, no new opt-in type. See
  Fork A/A2.
- **No internal job-board/posting workflow.** Reuses `opportunity.Opportunity`
  unchanged — no approval, expiry, or applicant-tracking state machine. See Fork
  A/A3.
- **No REST/wire surface, no UI.** `contracts/openapi.yaml` and
  `contracts/rendly-domain.schema.json` are unchanged; nothing in this module is
  called from anywhere in the request path today. See Fork A/A4.
- **No new `PlatformPermission` member.** Reuses R-027's existing
  `MANAGE_TENANT_MEMBERS` — `platform_rbac.py`'s closed enum and matrix are
  unchanged. See Fork B/B2.
- **No staffing DECISION workflow.** This module only ranks and reports candidates
  (`route_talent`) or projects a roster (`build_skills_inventory`) — it does not
  record an offer, an acceptance, or an actual internal transfer.
- **No persistence.** This is a pure function of caller-supplied `Tenant`,
  `Profile`, `IntentProfile`, and `Opportunity` objects — no new table, no new
  migration, no RLS change.

## Consequences

- Rendly gains its first PERMISSION-GATED matching/reporting seam — every prior
  R-016->R-022 matcher operates opt-in-to-opt-in with no access check, because each
  call only ever touches the two parties already in the pair; `talent_routing.py` is
  the first seam whose whole point is bulk, tenant-wide visibility, and it is gated
  accordingly by R-027's fixed permission matrix.
- No new attack surface is introduced: no new network endpoint, no new table, no new
  migration, no RLS change, no new identifier type, and no widened enum. The one new
  guard this module adds (rejecting EVERY cross-tenant mismatch, including a
  candidate silently dropped rather than raised) is stricter than `opportunity.py`'s
  own precedent — deliberately so, per Fork C.
- The roadmap's R-028 checklist line is intentionally NOT marked "the full real
  internal talent marketplace (persisted catalog + job board + staffing workflow)
  shipped" — it is marked shipped as THIS scoped, permission-gated composition seam,
  exactly as R-012/R-016 through R-027 were, with every deferred piece named above as
  the obvious next slice for a future, separately-dispatched task.
