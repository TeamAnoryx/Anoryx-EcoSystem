# ADR-0029 — Project/Sprint Workspaces + B2B Analytics: a Channel-Reusing Scheduling + Reporting Seam (R-029)

Status: Accepted
Date: 2026-07-11
Builds on: ADR-0006 (`channel.py`'s tenant-scoped `Channel`, R-006), ADR-0013
(`event.py`'s deterministic, no-overlap agenda-scheduling seam + its OWN
deliberate choice to keep a new domain type's identity SEPARATE from an
unrelated locked constant, R-013), ADR-0027 (`platform_rbac.py`'s fixed
`OrgRole` -> `PlatformPermission` matrix + its cross-tenant fail-loud guard,
R-027), ADR-0028 (`talent_routing.py`'s reuse of an EXISTING `PlatformPermission`
member rather than widening the enum, R-028), and the whole post-investment
tier's established "scoped seam, ADR-disclosed limitation, honesty boundary"
discipline (ADR-0012, ADR-0016 through ADR-0028).

## Context

The roadmap names R-029 "Project/sprint workspaces + B2B analytics
🏦 POST-INVESTMENT", the third task of Rendly's Phase 4 "Platform-as-a-Service
(VISION)" tier — the first still-unchecked `R-` line in
`anoryx-ecosystem-roadmap-v3.md`'s checklist as of this run (R-001 through
R-028 are all checked). Like every task in this tier, R-029 is not given its
own descriptive paragraph — it appears only as a name in the tier's shared
task list, with the shared estimate/dependency/risk line ("~12-22h each ·
Depends on: R-005/R-007/R-008 + Delta · Risk: Medium-High"). This run resolves
that absence of detail the same way every prior unattended run in this tier
has: the most conservative, smallest honestly-buildable reading, named
explicitly, with no scope widening to fill in the blanks.

"Project/sprint workspaces + B2B analytics" as a full PaaS primitive is a
large product space (a persisted project/workspace entity distinct from a
channel, task/issue tracking, burndown charts, a BI-grade analytics engine
with historical trends and dashboards). This codebase already has real
pieces this task can compose against without inventing any of that: `Channel`
(R-006) is already a tenant-scoped, named, membership-rostered container —
exactly what a "project workspace" needs as its comms/roster anchor, and
inventing a second, parallel "Workspace" entity next to it would fork that
concept for no product reason. `event.py`'s `schedule_session` (R-013)
already ships the deterministic, no-overlap, bounded-agenda scheduling
PATTERN a "sprint" needs — but its `EventSession.capacity` field is locked to
`event.py`'s own honesty boundary (an R-011 group-huddle participant count,
2-8), a constraint with no meaning for a sprint. `platform_rbac.py` (R-027)
already supplies a fixed, checkable tenant-level permission a caller can be
required to hold before it reads a tenant-wide reporting rollup.

## Decision — resolved forks

### Fork A — the workspace container: **A1 (reuse the EXISTING `channel.Channel` AS the project workspace — NOT a new persisted `Workspace`/`Project` entity)**

`src/rendly/workspace.py` schedules sprints and computes analytics directly
against a caller-supplied `Channel` + its `Membership` roster — no new
container type. A "project/sprint workspace" is, structurally, a tenant-scoped
named container with a membership roster: exactly what `Channel` (R-006)
already is. Everything this module adds is new SCHEDULING and REPORTING
behaviour layered over that existing container, not a new identity for it.

Rejected: A2 (a new, persisted `Workspace`/`Project` entity distinct from
`Channel`, with its own id/table). Would duplicate `Channel`'s existing
tenant-scoping, naming, and membership-roster machinery for no product
reason — exactly the kind of invented, unrequested scope this tier's own
precedent (ADR-0018 Fork A, ADR-0025 Fork A/A4, ADR-0026 Fork A/A3, ADR-0027
Fork A/A2, ADR-0028 Fork A/A2) already rejects. A future task that genuinely
needs a workspace to be something OTHER than a channel (e.g. multiple
channels per workspace) can introduce that distinction then, against a real
product requirement.

### Fork B — the sprint's identity and shape: **B1 (a NEW, minimal `Sprint` type — title + time window only — NOT a reuse of `event.EventSession`)**

`Sprint` is a new, non-persisted domain type: `sprint_id`, `tenant_id`,
`channel_id`, `title`, `starts_at`, `ends_at`. It deliberately does NOT reuse
`event.EventSession`, even though the two are structurally similar
(time-boxed, titled, tenant-scoped), because `EventSession.capacity` is
locked to `event.py`'s own R-011-huddle-derived honesty boundary (`2..8`,
"every scheduled session is still, mechanically, a group huddle") — a
constraint that has no meaning for a sprint (a sprint is a work period, not a
call). Forcing `Sprint` through `EventSession`'s shape would mean either
inventing a fake capacity for every sprint or silently breaking
`event.py`'s own documented invariant; a new, narrower type avoids both.

Rejected: B2 (reuse `EventSession` directly, ignoring or defaulting
`capacity`). Would either force a meaningless field onto every sprint or
require weakening `EventSession`'s own capacity bound — exactly the "widen
an existing locked concept to also mean something new" move ADR-0028 Fork A/
A2 and ADR-0027 Fork A/A2 already reject in spirit. Rejected: B3 (a generic
shared "time-boxed window" base type factored out of `event.py` and this
module). Pure refactor-for-its-own-sake with no second concrete consumer
requesting it yet — YAGNI; `event.py`'s own `EventSession` is left completely
unchanged by this ADR.

### Fork C — the sprint-scheduling constraint: **C1 (no two sprints on the same workspace may overlap in time — mirrors `event.schedule_session`'s no-overlap discipline)**

A single project workspace runs ONE sprint cycle at a time — an ordinary,
widely-used real-world Scrum/Kanban convention (sequential, non-overlapping
sprints), not an invented one. `schedule_sprint` therefore mirrors
`event.schedule_session`'s exact validation order: every entry of
`existing_sprints` must belong to the SAME `channel_id`/`tenant_id`, the
agenda is bounded (`MAX_SPRINTS_PER_WORKSPACE`, mirrors
`MAX_SESSIONS_PER_EVENT`), and the new sprint's `[starts_at, ends_at)` window
must not overlap any existing sprint on that workspace — `ValueError` on any
violation, never a silent drop or truncation.

Rejected: C2 (allow overlapping/parallel sprints, i.e. multiple concurrent
workstreams per workspace). A real, larger feature (independently schedulable
parallel tracks) with no existing precedent in this codebase to compose
against — `event.py`'s own ADR-0013 named the analogous "multi-host/parallel-
track agenda" explicitly out of scope for the same reason. A future task that
genuinely needs concurrent workstreams per workspace can add that distinction
then.

### Fork D — the analytics permission gate: **D1 (reuse R-027's EXISTING `PlatformPermission.VIEW_TENANT_AUDIT_LOG` — no new permission)**

`compute_workspace_analytics` aggregates a whole workspace's membership
roster and sprint history at once — a tenant-wide-visibility reporting
operation, materially more sensitive than any single-pair opt-in match, and
of the same shape ADR-0028 Fork B already reasoned about for
`talent_routing.py`'s roster read. Of `platform_rbac.py`'s three EXISTING
permissions, `VIEW_TENANT_AUDIT_LOG` — named for R-008's "complete
administrative audit/oversight" goal — is the closest existing fit: B2B
analytics over a workspace is a READ-ONLY oversight/reporting capability, not
a channel-ADMINISTRATION action (creating, archiving, or team-mapping a
channel), which is what `MANAGE_TENANT_CHANNELS` actually names.

Rejected: D2 (reuse `MANAGE_TENANT_CHANNELS` instead). Less apt: that
permission's own docstring ties it to `realtime.authz.ChannelAction
.MANAGE_MEMBERS`/`MAP_TO_TEAM` — channel ADMINISTRATION actions — not to
read-only reporting; conflating "may manage this channel" with "may read
this channel-workspace's rollup" would blur two genuinely distinct
capabilities for no product reason. Rejected: D3 (add a new, dedicated
`PlatformPermission.VIEW_WORKSPACE_ANALYTICS` member). Would widen R-027's
closed enum and its fixed matrix for a capability this task can already
express with an existing member — new enum growth is exactly what ADR-0028
Fork B already rejected for the same reason; a future task that genuinely
needs a FINER-grained split can add that member then, against a real product
requirement.

### Fork E — the cross-tenant/cross-workspace guard: **E1 (every function RAISES `ValueError` on ANY cross-tenant/cross-channel `tenant`/`channel`/membership/sprint mismatch — never a silent filter-out)**

Mirrors the EXISTING precedent in `platform_rbac.resolve_platform_permissions`
(ADR-0027 Fork D) and `talent_routing.py` (ADR-0028 Fork C): a caller passing
mismatched tenant- or channel-scoped objects together is a caller bug, not a
security decision this module is positioned to make quietly. A silently
dropped cross-channel membership or sprint would look identical to "this
workspace legitimately has fewer members/sprints than expected," hiding a
scoping bug behind ordinary-looking analytics output — the same reasoning
ADR-0028 Fork C already applied to a silently dropped cross-tenant candidate.

Rejected: E2 (silently exclude a mismatched membership/sprint from the
analytics rollup). Same rejection as ADR-0028 Fork C/C2: correct for
`opportunity.py`'s deliberately cross-tenant product, wrong for a
same-workspace reporting rollup, where every input is expected to already
belong to the one workspace being reported on.

## What is deliberately NOT built here (named, not silently skipped)

- **No new persisted `Workspace`/`Project` entity.** Reuses `channel.Channel`
  unchanged — no new table, no new opt-in type. See Fork A/A2.
- **No task/issue tracking, no burndown chart, no velocity/story-point
  concept.** `Sprint` carries only an identity + a time window — it is a
  scheduling primitive, not a work-item tracker.
- **No BI-grade analytics engine.** `compute_workspace_analytics` is a pure,
  deterministic aggregation over caller-supplied membership + sprint lists
  (counts, the active/upcoming sprint, total scheduled minutes) — no
  historical trending, no dashboards, no time-series storage.
- **No parallel/concurrent sprints per workspace.** See Fork C/C2.
- **No REST/wire surface, no UI.** `contracts/openapi.yaml` and
  `contracts/rendly-domain.schema.json` are unchanged; nothing in this module
  is called from anywhere in the request path today.
- **No new `PlatformPermission` member.** Reuses R-027's existing
  `VIEW_TENANT_AUDIT_LOG` — `platform_rbac.py`'s closed enum and matrix are
  unchanged. See Fork D/D3.
- **No persistence.** This is a pure function of caller-supplied `Channel`,
  `Membership`, and `Sprint` objects — no new table, no new migration, no RLS
  change.

## Consequences

- Rendly gains its first scheduling seam scoped to a `Channel` rather than to
  an `Event` — `event.py`'s single-host agenda pattern (R-013) is proven
  reusable for a materially different product shape (a project workspace's
  sprint cadence, no host, no huddle-capacity concept) without touching
  `event.py` itself.
- No new attack surface is introduced: no new network endpoint, no new
  table, no new migration, no RLS change, and no widened enum. The guard
  this module adds (rejecting every cross-tenant/cross-channel mismatch,
  including a membership or sprint silently dropped rather than raised) is
  the same fail-loud discipline ADR-0027/ADR-0028 already established.
- The roadmap's R-029 checklist line is intentionally NOT marked "the full
  real project-management + BI analytics platform shipped" — it is marked
  shipped as THIS scoped scheduling + reporting seam, exactly as R-012/R-016
  through R-028 were, with every deferred piece named above as the obvious
  next slice for a future, separately-dispatched task.
