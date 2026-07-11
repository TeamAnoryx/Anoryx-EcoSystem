# ADR-0027 — B2B Platform RBAC: a Fixed, Tenant-Scoped Permission-Resolution Seam (R-027)

Status: Accepted
Date: 2026-07-10
Builds on: ADR-0002 (`enums.py`'s `OrgRole` — "the per-tenant org-level role,
FORK B = B1, fixed enum"), `profile.py`/`membership.py`'s
`bind_profile`/`bind_membership` "unconstructible via the binding factory"
cross-tenant-rejection pattern, ADR-0006 §"PERMISSION MODEL" (`realtime/authz.py`'s
per-channel `ChannelRole` matrix and its own honesty boundary naming
"tenant-definable custom roles" as post-investment), and the whole
post-investment tier's established "scoped seam, ADR-disclosed limitation,
honesty boundary" discipline (ADR-0012, ADR-0016 through ADR-0026).

## Context

The roadmap names R-027 "B2B tenant + RBAC 🏦 POST-INVESTMENT", the first task
of Rendly's Phase 4 "Platform-as-a-Service (VISION)" tier — the first
still-unchecked `R-` line in `anoryx-ecosystem-roadmap-v3.md`'s checklist as of
this run. Like R-026 before it, R-027 is not given its own descriptive
paragraph — it appears only as a name in the tier's shared task list, with the
shared estimate/dependency/risk line ("~12-22h each · Depends on:
R-005/R-007/R-008 + Delta · Risk: Medium-High"). This run resolves that
absence of detail the same way every prior unattended run in this tier has:
the most conservative, smallest honestly-buildable reading, named explicitly,
with no scope widening to fill in the blanks.

"B2B tenant + RBAC" as a full PaaS primitive is a large product space (tenant
self-serve provisioning, tenant-definable custom roles, a role/permission
admin UI, per-tenant plan/seat limits). This codebase already has real
pieces of the "tenant" half — `tenant.py`'s `Tenant` root aggregate (R-002)
and `profile.py`'s `Profile.org_role: OrgRole` (R-002) — but `OrgRole` has,
until now, exactly ONE reader in the whole codebase: `realtime/authz.py`
(R-006), and only as a coarse TOKEN-SCOPE pre-gate ahead of its real decision,
which is entirely about a single `Channel`'s `ChannelRole`. That module's own
docstring names the gap this ADR closes: "tenant-definable custom roles and
persisted per-channel ACLs are NOT built (post-investment; a D-017 analog)."
Building tenant-definable custom roles for real means persistence + an admin
surface — exactly the kind of invented, unrequested scope this tier's own
precedent (ADR-0018 Fork A, ADR-0025 Fork A/A4, ADR-0026 Fork A/A3) already
rejects. What is missing, and IS honestly buildable now with what already
exists, is simpler and sits directly underneath that deferred system: a fixed
matrix answering "what can this `OrgRole` do at the TENANT level" — `OrgRole`
has never had that answer at all, fixed or otherwise.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure, deterministic `OrgRole` → `PlatformPermission` resolution seam over the existing `Tenant` + `Profile`; NOT tenant-definable custom roles, NOT a persisted role/permission catalog, NOT any REST/wire/UI surface, NOT B2B tenant onboarding or self-serve provisioning)**

`src/rendly/platform_rbac.py` adds `PlatformPermission` (a new closed enum),
the fixed `_ORG_ROLE_PERMISSIONS` matrix, and two pure functions
(`resolve_platform_permissions`, `has_platform_permission`) composing the
EXISTING `Tenant` and `Profile` types — no change to either.

Rejected: A2 (tenant-definable/custom roles — a persisted, admin-editable
role/permission catalog). `realtime/authz.py`'s own honesty boundary already
named this NOT built, for both channel roles and by extension tenant roles;
building it for real needs a new table, a migration, and an admin surface —
squarely the D-017/R-027-full-scope territory this ADR's own conservative
reading defers, not the smallest honest slice. Rejected: A3 (wire this into a
REST/token layer, e.g. a new `contracts/openapi.yaml` endpoint or a
`realtime/authz.py` integration). No wire surface is requested; every prior
seam task in this tier (creator.py, premium.py, discovery_feed.py, …) shipped
as pure domain composition with zero contract change, and this ADR follows
the same discipline — a future REST/token layer MAY call
`has_platform_permission`, none does today. Rejected: A4 (B2B tenant
onboarding / self-serve signup / tenant provisioning). A distinct, larger
feature (a B2B analog of R-023's consumer-onboarding seam) with no existing
behavior in this codebase to compose against — exactly the kind of invented
scope this tier's Fork A discipline already rejects elsewhere.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is a FIXED
permission-resolution RULE only — `OrgRole` stays the same three-member
`{admin, member, guest}` enum from R-001/`enums.py`, unchanged and
un-extended; no tenant can define its own roles or permissions; nothing here
is reachable from the network (no endpoint, no token, no UI); and no B2B
tenant onboarding/provisioning exists. "B2B tenant + RBAC" as a full PaaS
primitive remains almost entirely unbuilt; this ADR closes one narrow, real
sub-problem of it (giving `OrgRole` an actual, checkable tenant-level meaning)
and names everything else explicitly below.

### Fork B — the permission catalog: **B1 (three closed, tenant-wide capabilities: `MANAGE_TENANT_MEMBERS`, `MANAGE_TENANT_CHANNELS`, `VIEW_TENANT_AUDIT_LOG`)**

Each is the tenant-wide analog of something this codebase already gates
per-channel or names as an explicit product goal: `MANAGE_TENANT_MEMBERS` and
`MANAGE_TENANT_CHANNELS` are the org-wide counterparts of
`realtime.authz.ChannelAction.MANAGE_MEMBERS`/`MAP_TO_TEAM` (which that module
scopes to ONE channel's roster, never the tenant's); `VIEW_TENANT_AUDIT_LOG`
names R-008's "complete administrative audit/oversight of all internal comms"
goal as a checkable capability (R-008/R-009's archiving stays the actual
audit-log READER — this module only names the capability of being ALLOWED to
view it; it does not read or expose any archived record itself).

Rejected: B2 (an open/extensible permission catalog, e.g. a caller-supplied
permission string). Mirrors `premium.py`/`creator.py`'s own rejection of a
dynamic feature catalog — the whole point of a closed enum here is that
`PlatformPermission` names a small, reviewable, exhaustive set, not an
arbitrary string a caller could invent. Rejected: B3 (a single `is_admin`
boolean instead of a permission set). Would collapse three genuinely distinct
kinds of tenant-level authority (managing the roster, managing channels,
viewing the audit trail) into one flag, discarding the one piece of real
product value a permission SET has over a role check: a future, narrower
caller can ask "can this profile view the audit log" without also asking "is
this profile an admin of everything."

### Fork C — the role → permission matrix: **C1 (`ADMIN` holds all three; `MEMBER` and `GUEST` hold none — a two-tier ALL-or-NOTHING matrix)**

`OrgRole` has no tier between `ADMIN` and `MEMBER` today — `enums.py`'s own
docstring is explicit: "there is deliberately no `owner`" at the org level.
A two-tier all-or-nothing matrix is therefore the only matrix the EXISTING
enum actually supports without inventing a new role, which Fork A already
rejected. This mirrors how `OrgRole` is used everywhere else in the codebase
today: as a coarse, binary-in-practice pre-gate, never a graduated scale.

Rejected: C2 (grant `MEMBER` a subset, e.g. `VIEW_TENANT_AUDIT_LOG`). No
product requirement motivates it, and it would make this module the FIRST
place in the codebase where `MEMBER` carries an `OrgRole`-driven capability —
a larger interpretive leap than reusing the existing all-or-nothing pattern
every other `OrgRole` consumer already assumes. Rejected: C3 (`GUEST` holds a
distinct, non-empty subset from `MEMBER`). Same reasoning — nothing in this
codebase today distinguishes `GUEST` from `MEMBER` at the org level (only
`ChannelRole` does, per-channel), so inventing a distinction here would be
new, unrequested scope.

### Fork D — the cross-tenant guard: **D1 (`resolve_platform_permissions` RAISES `ValueError` when `profile.tenant_id != tenant.tenant_id`, never a silent empty-set/`False`)**

Mirrors the EXISTING precedent in `bind_membership`/`bind_profile`: a caller
passing a `Tenant` and a `Profile` that disagree is a caller bug, not a
security decision this function is positioned to make quietly. Failing loud
(an exception a caller cannot ignore) is more conservative than failing to an
indistinguishable "no permissions" result, which could mask the bug behind
what looks like a legitimate deny.

Rejected: D2 (resolve to an empty permission set on a cross-tenant mismatch,
i.e. fold the guard into the fail-closed default). Would make a caller's bug
(passing mismatched objects) silently indistinguishable from a correctly
resolved "this profile really has no permissions" answer — worse for
debugging and no more secure, since the caller already holds both objects and
the mismatch is a construction-time error, not a runtime authorization
outcome.

## What is deliberately NOT built here (named, not silently skipped)

- **No tenant-definable/custom roles, no persisted role/permission catalog.**
  `OrgRole` is unchanged: still the fixed three-member enum from
  `enums.py`/R-001. See Fork A/A2.
- **No REST/wire surface, no UI, no token/scope integration.**
  `contracts/openapi.yaml` and `contracts/rendly-domain.schema.json` are
  unchanged; `realtime/authz.py`'s existing per-channel matrix and
  `_REQUIRED_SCOPE` pre-gate are untouched — this module is not called from
  anywhere in the request path today.
- **No B2B tenant onboarding, self-serve signup, or tenant provisioning
  workflow.** `Tenant` construction is unchanged (still just `tenant_id` +
  `created_at`, per `tenant.py`'s own "deliberately minimal... nothing on the
  wire needs one" YAGNI note).
- **No seat limits, billing, or plan tiers tied to a tenant.** Real
  monetization/billing wiring remains Delta/X-005 territory — a different,
  still-unshipped cross-product task Rendly's builder has no write access to
  regardless of task framing (same deferral R-025/ADR-0025 and
  R-026/ADR-0026 already made for their own monetization edges).
- **No persistence.** This is a pure function of caller-supplied `Tenant`
  and `Profile` objects — no new table, no new migration, no RLS change.
- **No wiring of `VIEW_TENANT_AUDIT_LOG` to an actual audit-log READ.** This
  module names the CAPABILITY only; R-008/R-009's archiving remains the only
  code that reads an audit record.

## Consequences

- Rendly's domain layer gains its first tenant-scoped RBAC primitive:
  `OrgRole` — carried by every `Profile` since R-002 but read by exactly one
  module (`realtime/authz.py`, as a coarse scope pre-gate) — now has a real,
  checkable, fixed meaning at the platform level, composable by any future
  caller (a future REST/token layer, or a future B2B provisioning task)
  without that caller re-deriving the role-to-capability mapping itself.
- No new attack surface is introduced: no new network endpoint, no new table,
  no new migration, no RLS change, no new identifier type, and the one
  guard this module adds (the cross-tenant `ValueError`) is a stricter check
  than existed before (previously nothing prevented a caller from mismatching
  a `Tenant` and a `Profile` when reasoning about `OrgRole` — now it is a hard
  error).
- The roadmap's R-027 checklist line is intentionally NOT marked "the full
  real B2B tenant platform (onboarding + custom roles + admin UI + billing)
  shipped" — it is marked shipped as THIS scoped fixed-permission-matrix seam,
  exactly as R-012/R-016 through R-026 were, with every deferred piece named
  above as the obvious next slice for a future, separately-dispatched task.
