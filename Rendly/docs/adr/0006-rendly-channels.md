# ADR-0006 — Rendly Role-Based Secure Channels + Manual Team Mapping (R-006)

Status: Accepted
Date: 2026-07-02
Builds on: ADR-0005 (chat runtime, async session pattern, RLS chat schema, the inspection seam),
ADR-0002 (domain — `ChannelRole`/`ChannelType`/`ChannelSource`, `bind_membership`), ADR-0003 (ES256
auth — identity/tenant/role off the verified token), R-001 (the locked wire contract).

## Context

R-005 shipped real-time chat with tenant RLS, membership-gated posts/reads, and a fail-closed
inspection seam — but it **stubbed per-channel role authorization**: `ChannelRole` (owner/admin/
member/guest) is written to the membership row and never read, and channel management is gated by
the `channels:admin` *scope* alone. R-006 builds the authorization delta R-005 deferred and adds a
MANUAL channel↔team mapping with a documented resolver seam.

Roadmap dependency D-016 (Delta team data) is NOT shipped (Delta's merged work is D-001→D-005, all
financial — no team entity exists), and no Orchestrator team-event contract is defined. So R-006
takes the roadmap's stated "or manual fallback" path: the automatic Delta mapping is **not built**
(honesty boundary), only the manual mapping + the seam a future auto impl plugs into.

### STEP 0a — what R-005 already enforced (audited from `origin/main`; not rebuilt)

- Membership-gated **posts** (`pipeline.py` — LIVE `is_member` pre-inspection + an atomic re-check
  in the insert txn, TOCTOU-closed) and membership-gated **REST history reads** (`rest.py` —
  `is_member` → non-member 404, no oracle). Both via `chat_repo.is_member` (row existence only).
- Coarse **scope** gates everywhere (WS connect `chat:read`, send `chat:write`, create
  `channels:write`, member-manage `channels:admin`), org-role-derived at token mint.
- Tenant RLS (`FORCE`, `rendly_app` `NOBYPASSRLS`, the `NULLIF` predicate in both `USING` and
  `WITH CHECK`), append-only messages by GRANT, cross-tenant membership structurally impossible (two
  same-tenant composite FKs).

**The gap R-006 closes:** no per-channel ROLE is ever read. `ChannelRole` is written, never
consulted; member-management is gated by the `channels:admin` scope alone, with **no check that the
caller owns/administers THAT channel** — an org-admin-scoped principal could add/remove members of
any channel, including private ones they aren't in. There is also no single authorization decision
point (checks are inlined at each WS/REST call site).

### Correction to ADR-0005's wording

ADR-0005 said "`source`/`external_ref` persist nullable". Verified against migration 0002: only
`external_ref` is nullable. `channels.source` is **NOT NULL** (server_default `'manual'`), and a
biconditional CHECK `ck_channels_external_ref_seam` enforces `(source='delta_team') = (external_ref
IS NOT NULL)`. So attaching a team label requires flipping `source` to `delta_team`; `manual` +
`external_ref` is DB-forbidden (the domain `Channel` model mirrors this). This does not change the
"reuse the columns" decision — it clarifies what the mapping write does.

## Decisions (one per resolved fork)

### Fork A — mapping storage: **A1 (reuse `source`/`external_ref`; NO migration)**
The manual mapping is an admin op that sets `source='delta_team'` + `external_ref='<opaque
tenant-scoped team label>'` on the existing `channels` row (`channels` already grants `rendly_app`
UPDATE; the biconditional CHECK is satisfied by writing both together). This matches ADR-0005's own
stated consequence ("R-006 maps channels to Delta teams by populating `source`/`external_ref`").
**R-006 adds no schema — no migration, and rule 9 does not fire.**

Honesty framing: `delta_team` denotes "team-mapped"; R-006 builds the **manual writer**, the
Delta-event **auto-writer** is reserved (D-016). The column does not lie — the channel *is*
team-mapped; only the writer differs. Provenance (manual-vs-Delta) is not recorded on the row; that
distinction is deferred to D-016 (the resolver can add a marker then).

Rejected: A2 (a separate `channel_team_map` table) — records provenance more richly but forces a
migration (rule 9) for no MVP benefit.

### Fork B — role→permission model: **B-channel (fixed in-code matrix on per-channel `ChannelRole`)**
A fixed permission matrix in code, keyed on the caller's per-channel `ChannelRole`
(owner/admin/member/guest, or non-member) × `ChannelType` × action. This is exactly the gap R-005
left. `OrgRole`/scope remains a coarse capability pre-gate: channel CREATE (no target channel exists)
stays gated by `channels:write` alone at `rest.create_channel` (unchanged), and each channel action
also requires its coarse scope. A new read-only repo helper `chat_repo.member_role()` reads the
per-channel role (`is_member` only returned a bool).

The matrix (fail-closed default DENY; a non-member is denied every action):

| action | public | private | dm |
|---|---|---|---|
| read | any member incl. guest; non-member DENY | same | participant; non-member DENY |
| post | owner/admin/member; guest DENY; non-member DENY | same | participant; else DENY |
| manage-members | owner/admin; else DENY | owner/admin; else DENY | **DENY (all roles)** |
| map-to-team | owner/admin; else DENY | owner/admin; else DENY | **DENY (all roles)** |

Rejected: B-org (OrgRole-only — coarse; an org admin manages every channel; leaves `ChannelRole`
unused); B-persisted ACL/override model (D-017 vision-tier; violates the fixed-roles honesty
boundary + lean surface).

### Fork C — team-membership resolver seam: **C1 (interface + manual impl + fail-closed)**
`TeamMembershipResolver` (ABC at `realtime/resolver.py`, mirroring the `realtime/inspector.py`
inspection seam) + `ManualResolver` now + a documented future Delta-event impl. For a team-mapped
(`delta_team`) channel the manual resolver treats `external_ref` as an **opaque tenant-scoped label**
and reads the caller's role from the **admin-managed `memberships` table** (RLS-scoped) — it does not
duplicate `is_member`, it delegates to `member_role`. The seam is the single point where a future
Delta-driven impl swaps the membership source with **no change to the authz layer**.

**Security tradeoff — fail-closed:** an unresolvable/unrecognized `source`, OR a resolver that
raises, yields DENY (empty member set → the authz matrix denies). No phantom members, no
default-open path. Cross-tenant is structurally impossible: the resolver reads only under the tenant
GUC (RLS), the map-to-team UPDATE runs under the tenant GUC (so it cannot write another tenant's
channel), and `external_ref` is an opaque charset-bounded label (`^[A-Za-z0-9._:-]{1,64}$`)
interpreted only within the tenant — the label grants no access, the (tenant-scoped) memberships do.

Rejected: C0 (no seam / hardcode manual) — a later D-016 would force a rewrite, and it loses the
seam that makes "manual-not-auto" verifiable.

### Fork D — migration: **none (rule 9 N/A)**
A1 + B-channel + C1 touch no tables/columns. The map op is an UPDATE on the existing GRANT; the new
work is code (the authz module, the resolver, two repo helpers). Rule 9 (head-pin bumps + chain
reversibility) fires only on a new migration, and there is none — stated for the record.

### Join/leave: **no new self-service endpoints (lean surface)**
R-005 has no self-service join/leave; a join is an owner/admin member-add and a leave is an
owner/admin member-remove. R-006 routes those existing `PUT`/`DELETE` member endpoints through the
`MANAGE_MEMBERS` decision; the matrix documents self-service join/leave semantics for a future task,
but no new endpoint is added.

### Contract surface (R-001 extension)
R-001's `openapi.yaml` carried `Channel.source`/`external_ref` (readable) and the `PATCH
/channels/{id}` (`updateChannel`, rename/archive) endpoint, but defined **no write surface for the
team mapping** — a gap for the R-006 deliverable. R-006 adds `PUT /channels/{channel_id}/team`
(`operationId: mapChannelTeam`, `channels:admin`, body `ChannelTeamMap`, responses 200 Channel /
400 / 401 / 403 / 404 / 500) + the `ChannelTeamMap` schema (`external_ref`, charset-bounded), a
dedicated single-responsibility mapping endpoint (chosen over overloading `updateChannel`, whose
documented purpose is rename/archive and which R-005 left unimplemented). The contract remains the
law — the implementation conforms to this added entry exactly. No other contract change.

## The single decision point

`realtime/authz.py::authorize(session, *, principal, channel, action, resolver)` is the ONE gate,
called from BOTH the WS pipeline (`handle_chat_send`, action `POST`, at the pre-inspection reject AND
the atomic in-txn re-check) and the REST layer (`upsert_member`/`remove_member` → `MANAGE_MEMBERS`,
`map_channel_team` → `MAP_TO_TEAM`, `list_messages` → `READ`). It applies: coarse scope gate → tenant
guard (defense in depth over RLS) → resolve the per-channel role via the seam (fail-closed) → the
pure `evaluate` matrix. `AuthzPrincipal` is built identically from the REST `AccessTokenClaims`
(`sub`/`tenant_id`/`scope_set()`) and the WS `Connection`, so both layers feed the same inputs and
reach the same outcome; identity is token-derived only (R-003 claim-injection defense preserved). A
denial is rendered non-oracle (WS `unauthorized` frame; REST tenant-scoped 404).

## Honesty boundaries (verbatim — non-removable)
- **Manual mapping only.** "R-006 implements MANUAL channel↔team mapping + a documented resolver
  seam. Automatic mapping requires D-016 (Delta team data — NOT shipped) + an Orchestrator team-event
  contract (NOT defined). Reserved, not built."
- **Resolver seam, not auto.** The `TeamMembershipResolver` seam ships with a manual impl only; the
  Delta-event-driven impl is a later task (it plugs in at the seam with no contract change). An
  unresolvable source fails closed.
- **Fixed roles, not custom.** The roles are the fixed `{owner, admin, member, guest}` enum;
  tenant-definable custom roles and persisted per-channel ACLs are NOT built (a D-017 analog).

## Consequences
- Channel management is now tightened: a bare `channels:admin` scope no longer authorizes managing or
  mapping a channel — the caller must hold the per-channel owner/admin role. The channel creator is
  the initial `owner` (R-005), so control is retained; an org admin who is not a channel owner/admin
  can no longer manage a private channel they are not part of (intended — private-channel
  confidentiality). A `DELETE` member on a non-existent channel now resolves 404 (was 204) — a
  no-oracle improvement; re-removing an existing channel's member is still idempotent 204.
- **DM participant seeding is NOT built (noted gap).** `POST /channels` seeds only the creator as
  the sole `owner` (R-005, unchanged), and R-006's matrix denies `MANAGE_MEMBERS` on a DM for every
  role — so a `dm` channel created through the API cannot reach its second participant via any
  authorized path yet. Denying member management on a DM is the correct policy (a DM's roster is not
  administrable), but the complementary "seed both participants at DM creation" flow is deferred to a
  later task; until then a DM is effectively single-occupant. This is disclosed here rather than
  papered over.
- A future D-016 + Orchestrator team-event contract provides a Delta-driven `TeamMembershipResolver`
  that resolves `external_ref` → Delta team → member set, failing closed when the feed is
  unavailable. It replaces `ManualResolver` at the seam with no change to `authz.py` or the wire.
- R-007 (signaling), R-008 (real inspection), R-009 (message hash chain) are unaffected; R-006 adds
  no message-path or contract change.
