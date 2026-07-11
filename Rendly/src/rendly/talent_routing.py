"""Talent routing — a permission-gated, intra-tenant composition seam over R-016's
intent matching + R-021's opportunity scoring + R-027's platform RBAC (R-028 =
FORK A1/B1/C1/D1).

HONESTY BOUNDARY (verbatim, non-removable): "Intent-driven talent routing + skills
inventory (B2B)" ships here as a DETERMINISTIC, PERMISSION-GATED, SAME-TENANT-ONLY
composition of three already-shipped seams — ``intent.IntentProfile`` (R-016, "what
I can offer"), ``opportunity.suggest_opportunity_match`` (R-021, the set-intersection
scorer), and ``platform_rbac.has_platform_permission`` (R-027, the fixed
``OrgRole`` -> ``PlatformPermission`` matrix) — no ML, no resume parsing, no
applicant-tracking workflow, no new skill-tag concept, and no persistence. This is a
deliberate scope-down of R-028 (~12-22h, 🏦 POST-INVESTMENT, second task of Rendly's
Phase 4 "Platform-as-a-Service" tier, "Depends on: R-005/R-007/R-008 + Delta") to a
minimal seam, in the same spirit as R-012/R-016 through R-027's own scoped
deliveries (see ADR-0028).

"Skills inventory" ships as :func:`build_skills_inventory` — a pure, permission-
gated ROSTER-BUILDING read over caller-supplied ``(Profile, IntentProfile)`` pairs,
reusing R-021's own observation that ``IntentProfile.offering`` ("what I can offer")
already IS a skill declaration, rather than inventing a parallel skill-tag concept.
"Talent routing" ships as :func:`route_talent` — a thin, tenant-scoped wrapper around
R-021's existing :func:`rendly.opportunity.suggest_opportunity_match` /
:func:`rendly.opportunity.rank_opportunities`.

DELIBERATE DIVERGENCE FROM ``opportunity.py`` (R-021), NOT an oversight: R-021's
scorer intentionally matches CROSS-tenant pairs (freelance/full-time hiring across
companies is definitionally cross-tenant). "Talent routing (B2B)" is the opposite
product shape — INTERNAL mobility/staffing within one's OWN organization — so every
function in this module requires the ``tenant``, the ``opportunity``, and every
candidate to share ONE ``tenant_id``, and RAISES ``ValueError`` (mirrors
``platform_rbac.resolve_platform_permissions``'s cross-tenant guard, ADR-0027 Fork D)
rather than silently filtering a cross-tenant entry out of the result.

PERMISSION-GATED, unlike every prior R-016->R-027 matching seam: building or reading
a tenant-wide roster of members' skills, or routing a member to an internal role, is
a materially more sensitive operation than a single opt-in-to-opt-in match (R-016/
R-021/R-022's own model) — it lets one caller see many members' data at once. Both
entry points here therefore require the acting ``Profile`` to hold
``PlatformPermission.MANAGE_TENANT_MEMBERS`` (``platform_rbac.py``, R-027) and RAISE
``PermissionError`` otherwise (fail-closed, never a silently empty result).

NOT BUILT HERE: a new opt-in type for "my skills" (deliberately REUSES R-016's
``IntentProfile.offering``, exactly as R-021 already did); a new ``Opportunity``
posting workflow (reuses R-021's existing ``Opportunity`` entity unchanged); a new
``PlatformPermission`` member (reuses R-027's existing ``MANAGE_TENANT_MEMBERS`` —
see Fork B below); any REST/wire surface or UI (``contracts/openapi.yaml`` is
unchanged); any persistence (this is a pure function of caller-supplied objects, no
new table, no new migration); and any actual staffing DECISION workflow (offer,
acceptance, transfer) — this module only ranks and reports candidates, it does not
move anyone into a role.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict

from .identifiers import TenantId, UserId
from .intent import IntentProfile
from .opportunity import Opportunity, OpportunityMatch, suggest_opportunity_match
from .platform_rbac import PlatformPermission, has_platform_permission
from .profile import Profile
from .tenant import Tenant

# Bounds the roster/candidate pool of a single call (mirrors intent.py's/
# opportunity.py's MAX_CANDIDATES/MAX_OPPORTUNITIES at the same magnitude — a
# DoS/cost guard, not a product decision about roster size).
MAX_ROSTER_ENTRIES = 500
MAX_ROUTING_MATCHES = 50
DEFAULT_ROUTING_LIMIT = 10


class SkillsInventoryEntry(BaseModel):
    """One member's skill declaration as it appears in a tenant's skills inventory.

    A thin, read-model projection of an existing ``IntentProfile.offering`` tag
    set — not a new persisted record (see this module's HONESTY BOUNDARY).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: UserId
    tenant_id: TenantId
    skills: tuple[str, ...]


def _require_same_tenant(tenant: Tenant, subject_tenant_id: str, *, label: str) -> None:
    if subject_tenant_id != tenant.tenant_id:
        raise ValueError(
            f"cross-tenant {label} rejected: {label} tenant_id != tenant.tenant_id "
            "(talent routing is intra-tenant only, unlike opportunity.py's deliberately "
            "cross-tenant freelance/full-time matching)"
        )


def _require_routing_permission(tenant: Tenant, actor: Profile) -> None:
    _require_same_tenant(tenant, actor.tenant_id, label="actor")
    if not has_platform_permission(tenant, actor, PlatformPermission.MANAGE_TENANT_MEMBERS):
        raise PermissionError(
            "actor lacks PlatformPermission.MANAGE_TENANT_MEMBERS: talent routing and the "
            "skills inventory are gated, tenant-wide-visibility operations (R-027)"
        )


def build_skills_inventory(
    tenant: Tenant,
    actor: Profile,
    members: Sequence[tuple[Profile, IntentProfile]],
) -> tuple[SkillsInventoryEntry, ...]:
    """Build the tenant's skills inventory: one entry per ``(Profile, IntentProfile)``
    pair in ``members``, each reporting that member's ``IntentProfile.offering`` tags.

    Requires ``actor`` (the caller building the inventory) to hold
    ``PlatformPermission.MANAGE_TENANT_MEMBERS`` within ``tenant`` — RAISES
    ``PermissionError`` otherwise (fail-closed, mirrors every gate in this module).

    Every entry in ``members`` MUST belong to ``tenant`` and be an internally
    consistent ``(Profile, IntentProfile)`` pair — RAISES ``ValueError`` on the first
    entry that is not (a cross-tenant or mismatched member is a caller bug, never
    silently dropped from the roster — mirrors ADR-0027 Fork D). ``members`` beyond
    :data:`MAX_ROSTER_ENTRIES` is rejected outright rather than silently truncated.

    Order is preserved from ``members`` (this is a roster, not a ranking — there is
    no score to sort by).
    """
    _require_routing_permission(tenant, actor)
    if len(members) > MAX_ROSTER_ENTRIES:
        raise ValueError(f"members must not exceed {MAX_ROSTER_ENTRIES} entries")

    entries = []
    for member_profile, member_intent in members:
        _require_same_tenant(tenant, member_profile.tenant_id, label="member profile")
        if (
            member_profile.user_id != member_intent.user_id
            or member_profile.tenant_id != member_intent.tenant_id
        ):
            raise ValueError("member profile/intent pair do not describe the same user")
        entries.append(
            SkillsInventoryEntry(
                user_id=member_profile.user_id,
                tenant_id=member_profile.tenant_id,
                skills=member_intent.offering,
            )
        )
    return tuple(entries)


def route_talent(
    tenant: Tenant,
    actor: Profile,
    opportunity: Opportunity,
    candidates: Sequence[tuple[Profile, IntentProfile]],
    *,
    limit: int = DEFAULT_ROUTING_LIMIT,
) -> list[OpportunityMatch]:
    """Rank internal candidates for an internal ``opportunity``, all within ONE tenant.

    Requires ``actor`` to hold ``PlatformPermission.MANAGE_TENANT_MEMBERS`` within
    ``tenant`` — RAISES ``PermissionError`` otherwise. Requires ``opportunity`` and
    every candidate in ``candidates`` to belong to ``tenant`` — RAISES ``ValueError``
    on the first mismatch (see this module's "DELIBERATE DIVERGENCE" docstring
    section: unlike ``opportunity.rank_opportunities``, this never silently matches
    or filters out a cross-tenant entry).

    Scoring itself is unchanged from R-021: delegates to
    :func:`rendly.opportunity.suggest_opportunity_match` per candidate. Deterministic:
    ties break on ``candidate_user_id`` ascending (mirrors every ``rank_*`` sibling in
    this codebase). ``limit`` is clamped to ``[0, MAX_ROUTING_MATCHES]``; ``candidates``
    beyond :data:`MAX_ROSTER_ENTRIES` is rejected outright rather than silently
    truncated.
    """
    _require_routing_permission(tenant, actor)
    _require_same_tenant(tenant, opportunity.tenant_id, label="opportunity")
    if len(candidates) > MAX_ROSTER_ENTRIES:
        raise ValueError(f"candidates must not exceed {MAX_ROSTER_ENTRIES} entries")
    bounded_limit = max(0, min(limit, MAX_ROUTING_MATCHES))

    matches = []
    for candidate_profile, candidate_intent in candidates:
        _require_same_tenant(tenant, candidate_profile.tenant_id, label="candidate")
        match = suggest_opportunity_match(candidate_profile, candidate_intent, opportunity)
        if match is not None:
            matches.append(match)

    matches.sort(key=lambda m: (-m.score, m.subject_user_id))
    return matches[:bounded_limit]
