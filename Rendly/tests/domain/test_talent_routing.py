"""R-028: the permission-gated, intra-tenant talent-routing + skills-inventory
seam (talent_routing.py), composing R-016's intent.py, R-021's opportunity.py, and
R-027's platform_rbac.py."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from rendly.enums import OrgRole
from rendly.intent import IntentProfile, bind_intent_profile
from rendly.opportunity import Opportunity, OpportunityKind, bind_opportunity
from rendly.profile import Profile
from rendly.talent_routing import (
    MAX_ROSTER_ENTRIES,
    build_skills_inventory,
    route_talent,
)
from rendly.tenant import Tenant

_NOW = datetime(2026, 7, 11, 12, 0, 0, tzinfo=timezone.utc)
_TENANT_ID = "12121212-1212-4212-8212-121212121212"
_OTHER_TENANT_ID = "99999999-9999-4999-8999-999999999999"


def _tenant(tenant_id: str = _TENANT_ID) -> Tenant:
    return Tenant(tenant_id=tenant_id, created_at=_NOW)


def _profile(
    user_id: str, org_role: OrgRole = OrgRole.MEMBER, tenant_id: str = _TENANT_ID
) -> Profile:
    return Profile(user_id=user_id, tenant_id=tenant_id, org_role=org_role)


def _intent(profile: Profile, *, offering: tuple[str, ...] = ()) -> IntentProfile:
    return bind_intent_profile(profile, seeking=(), offering=offering, opted_in_at=_NOW)


def _opportunity(poster: Profile, *, required_skills: tuple[str, ...] = ()) -> Opportunity:
    return bind_opportunity(
        poster,
        title="Internal transfer",
        kind=OpportunityKind.FULL_TIME,
        required_skills=required_skills,
        posted_at=_NOW,
    )


_ADMIN = _profile("11111111-1111-4111-8111-111111111111", OrgRole.ADMIN)
_MEMBER = _profile("22222222-2222-4222-8222-222222222222", OrgRole.MEMBER)


# --- build_skills_inventory: the permission-gated roster -----------------------------------------


def test_build_skills_inventory_projects_offering_tags():
    alice = _profile("33333333-3333-4333-8333-333333333333")
    bob = _profile("44444444-4444-4444-8444-444444444444")
    inventory = build_skills_inventory(
        _tenant(),
        _ADMIN,
        [
            (alice, _intent(alice, offering=("python", "rust"))),
            (bob, _intent(bob, offering=("go",))),
        ],
    )
    assert len(inventory) == 2
    assert inventory[0].user_id == alice.user_id
    assert inventory[0].skills == ("python", "rust")
    assert inventory[1].user_id == bob.user_id
    assert inventory[1].skills == ("go",)


def test_build_skills_inventory_preserves_input_order():
    alice = _profile("33333333-3333-4333-8333-333333333333")
    bob = _profile("44444444-4444-4444-8444-444444444444")
    inventory = build_skills_inventory(
        _tenant(), _ADMIN, [(bob, _intent(bob)), (alice, _intent(alice))]
    )
    assert [entry.user_id for entry in inventory] == [bob.user_id, alice.user_id]


def test_build_skills_inventory_requires_the_permission():
    alice = _profile("33333333-3333-4333-8333-333333333333")
    with pytest.raises(PermissionError, match="MANAGE_TENANT_MEMBERS"):
        build_skills_inventory(_tenant(), _MEMBER, [(alice, _intent(alice))])


def test_build_skills_inventory_rejects_cross_tenant_actor():
    other_tenant_admin = _profile(
        "55555555-5555-4555-8555-555555555555", OrgRole.ADMIN, tenant_id=_OTHER_TENANT_ID
    )
    with pytest.raises(ValueError, match="cross-tenant actor"):
        build_skills_inventory(_tenant(), other_tenant_admin, [])


def test_build_skills_inventory_rejects_a_cross_tenant_member():
    outsider = _profile("66666666-6666-4666-8666-666666666666", tenant_id=_OTHER_TENANT_ID)
    with pytest.raises(ValueError, match="cross-tenant member profile"):
        build_skills_inventory(_tenant(), _ADMIN, [(outsider, _intent(outsider))])


def test_build_skills_inventory_rejects_a_mismatched_pair():
    alice = _profile("33333333-3333-4333-8333-333333333333")
    bob = _profile("44444444-4444-4444-8444-444444444444")
    with pytest.raises(ValueError, match="do not describe the same user"):
        build_skills_inventory(_tenant(), _ADMIN, [(alice, _intent(bob))])


def test_build_skills_inventory_rejects_oversized_roster():
    member = _profile("33333333-3333-4333-8333-333333333333")
    roster = [(member, _intent(member))] * (MAX_ROSTER_ENTRIES + 1)
    with pytest.raises(ValueError, match="must not exceed"):
        build_skills_inventory(_tenant(), _ADMIN, roster)


# --- route_talent: intra-tenant opportunity routing ----------------------------------------------


def test_route_talent_ranks_by_matched_skill_count():
    alice = _profile("33333333-3333-4333-8333-333333333333")
    bob = _profile("44444444-4444-4444-8444-444444444444")
    opportunity = _opportunity(_ADMIN, required_skills=("python", "rust"))
    matches = route_talent(
        _tenant(),
        _ADMIN,
        opportunity,
        [
            (alice, _intent(alice, offering=("python",))),
            (bob, _intent(bob, offering=("python", "rust"))),
        ],
    )
    assert [m.subject_user_id for m in matches] == [bob.user_id, alice.user_id]
    assert matches[0].score == 2
    assert matches[1].score == 1


def test_route_talent_excludes_non_matching_candidates():
    alice = _profile("33333333-3333-4333-8333-333333333333")
    opportunity = _opportunity(_ADMIN, required_skills=("python",))
    matches = route_talent(
        _tenant(), _ADMIN, opportunity, [(alice, _intent(alice, offering=("go",)))]
    )
    assert matches == []


def test_route_talent_requires_the_permission():
    alice = _profile("33333333-3333-4333-8333-333333333333")
    opportunity = _opportunity(_ADMIN, required_skills=("python",))
    with pytest.raises(PermissionError, match="MANAGE_TENANT_MEMBERS"):
        route_talent(_tenant(), _MEMBER, opportunity, [(alice, _intent(alice))])


def test_route_talent_rejects_a_cross_tenant_opportunity():
    other_tenant_admin = _profile(
        "55555555-5555-4555-8555-555555555555", OrgRole.ADMIN, tenant_id=_OTHER_TENANT_ID
    )
    opportunity = _opportunity(other_tenant_admin, required_skills=("python",))
    with pytest.raises(ValueError, match="cross-tenant opportunity"):
        route_talent(_tenant(), _ADMIN, opportunity, [])


def test_route_talent_rejects_a_cross_tenant_candidate():
    outsider = _profile("66666666-6666-4666-8666-666666666666", tenant_id=_OTHER_TENANT_ID)
    opportunity = _opportunity(_ADMIN, required_skills=("python",))
    with pytest.raises(ValueError, match="cross-tenant candidate"):
        route_talent(
            _tenant(), _ADMIN, opportunity, [(outsider, _intent(outsider, offering=("python",)))]
        )


def test_route_talent_respects_limit():
    candidates = []
    for i in range(3):
        member = _profile(f"7777777{i}-7777-4777-8777-777777777777")
        candidates.append((member, _intent(member, offering=("python",))))
    opportunity = _opportunity(_ADMIN, required_skills=("python",))
    matches = route_talent(_tenant(), _ADMIN, opportunity, candidates, limit=2)
    assert len(matches) == 2


def test_route_talent_rejects_oversized_candidate_pool():
    member = _profile("33333333-3333-4333-8333-333333333333")
    opportunity = _opportunity(_ADMIN, required_skills=("python",))
    candidates = [(member, _intent(member, offering=("python",)))] * (MAX_ROSTER_ENTRIES + 1)
    with pytest.raises(ValueError, match="must not exceed"):
        route_talent(_tenant(), _ADMIN, opportunity, candidates)
