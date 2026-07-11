"""R-029: project/sprint workspaces + B2B analytics (workspace.py), composing
R-006's channel.py/membership.py and R-027's platform_rbac.py."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from rendly.channel import Channel
from rendly.enums import ChannelRole, ChannelType, OrgRole
from rendly.membership import Membership
from rendly.profile import Profile
from rendly.tenant import Tenant
from rendly.workspace import (
    MAX_ANALYTICS_MEMBERS,
    MAX_SPRINTS_PER_WORKSPACE,
    Sprint,
    compute_workspace_analytics,
    schedule_sprint,
)

_NOW = datetime(2026, 7, 11, 12, 0, 0, tzinfo=timezone.utc)
_TENANT_ID = "12121212-1212-4212-8212-121212121212"
_OTHER_TENANT_ID = "99999999-9999-4999-8999-999999999999"
_CHANNEL_ID = "14141414-1414-4414-8414-141414141414"
_OTHER_CHANNEL_ID = "15151515-1515-4515-8515-151515151515"
_CREATOR_ID = "13131313-1313-4313-8313-131313131313"


def _tenant(tenant_id: str = _TENANT_ID) -> Tenant:
    return Tenant(tenant_id=tenant_id, created_at=_NOW)


def _channel(channel_id: str = _CHANNEL_ID, tenant_id: str = _TENANT_ID) -> Channel:
    return Channel(
        channel_id=channel_id,
        tenant_id=tenant_id,
        name="proj-atlas",
        type=ChannelType.PRIVATE,
        created_by=_CREATOR_ID,
        created_at=_NOW,
    )


def _profile(
    user_id: str, org_role: OrgRole = OrgRole.MEMBER, tenant_id: str = _TENANT_ID
) -> Profile:
    return Profile(user_id=user_id, tenant_id=tenant_id, org_role=org_role)


def _membership(
    user_id: str, channel_id: str = _CHANNEL_ID, tenant_id: str = _TENANT_ID
) -> Membership:
    return Membership(
        channel_id=channel_id,
        tenant_id=tenant_id,
        user_id=user_id,
        role=ChannelRole.MEMBER,
        added_at=_NOW,
    )


def _window(start_offset_min: int, duration_min: int = 30) -> tuple[datetime, datetime]:
    start = _NOW + timedelta(minutes=start_offset_min)
    return start, start + timedelta(minutes=duration_min)


_ADMIN = _profile("11111111-1111-4111-8111-111111111111", OrgRole.ADMIN)
_MEMBER = _profile("22222222-2222-4222-8222-222222222222", OrgRole.MEMBER)


# --- Sprint construction -----------------------------------------------------------------------


def test_sprint_rejects_naive_starts_at():
    with pytest.raises(ValidationError):
        Sprint(
            sprint_id="33333333-3333-4333-8333-333333333333",
            channel_id=_CHANNEL_ID,
            tenant_id=_TENANT_ID,
            title="Sprint 1",
            starts_at=datetime(2026, 7, 11, 12, 0, 0),  # naive
            ends_at=_NOW + timedelta(days=14),
        )


def test_sprint_rejects_ends_before_starts():
    with pytest.raises(ValidationError, match="ends_at must be strictly after starts_at"):
        Sprint(
            sprint_id="33333333-3333-4333-8333-333333333333",
            channel_id=_CHANNEL_ID,
            tenant_id=_TENANT_ID,
            title="Sprint 1",
            starts_at=_NOW,
            ends_at=_NOW - timedelta(minutes=1),
        )


def test_sprint_is_frozen():
    sprint = schedule_sprint(
        _channel(), (), title="Sprint 1", starts_at=_window(0)[0], ends_at=_window(0)[1]
    )
    with pytest.raises(ValidationError):
        sprint.title = "Renamed"  # type: ignore[misc]


def test_sprint_rejects_extra_key():
    with pytest.raises(ValidationError):
        Sprint(
            sprint_id="33333333-3333-4333-8333-333333333333",
            channel_id=_CHANNEL_ID,
            tenant_id=_TENANT_ID,
            title="Sprint 1",
            starts_at=_NOW,
            ends_at=_NOW + timedelta(days=14),
            velocity=42,
        )


# --- schedule_sprint: happy path + determinism --------------------------------------------------


def test_schedule_sprint_mints_new_sprint_bound_to_channel():
    channel = _channel()
    starts_at, ends_at = _window(0, duration_min=60 * 24 * 14)
    sprint = schedule_sprint(channel, (), title="Sprint 1", starts_at=starts_at, ends_at=ends_at)
    assert sprint.channel_id == channel.channel_id
    assert sprint.tenant_id == channel.tenant_id
    assert sprint.starts_at == starts_at
    assert sprint.ends_at == ends_at


def test_schedule_sprint_accepts_back_to_back_non_overlapping_sprints():
    channel = _channel()
    first_start, first_end = _window(0, duration_min=30)
    first = schedule_sprint(channel, (), title="Sprint 1", starts_at=first_start, ends_at=first_end)
    second_start, second_end = _window(30, duration_min=30)  # starts exactly when first ends
    second = schedule_sprint(
        channel, (first,), title="Sprint 2", starts_at=second_start, ends_at=second_end
    )
    assert second.starts_at == first.ends_at


@pytest.mark.parametrize(
    ("offset", "duration"),
    [
        (0, 30),  # identical window
        (10, 10),  # fully nested inside the existing sprint
        (-10, 30),  # overlaps the start
        (20, 30),  # overlaps the end
    ],
    ids=["identical", "nested", "overlaps-start", "overlaps-end"],
)
def test_schedule_sprint_rejects_any_overlap_on_same_workspace(offset, duration):
    channel = _channel()
    existing = schedule_sprint(
        channel, (), title="Sprint 1", starts_at=_window(0)[0], ends_at=_window(0)[1]
    )
    new_start, new_end = _window(offset, duration)
    with pytest.raises(ValueError, match="overlaps"):
        schedule_sprint(
            channel, (existing,), title="Sprint 2", starts_at=new_start, ends_at=new_end
        )


def test_schedule_sprint_rejects_sprints_from_a_different_workspace():
    channel = _channel()
    other_channel = _channel(channel_id=_OTHER_CHANNEL_ID)
    foreign_sprint = schedule_sprint(
        other_channel, (), title="Foreign", starts_at=_window(0)[0], ends_at=_window(0)[1]
    )
    with pytest.raises(ValueError, match="cross-workspace existing sprint"):
        schedule_sprint(
            channel,
            (foreign_sprint,),
            title="Sprint 2",
            starts_at=_window(100)[0],
            ends_at=_window(100)[1],
        )


def test_schedule_sprint_enforces_max_sprints_per_workspace():
    channel = _channel()
    sprints: tuple[Sprint, ...] = ()
    for i in range(MAX_SPRINTS_PER_WORKSPACE):
        start, end = _window(i * 30, duration_min=30)
        sprints = (
            *sprints,
            schedule_sprint(channel, sprints, title=f"S{i}", starts_at=start, ends_at=end),
        )
    overflow_start, overflow_end = _window(MAX_SPRINTS_PER_WORKSPACE * 30, duration_min=30)
    with pytest.raises(ValueError, match="must not exceed"):
        schedule_sprint(
            channel, sprints, title="Overflow", starts_at=overflow_start, ends_at=overflow_end
        )


# --- compute_workspace_analytics: the permission-gated reporting rollup -------------------------


def test_compute_workspace_analytics_aggregates_counts_and_minutes():
    channel = _channel()
    memberships = [_membership("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")]
    sprint_a = schedule_sprint(
        channel, (), title="Sprint 1", starts_at=_window(-60 * 24)[0], ends_at=_window(-60)[0]
    )
    sprint_b = schedule_sprint(
        channel,
        (sprint_a,),
        title="Sprint 2",
        starts_at=_window(0)[0],
        ends_at=_window(60)[0],
    )
    analytics = compute_workspace_analytics(
        _tenant(),
        _ADMIN,
        channel,
        memberships,
        (sprint_a, sprint_b),
        as_of=_NOW,
    )
    assert analytics.member_count == 1
    assert analytics.sprint_count == 2
    assert analytics.completed_sprint_count == 1
    assert analytics.active_sprint == sprint_b
    assert analytics.upcoming_sprint is None
    assert analytics.total_scheduled_minutes == (60 * 24 - 60) + 60


def test_compute_workspace_analytics_reports_upcoming_sprint():
    channel = _channel()
    future_start, future_end = _window(60, duration_min=60)
    sprint = schedule_sprint(
        channel, (), title="Next sprint", starts_at=future_start, ends_at=future_end
    )
    analytics = compute_workspace_analytics(_tenant(), _ADMIN, channel, (), (sprint,), as_of=_NOW)
    assert analytics.active_sprint is None
    assert analytics.upcoming_sprint == sprint


def test_compute_workspace_analytics_breaks_active_ties_on_sprint_id():
    channel = _channel()
    a = Sprint(
        sprint_id="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        channel_id=channel.channel_id,
        tenant_id=channel.tenant_id,
        title="A",
        starts_at=_window(-30)[0],
        ends_at=_window(30)[0],
    )
    b = Sprint(
        sprint_id="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        channel_id=channel.channel_id,
        tenant_id=channel.tenant_id,
        title="B",
        starts_at=_window(-30)[0],
        ends_at=_window(30)[0],
    )
    analytics = compute_workspace_analytics(_tenant(), _ADMIN, channel, (), (b, a), as_of=_NOW)
    assert analytics.active_sprint == a


def test_compute_workspace_analytics_requires_the_permission():
    channel = _channel()
    with pytest.raises(PermissionError, match="VIEW_TENANT_AUDIT_LOG"):
        compute_workspace_analytics(_tenant(), _MEMBER, channel, (), (), as_of=_NOW)


def test_compute_workspace_analytics_rejects_cross_tenant_actor():
    channel = _channel()
    other_tenant_admin = _profile(
        "55555555-5555-4555-8555-555555555555", OrgRole.ADMIN, tenant_id=_OTHER_TENANT_ID
    )
    with pytest.raises(ValueError, match="cross-tenant actor"):
        compute_workspace_analytics(_tenant(), other_tenant_admin, channel, (), (), as_of=_NOW)


def test_compute_workspace_analytics_rejects_cross_tenant_channel():
    channel = _channel(tenant_id=_OTHER_TENANT_ID)
    with pytest.raises(ValueError, match="cross-tenant channel"):
        compute_workspace_analytics(_tenant(), _ADMIN, channel, (), (), as_of=_NOW)


def test_compute_workspace_analytics_rejects_a_cross_workspace_membership():
    channel = _channel()
    outsider_membership = _membership(
        "66666666-6666-4666-8666-666666666666", channel_id=_OTHER_CHANNEL_ID
    )
    with pytest.raises(ValueError, match="cross-workspace membership"):
        compute_workspace_analytics(
            _tenant(), _ADMIN, channel, (outsider_membership,), (), as_of=_NOW
        )


def test_compute_workspace_analytics_rejects_a_cross_workspace_sprint():
    channel = _channel()
    other_channel = _channel(channel_id=_OTHER_CHANNEL_ID)
    foreign_sprint = schedule_sprint(
        other_channel, (), title="Foreign", starts_at=_window(0)[0], ends_at=_window(30)[0]
    )
    with pytest.raises(ValueError, match="cross-workspace sprint"):
        compute_workspace_analytics(_tenant(), _ADMIN, channel, (), (foreign_sprint,), as_of=_NOW)


def test_compute_workspace_analytics_rejects_naive_as_of():
    channel = _channel()
    with pytest.raises(ValueError, match="as_of must be timezone-aware"):
        compute_workspace_analytics(
            _tenant(), _ADMIN, channel, (), (), as_of=datetime(2026, 7, 11, 12, 0, 0)
        )


def test_compute_workspace_analytics_rejects_oversized_membership_list():
    channel = _channel()
    memberships = [_membership("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")] * (
        MAX_ANALYTICS_MEMBERS + 1
    )
    with pytest.raises(ValueError, match="must not exceed"):
        compute_workspace_analytics(_tenant(), _ADMIN, channel, memberships, (), as_of=_NOW)


def test_compute_workspace_analytics_rejects_oversized_sprint_list():
    channel = _channel()
    sprint = schedule_sprint(
        channel, (), title="Sprint 1", starts_at=_window(0)[0], ends_at=_window(30)[0]
    )
    sprints = (sprint,) * (MAX_SPRINTS_PER_WORKSPACE + 1)
    with pytest.raises(ValueError, match="must not exceed"):
        compute_workspace_analytics(_tenant(), _ADMIN, channel, (), sprints, as_of=_NOW)
