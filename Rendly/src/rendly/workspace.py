"""Project/sprint workspaces + B2B analytics — a channel-reusing sprint-scheduling
+ permission-gated reporting seam over R-006's ``Channel``/``Membership`` and
R-027's platform RBAC (R-029 = FORK A1/B1/C1/D1/E1).

HONESTY BOUNDARY (verbatim, non-removable): "Project/sprint workspaces + B2B
analytics" ships here as a DETERMINISTIC sprint-scheduling seam over an EXISTING
``channel.Channel`` (no new persisted workspace entity) plus a PERMISSION-GATED,
deterministic aggregation over caller-supplied membership + sprint lists — no
task/issue tracking, no burndown/velocity concept, no BI-grade analytics engine,
no persistence, and no REST/wire/UI surface. This is a deliberate scope-down of
R-029 (~12-22h, 🏦 POST-INVESTMENT, third task of Rendly's Phase 4
"Platform-as-a-Service" tier, "Depends on: R-005/R-007/R-008 + Delta") to a
minimal seam, in the same spirit as R-012/R-016 through R-028's own scoped
deliveries (see ADR-0029).

"Project/sprint workspace" reuses ``channel.Channel`` (R-006) directly as the
workspace container — a tenant-scoped, named, membership-rostered entity is
already exactly what a workspace needs, so no second, parallel ``Workspace``
entity is invented (see ADR-0029 Fork A). "Sprint" ships as a NEW, minimal
:class:`Sprint` type (title + time window only) scheduled via
:func:`schedule_sprint`, which mirrors :func:`rendly.event.schedule_session`'s
deterministic, bounded, no-overlap agenda discipline (R-013) — deliberately NOT
a reuse of :class:`rendly.event.EventSession`, whose ``capacity`` field is
locked to that module's own R-011-huddle honesty boundary and has no meaning for
a sprint (see ADR-0029 Fork B). "B2B analytics" ships as
:func:`compute_workspace_analytics` — a permission-gated, deterministic
aggregation (member/sprint counts, the active/upcoming sprint, total scheduled
minutes) over a caller-supplied roster + sprint history, gated by R-027's
EXISTING ``PlatformPermission.VIEW_TENANT_AUDIT_LOG`` (see ADR-0029 Fork D).

NOT BUILT HERE: a new persisted ``Workspace``/``Project`` entity (reuses
``channel.Channel`` unchanged — see Fork A); task/issue tracking or any
burndown/velocity concept; parallel/concurrent sprints per workspace (every
sprint on one workspace must be non-overlapping, see Fork C); a BI-grade
analytics engine with historical trending or dashboards (this module computes
one deterministic snapshot from caller-supplied inputs, nothing is stored); any
REST/wire surface or UI (``contracts/openapi.yaml`` is unchanged); any new
``PlatformPermission`` member (reuses R-027's existing
``VIEW_TENANT_AUDIT_LOG`` — see Fork D); and any persistence (this is a pure
function of caller-supplied objects, no new table, no new migration).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from typing import Annotated

from pydantic import (
    BaseModel,
    ConfigDict,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)

from .channel import Channel
from .common import require_aware_utc
from .identifiers import ChannelId, SprintId, TenantId
from .membership import Membership
from .platform_rbac import PlatformPermission, has_platform_permission
from .profile import Profile
from .tenant import Tenant

# Mirrors `event.Title` (1..128) — a sprint's title is a persisted-once label,
# never empty.
SprintTitle = Annotated[str, StringConstraints(min_length=1, max_length=128)]

# Bounded-list discipline (mirrors `event.py`'s MAX_SESSIONS_PER_EVENT,
# `talent_routing.py`'s MAX_ROSTER_ENTRIES): a workspace's sprint agenda and the
# roster fed into analytics are capped so neither storage (once a follow-up task
# adds it) nor this module's own scans are exposed to an unbounded input.
MAX_SPRINTS_PER_WORKSPACE = 50
MAX_ANALYTICS_MEMBERS = 500


class Sprint(BaseModel):
    """One time-boxed sprint on a project workspace's (``Channel``'s) agenda.
    Immutable.

    Direct construction with hand-supplied ids is a lower-level primitive (mirrors
    ``EventSession``'s same reservation) that is NOT validated against a real
    ``Channel``; :func:`schedule_sprint` is the canonical, validated path.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    sprint_id: SprintId
    channel_id: ChannelId
    tenant_id: TenantId
    title: SprintTitle
    starts_at: datetime
    ends_at: datetime

    @field_validator("starts_at", "ends_at")
    @classmethod
    def _aware(cls, value: datetime, info: ValidationInfo) -> datetime:
        return require_aware_utc(value, info.field_name)

    @model_validator(mode="after")
    def _ends_after_starts(self) -> "Sprint":
        if self.ends_at <= self.starts_at:
            raise ValueError("ends_at must be strictly after starts_at")
        return self


class WorkspaceAnalytics(BaseModel):
    """A deterministic, point-in-time reporting snapshot of one project
    workspace (``Channel``). Immutable.

    A pure aggregation of caller-supplied inputs — nothing here is stored, and
    no history/trend is tracked across calls (see this module's HONESTY
    BOUNDARY).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    channel_id: ChannelId
    tenant_id: TenantId
    as_of: datetime
    member_count: int
    sprint_count: int
    completed_sprint_count: int
    active_sprint: Sprint | None
    upcoming_sprint: Sprint | None
    total_scheduled_minutes: int


def new_sprint_id() -> str:
    """Mint a caller-side sprint id (canonical dashed-hex UUID v4 — matches the
    ``identifiers.py`` wire-mirroring shape)."""
    return str(uuid.uuid4())


def _require_same_workspace(
    channel: Channel, other_tenant_id: str, other_channel_id: str, *, label: str
) -> None:
    if other_tenant_id != channel.tenant_id or other_channel_id != channel.channel_id:
        raise ValueError(
            f"cross-workspace {label} rejected: {label} tenant_id/channel_id != "
            "channel.tenant_id/channel_id (a project workspace's sprints and roster "
            "are scoped to ONE channel only)"
        )


def _overlaps(a: Sprint, b: Sprint) -> bool:
    return a.starts_at < b.ends_at and b.starts_at < a.ends_at


def schedule_sprint(
    channel: Channel,
    existing_sprints: Sequence[Sprint],
    *,
    title: str,
    starts_at: datetime,
    ends_at: datetime,
) -> Sprint:
    """Schedule one new sprint on ``channel``'s (the project workspace's)
    single-track agenda.

    Validates, in order:
    - every entry of ``existing_sprints`` actually belongs to ``channel``'s
      workspace (a mismatched ``channel_id``/``tenant_id`` is refused outright,
      mirroring ``event.schedule_session``'s same guard — a caller must not mix
      agendas),
    - ``len(existing_sprints) < MAX_SPRINTS_PER_WORKSPACE`` (bounded-list guard),
    - the new sprint's ``[starts_at, ends_at)`` window does not overlap any
      existing sprint on the SAME workspace (a project workspace runs one
      sprint cycle at a time — see this module's docstring / ADR-0029 Fork C).

    Raises ``ValueError`` on any violation (never silently drops or truncates).
    Returns the new ``Sprint`` with a freshly minted ``sprint_id`` — the caller
    owns appending it to its own agenda sequence (this function is pure and
    holds no state, exactly as ``event.schedule_session`` holds none).
    """
    if len(existing_sprints) >= MAX_SPRINTS_PER_WORKSPACE:
        raise ValueError(f"existing_sprints must not exceed {MAX_SPRINTS_PER_WORKSPACE} entries")

    for existing in existing_sprints:
        _require_same_workspace(
            channel, existing.tenant_id, existing.channel_id, label="existing sprint"
        )

    candidate = Sprint(
        sprint_id=new_sprint_id(),
        channel_id=channel.channel_id,
        tenant_id=channel.tenant_id,
        title=title,
        starts_at=starts_at,
        ends_at=ends_at,
    )

    for existing in existing_sprints:
        if _overlaps(candidate, existing):
            raise ValueError(
                "sprint overlaps an existing sprint on this workspace's single-track agenda"
            )

    return candidate


def _require_analytics_permission(tenant: Tenant, actor: Profile) -> None:
    if actor.tenant_id != tenant.tenant_id:
        raise ValueError("cross-tenant actor rejected: actor tenant_id != tenant.tenant_id")
    if not has_platform_permission(tenant, actor, PlatformPermission.VIEW_TENANT_AUDIT_LOG):
        raise PermissionError(
            "actor lacks PlatformPermission.VIEW_TENANT_AUDIT_LOG: workspace analytics is a "
            "gated, tenant-wide-visibility reporting operation (R-027)"
        )


def compute_workspace_analytics(
    tenant: Tenant,
    actor: Profile,
    channel: Channel,
    memberships: Sequence[Membership],
    sprints: Sequence[Sprint],
    *,
    as_of: datetime,
) -> WorkspaceAnalytics:
    """Compute a deterministic B2B analytics snapshot of ``channel`` (the project
    workspace), as of ``as_of``.

    Requires ``actor`` (the caller reading the analytics) to hold
    ``PlatformPermission.VIEW_TENANT_AUDIT_LOG`` within ``tenant`` — RAISES
    ``PermissionError`` otherwise (fail-closed, mirrors every gate in this
    module). Requires ``channel`` to belong to ``tenant`` — RAISES ``ValueError``
    otherwise.

    Every entry of ``memberships`` and ``sprints`` MUST belong to ``channel``'s
    workspace — RAISES ``ValueError`` on the first entry that does not (a
    cross-workspace membership or sprint is a caller bug, never silently
    dropped from the rollup — mirrors ``talent_routing.py``'s same discipline,
    ADR-0028 Fork C). Inputs beyond :data:`MAX_ANALYTICS_MEMBERS`/
    :data:`MAX_SPRINTS_PER_WORKSPACE` are rejected outright rather than
    silently truncated.

    ``member_count``/``sprint_count`` are plain counts. ``completed_sprint_count``
    counts sprints whose ``ends_at <= as_of``. ``active_sprint`` is the sprint
    (if any) whose window contains ``as_of`` (``starts_at <= as_of <
    ends_at``); ``upcoming_sprint`` is the soonest sprint whose ``starts_at >
    as_of`` (ties break on ``sprint_id`` ascending, mirroring every ``rank_*``/
    ``agenda`` sibling in this codebase). ``total_scheduled_minutes`` sums every
    sprint's duration, floored to whole minutes — an integer, never a float
    (this module reports minutes, not money; the integer-minor-units rule is
    Delta's, not a constraint this module needs, but whole minutes keep the
    result exactly reproducible regardless).
    """
    _require_analytics_permission(tenant, actor)
    if channel.tenant_id != tenant.tenant_id:
        raise ValueError("cross-tenant channel rejected: channel.tenant_id != tenant.tenant_id")

    as_of = require_aware_utc(as_of, "as_of")

    if len(memberships) > MAX_ANALYTICS_MEMBERS:
        raise ValueError(f"memberships must not exceed {MAX_ANALYTICS_MEMBERS} entries")
    if len(sprints) > MAX_SPRINTS_PER_WORKSPACE:
        raise ValueError(f"sprints must not exceed {MAX_SPRINTS_PER_WORKSPACE} entries")

    for membership in memberships:
        _require_same_workspace(
            channel, membership.tenant_id, membership.channel_id, label="membership"
        )
    for sprint in sprints:
        _require_same_workspace(channel, sprint.tenant_id, sprint.channel_id, label="sprint")

    completed = [s for s in sprints if s.ends_at <= as_of]
    active_candidates = sorted(
        (s for s in sprints if s.starts_at <= as_of < s.ends_at),
        key=lambda s: (s.starts_at, s.sprint_id),
    )
    upcoming_candidates = sorted(
        (s for s in sprints if s.starts_at > as_of),
        key=lambda s: (s.starts_at, s.sprint_id),
    )
    total_minutes = sum(int((s.ends_at - s.starts_at).total_seconds() // 60) for s in sprints)

    return WorkspaceAnalytics(
        channel_id=channel.channel_id,
        tenant_id=channel.tenant_id,
        as_of=as_of,
        member_count=len(memberships),
        sprint_count=len(sprints),
        completed_sprint_count=len(completed),
        active_sprint=active_candidates[0] if active_candidates else None,
        upcoming_sprint=upcoming_candidates[0] if upcoming_candidates else None,
        total_scheduled_minutes=total_minutes,
    )
