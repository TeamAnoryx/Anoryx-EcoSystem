"""The team-membership resolution SEAM (R-006 FORK C) — interface + manual impl + fail-closed.

R-006 builds MANUAL channel<->team mapping (an admin sets a channel's ``source``/``external_ref``)
plus this documented resolver seam. The seam answers ONE question for the channel-authz decision
point: "what is this user's per-channel role in this channel?" — abstracting WHERE channel
membership comes from, so a future Delta-event-driven impl can supply team membership with NO change
to the authorization layer. It mirrors the R-005 inspection seam (``inspector.py``): build the seam
+ a fail-closed default now; the real/automatic impl is a later task.

HONESTY BOUNDARY (verbatim): "R-006 implements MANUAL channel<->team mapping + a documented
resolver seam. Automatic mapping requires D-016 (Delta team data - NOT shipped) + an Orchestrator
team-event contract (NOT defined). Reserved, not built." And: "manual-mapping-only;
resolver-seam-not-auto; fixed-roles-not-custom."

THE MANUAL IMPL returns ADMIN-MANAGED membership: for both a self-managed (``manual``) channel and a
team-mapped (``delta_team``) channel it reads the caller's role from the ``memberships`` table
(RLS-scoped to the tenant), treating a mapped channel's ``external_ref`` as an OPAQUE tenant-scoped
label. It NEVER dereferences ``external_ref`` to another system, so the label can never become an
access vector (cross-tenant or otherwise) — the tenant-scoped memberships grant access, the label
does not.

FAIL-CLOSED CONTRACT the authz point enforces around this seam (mirrors the inspector seam):
  * ``resolve_role`` returns ``resolved`` with a role / None -> authz applies the permission matrix
    (None means "not a member" -> DENY).
  * ``resolve_role`` returns ``unresolvable`` (a source the resolver cannot map to a membership
    set) -> authz DENIES: no phantom members, no open access.
  * ``resolve_role`` RAISES any exception          -> authz DENIES: a resolver failure is NEVER a
    silent allow.
The FUTURE Delta impl fails closed (``unresolvable``) whenever the Delta team feed is unavailable,
so an unresolvable team never widens access.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal

from sqlalchemy.ext.asyncio import AsyncSession

from ..channel import Channel
from ..enums import ChannelRole, ChannelSource
from ..persistence import chat_repo

ResolutionStatus = Literal["resolved", "unresolvable"]


@dataclass(frozen=True)
class MembershipResolution:
    """A resolver verdict.

    ``role`` is the caller's ``ChannelRole`` when ``resolved`` and a member, or ``None`` when
    ``resolved`` but the caller is not a member. ``role`` is IGNORED when the status is
    ``unresolvable`` (a fail-closed DENY at the authz point) — an ``unresolvable`` verdict never
    carries a usable role.
    """

    status: ResolutionStatus
    role: ChannelRole | None = None

    @staticmethod
    def resolved(role: ChannelRole | None) -> "MembershipResolution":
        return MembershipResolution(status="resolved", role=role)

    @staticmethod
    def unresolvable() -> "MembershipResolution":
        return MembershipResolution(status="unresolvable", role=None)


class TeamMembershipResolver(ABC):
    """The resolver seam interface. ``resolve_role`` is async so a real (D-016) impl can call out to
    the Orchestrator/Delta team feed without blocking the event loop; the authz point awaits it
    in-line.

    An implementation MUST NOT return ``resolved`` with a fabricated role on an internal failure — it
    must return ``unresolvable`` or raise, and the authz point treats BOTH as a fail-closed DENY.
    Returning ``resolved`` is a positive assertion that the membership was actually looked up.
    """

    @abstractmethod
    async def resolve_role(
        self, session: AsyncSession, *, tenant_id: str, channel: Channel, user_id: str
    ) -> MembershipResolution:
        """Resolve the user's per-channel role for ``channel`` (fail-closed at the caller)."""
        raise NotImplementedError


# The sources the manual resolver can resolve from admin-managed memberships. A source OUTSIDE this
# set is UNRESOLVABLE -> fail-closed DENY. ``ChannelSource`` is a closed 2-value enum today, so the
# defensive branch is unreachable via a validated ``Channel``; it exists so the seam fails closed on
# any source it does not understand (e.g. a future source added before its resolver is wired).
_MANUAL_RESOLVABLE_SOURCES = frozenset({ChannelSource.MANUAL, ChannelSource.DELTA_TEAM})


class ManualResolver(TeamMembershipResolver):
    """R-006 default: membership is ADMIN-MANAGED via the ``memberships`` table (RLS-scoped).

    HONESTY BOUNDARY: this performs NO Delta lookup. For a ``delta_team`` (team-mapped) channel it
    treats ``external_ref`` as an OPAQUE label and STILL reads the caller's role from the
    admin-managed ``memberships`` table — the manual fallback. It exists so the fail-closed wiring is
    REAL and testable now; D-016 replaces it with a Delta-event-driven impl (which fails closed when
    the team feed is unavailable) at this exact seam, with no change to the authz layer.
    """

    async def resolve_role(
        self, session: AsyncSession, *, tenant_id: str, channel: Channel, user_id: str
    ) -> MembershipResolution:
        if channel.source not in _MANUAL_RESOLVABLE_SOURCES:  # pragma: no cover - defensive
            # A source this resolver does not understand -> fail closed (no phantom members).
            # Unreachable via a validated Channel (ChannelSource is a closed enum both of whose
            # values are resolvable); present so the seam fails closed on any future/unknown source.
            return MembershipResolution.unresolvable()
        role = await chat_repo.member_role(
            session, tenant_id=tenant_id, channel_id=channel.channel_id, user_id=user_id
        )
        return MembershipResolution.resolved(role)
