"""Profile — the internal affiliation overlay on a User (FORK E = E1).

HONESTY BOUNDARY (verbatim, non-removable): in the MVP, "intent" reduces to the
User's org-role + team-affiliation fields ONLY. There is NO matching algorithm, NO
preference vectors, and NO Intent entity. Intent-based matching is the
post-investment B2C tier (R-016 → R-026) and is explicitly deferred. The task name
("Intent + Matching") describes that future tier, not anything implemented here.

``Profile`` is the strict SUPERSET R-002 adds over R-001's wire projection: it
carries ``org_role`` (FORK B = B1) and ``team`` affiliation that R-001's ``User``
wire shape does NOT expose. These internal fields are never serialized through the
locked, closed ``User`` shape, so they are NOT a contract change to R-001 — R-001's
``User`` stays the public projection and R-004 persists this richer record.

Cross-entity invariant: a ``Profile`` belongs to exactly one ``User`` and shares
its tenant. The canonical construction path :func:`bind_profile` derives
``tenant_id``/``user_id`` from a real ``User`` object, so a profile whose tenant
disagrees with its user is unconstructible by that path (the structural seam,
mirroring :func:`rendly.membership.bind_membership`).
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

from .enums import OrgRole
from .identifiers import TenantId, UserId
from .user import User

# Team/department affiliation slug — internal only (never on R-001's wire). An empty
# string is not a team; absence is modelled as None (the field default), so a present
# team is bounded to 1..128 chars rather than admitting a meaningless "".
Team = Annotated[str, StringConstraints(min_length=1, max_length=128)]


class Profile(BaseModel):
    """A user's internal org affiliation: per-tenant role + team. Immutable."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: UserId
    tenant_id: TenantId
    org_role: OrgRole
    team: Team | None = None


def bind_profile(user: User, *, org_role: OrgRole, team: str | None = None) -> Profile:
    """Build a ``Profile`` bound to a real ``User`` (the canonical construction path).

    ``tenant_id`` and ``user_id`` are read FROM the ``User``, so the binding cannot
    produce a profile whose tenant disagrees with its user — tenant agreement is a
    structural property of this path, not a runtime check applied afterward. One
    profile per user is a uniqueness constraint enforced at persistence (R-004);
    here the binding fixes the (user, tenant) identity.
    """
    return Profile(
        user_id=user.user_id,
        tenant_id=user.tenant_id,
        org_role=org_role,
        team=team,
    )
