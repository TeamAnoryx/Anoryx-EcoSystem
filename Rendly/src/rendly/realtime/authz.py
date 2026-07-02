"""The single channel-authorization decision point (R-006).

ONE place decides whether a (verified-token principal, channel, action) is allowed, called from
BOTH the WebSocket send pipeline AND the chat REST layer, so per-channel role authorization has a
single source of truth instead of the scattered scope + ``is_member`` checks R-005 inlined at each
call site. R-005 wrote ``ChannelRole`` to the membership row but never read it; R-006 reads it here.

PERMISSION MODEL (FORK B = B-channel): a FIXED in-code matrix keyed on the caller's per-channel
``ChannelRole`` (owner/admin/member/guest, or non-member) x ``ChannelType`` x action. The
org-level ``OrgRole``/scope stays a coarse capability PRE-GATE (each action maps to a required
token scope); channel CREATE — which has no target channel yet — is gated by that scope alone
(``channels:write`` at ``rest.create_channel``, unchanged) and is not an action this point decides.

FAIL-CLOSED (the security spine of an authorization layer): the default is DENY. A missing scope, a
mismatched tenant, a non-member, an unresolvable team-membership source, or a resolver that raises
ALL deny. There is no default-open path. The per-channel role is resolved through the
``TeamMembershipResolver`` seam (``resolver.py``) so a future Delta-event impl can supply team
membership with no change here; today the manual resolver returns admin-managed membership and
treats a mapped channel's ``external_ref`` as an opaque tenant-scoped label.

HONESTY BOUNDARY (verbatim): "fixed-roles-not-custom." The roles are the fixed {owner, admin,
member, guest} enum; tenant-definable custom roles and persisted per-channel ACLs are NOT built
(post-investment; a D-017 analog).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy.ext.asyncio import AsyncSession

from ..channel import Channel
from ..enums import ChannelRole, ChannelType
from .resolver import TeamMembershipResolver


class ChannelAction(StrEnum):
    """The channel-scoped actions the single decision point gates.

    ``JOIN``/``LEAVE`` are NOT separate self-service endpoints in R-006 (lean surface): a join is an
    owner/admin ``MANAGE_MEMBERS`` add and a leave is an owner/admin ``MANAGE_MEMBERS`` remove, so
    they are decided as ``MANAGE_MEMBERS``. Channel CREATE is gated by scope alone (no target
    channel) and is not decided here.
    """

    READ = "read"
    POST = "post"
    MANAGE_MEMBERS = "manage_members"
    MAP_TO_TEAM = "map_to_team"


# Each action's coarse capability scope (the OrgRole-derived token scope). The per-channel role
# matrix below is the FINE gate; BOTH the scope and the matrix must pass. (On REST these scopes are
# ALSO enforced by an outer ``require_scope`` dependency — belt-and-suspenders, same scope names.)
_REQUIRED_SCOPE: dict[ChannelAction, str] = {
    ChannelAction.READ: "chat:read",
    ChannelAction.POST: "chat:write",
    ChannelAction.MANAGE_MEMBERS: "channels:admin",
    ChannelAction.MAP_TO_TEAM: "channels:admin",
}

# Any member (incl. guest) may READ. owner/admin/member may POST — a guest is read-only. Managing
# members + mapping to a team is owner/admin only (of THAT channel).
_READ_ROLES = frozenset(
    {ChannelRole.OWNER, ChannelRole.ADMIN, ChannelRole.MEMBER, ChannelRole.GUEST}
)
_POST_ROLES = frozenset({ChannelRole.OWNER, ChannelRole.ADMIN, ChannelRole.MEMBER})
_MANAGER_ROLES = frozenset({ChannelRole.OWNER, ChannelRole.ADMIN})


@dataclass(frozen=True)
class AuthzPrincipal:
    """The verified-token identity used for a channel-authorization decision.

    Built identically from the REST ``AccessTokenClaims`` and the WS ``Connection`` so BOTH layers
    feed the ONE decision point the same inputs. ``tenant_id``/``user_id`` are server-resolved off
    the verified token (never a request/frame/body field), and ``scopes`` is the granted scope set —
    so the payload being authorized can never widen the identity deciding it (claim-injection
    defense, preserved from R-003).
    """

    tenant_id: str
    user_id: str
    scopes: frozenset[str]


@dataclass(frozen=True)
class Decision:
    """An authorization outcome. ``reason`` is for server-side logging only; the WS/REST responses
    stay non-oracle (a generic deny) so a denial never leaks channel existence or membership."""

    allowed: bool
    reason: str

    @staticmethod
    def allow() -> "Decision":
        return Decision(allowed=True, reason="ok")

    @staticmethod
    def deny(reason: str) -> "Decision":
        return Decision(allowed=False, reason=reason)


def evaluate(
    channel_type: ChannelType, caller_role: ChannelRole | None, action: ChannelAction
) -> bool:
    """The PURE fixed permission matrix (no DB): (type, per-channel role, action) -> allow?

    Fail-closed: any combination not explicitly allowed returns False. ``caller_role is None`` means
    the caller is not a member of the channel and is denied every action. A DM's roster is its two
    participants and is not administrable, so ``MANAGE_MEMBERS``/``MAP_TO_TEAM`` are denied on a DM
    for every role.
    """
    if caller_role is None:
        return False  # non-member -> denied everything (fail-closed)
    if action is ChannelAction.READ:
        return caller_role in _READ_ROLES
    if action is ChannelAction.POST:
        return caller_role in _POST_ROLES
    if action is ChannelAction.MANAGE_MEMBERS or action is ChannelAction.MAP_TO_TEAM:
        if channel_type is ChannelType.DM:
            return False  # a DM cannot be member-managed or team-mapped
        return caller_role in _MANAGER_ROLES
    return False  # pragma: no cover - defensive: every ChannelAction is handled above (fail-closed)


async def authorize(
    session: AsyncSession,
    *,
    principal: AuthzPrincipal,
    channel: Channel,
    action: ChannelAction,
    resolver: TeamMembershipResolver,
) -> Decision:
    """THE decision point: coarse scope gate -> tenant guard -> resolve per-channel role -> matrix.

    Called with a TENANT session already opened by the caller (RLS scopes the role resolution). The
    per-channel role is obtained through the resolver seam; an unresolvable source OR a resolver that
    raises is a fail-closed DENY (never a silent allow). Both the WS pipeline and the REST layer call
    this, so the same (principal, channel, action) reaches the same outcome on either path.
    """
    if _REQUIRED_SCOPE[action] not in principal.scopes:
        return Decision.deny("scope")
    # Defense in depth: the channel was loaded under the caller's tenant session (RLS), so this
    # always holds — but an authz decision must never straddle tenants, so a mismatch fails closed.
    if channel.tenant_id != principal.tenant_id:
        return Decision.deny("tenant")
    try:
        resolution = await resolver.resolve_role(
            session, tenant_id=principal.tenant_id, channel=channel, user_id=principal.user_id
        )
    except (
        Exception
    ):  # noqa: BLE001 - a resolver failure is a fail-closed DENY, never a silent allow
        return Decision.deny("resolver_error")
    if resolution.status != "resolved":
        return Decision.deny("unresolvable")  # fail-closed: no phantom members, no open access
    if not evaluate(channel.type, resolution.role, action):
        return Decision.deny("role")
    return Decision.allow()
