"""Public embedding — a permission-gated, time-bounded grant + public-safe
projection seam over R-013's ``Event``/``EventSession`` agenda (R-030 =
FORK A1/B1/C1/D1/E1).

HONESTY BOUNDARY (verbatim, non-removable): "Public embedding API + developer
portal" ships here as a DETERMINISTIC authorization + data-shaping seam — a
tenant-admin-issued, time-bounded ``EmbedGrant`` naming exactly ONE ``Event``
as publicly embeddable, plus :func:`render_embed_manifest`, a pure projection
that turns that ``Event``'s agenda into the minimal public-safe payload a
future embed widget would serve. This is a deliberate scope-down of R-030
(~12-22h, 🏦 POST-INVESTMENT, fourth and final task of Rendly's Phase 4
"Platform-as-a-Service" tier, "Depends on: R-005/R-007/R-008 + Delta") to a
minimal seam, in the same spirit as R-012/R-016 through R-029's own scoped
deliveries (see ADR-0030).

NOT BUILT HERE (named, not silently skipped):
- **No developer portal.** No self-serve UI, no app registration workflow, no
  API-key issuance/rotation, no usage dashboards, no docs site. Nothing here
  is reachable from anywhere but a direct Python call.
- **No public embedding API.** No REST/wire surface — ``contracts/openapi.yaml``
  is unchanged, and nothing unauthenticated can reach this module today. What
  ships is the authorization-and-projection CORE such an endpoint would need
  underneath: who may authorize an embed, what it may honestly expose, and
  when it stops being valid.
- **No persisted, revocable API-key/credential system.** ``EmbedGrant`` is a
  plain, caller-managed capability object (mirrors ``workspace.Sprint``'s own
  no-persistence-yet reservation) — no new table, no new migration, no key
  store. Because there is no persistence there is also no revocation; see
  Fork C below for how this module compensates for that.
- **No embedding of ``channel.Channel`` content.** Only ``event.Event``/
  ``EventSession`` scheduling metadata (title + time window) may ever be
  named in a grant — see Fork A. Embedding actual chat messages, rosters, or
  huddle content would contradict R-008's data-sovereignty commitment
  ("logs/transcripts/records never leave company control"); this module has
  no code path that can even construct a grant over a ``Channel``.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, ValidationInfo, field_validator

from .common import require_aware_utc
from .event import Event, EventSession, agenda
from .identifiers import EmbedGrantId, EventId, TenantId
from .platform_rbac import PlatformPermission, has_platform_permission
from .profile import Profile
from .tenant import Tenant

# Mirrors `event.Title` — an event's title, reprojected onto the public manifest.
Title = Annotated[str, StringConstraints(min_length=1, max_length=128)]

# A leaked grant_id cannot be revoked (this module has no persistence, no
# revocation list) — bounding lifetime is the only mitigation available, so it
# is enforced unconditionally rather than left to caller discipline (ADR-0030
# Fork C). 90 days mirrors the ecosystem's existing "generous but bounded"
# convention (e.g. F-014 SSO transaction stores, Sentinel key rotation windows).
MAX_EMBED_GRANT_LIFETIME = timedelta(days=90)

# Bounded-list discipline (mirrors `event.py`'s MAX_SESSIONS_PER_EVENT,
# `workspace.py`'s MAX_SPRINTS_PER_WORKSPACE): the agenda projected into one
# manifest is capped so neither the eventual embed response nor this module's
# own scan is exposed to an unbounded input.
MAX_MANIFEST_SESSIONS = 50


class EmbedGrant(BaseModel):
    """A capability naming exactly one ``Event`` as publicly embeddable, valid
    only within ``[issued_at, expires_at)``. Immutable.

    Deliberately carries no ``host_id`` and no arbitrary caller-supplied scope —
    a grant names an event and a validity window only (see this module's
    HONESTY BOUNDARY); :func:`issue_embed_grant` is the canonical, permission-
    gated construction path.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    grant_id: EmbedGrantId
    tenant_id: TenantId
    event_id: EventId
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def _aware(cls, value: datetime, info: ValidationInfo) -> datetime:
        return require_aware_utc(value, info.field_name)

    @field_validator("expires_at")
    @classmethod
    def _bounded_lifetime(cls, value: datetime, info: ValidationInfo) -> datetime:
        issued_at = info.data.get("issued_at")
        if issued_at is None:
            # issued_at itself failed validation; nothing further to check here.
            return value
        if value <= issued_at:
            raise ValueError("expires_at must be strictly after issued_at")
        if value - issued_at > MAX_EMBED_GRANT_LIFETIME:
            raise ValueError(
                f"expires_at must be within {MAX_EMBED_GRANT_LIFETIME} of issued_at "
                "(an unrevocable grant must also be time-bounded)"
            )
        return value


class EmbedSessionSummary(BaseModel):
    """One agenda entry as it appears in a public embed manifest — title and
    time window only. Immutable.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    title: Title
    starts_at: datetime
    ends_at: datetime


class EmbedManifest(BaseModel):
    """The public-safe projection of one granted ``Event``'s agenda. Immutable.

    Deliberately excludes ``tenant_id``, ``event_id``, and ``host_id`` — none
    of a tenant's internal identifiers or a host's identity is public-safe by
    default; the manifest carries only the grant's own opaque ``grant_id`` and
    the event's public-facing title + agenda (see this module's HONESTY
    BOUNDARY).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    grant_id: EmbedGrantId
    event_title: Title
    sessions: tuple[EmbedSessionSummary, ...]


def new_embed_grant_id() -> str:
    """Mint a caller-side grant id (canonical dashed-hex UUID v4 — matches the
    ``identifiers.py`` wire-mirroring shape)."""
    return str(uuid.uuid4())


def _require_authorize_permission(tenant: Tenant, actor: Profile) -> None:
    if actor.tenant_id != tenant.tenant_id:
        raise ValueError("cross-tenant actor rejected: actor tenant_id != tenant.tenant_id")
    if not has_platform_permission(tenant, actor, PlatformPermission.MANAGE_TENANT_CHANNELS):
        raise PermissionError(
            "actor lacks PlatformPermission.MANAGE_TENANT_CHANNELS: authorizing a public "
            "embed is a gated, tenant-content-administration decision (R-027)"
        )


def issue_embed_grant(
    tenant: Tenant,
    actor: Profile,
    event: Event,
    *,
    issued_at: datetime,
    expires_at: datetime,
) -> EmbedGrant:
    """Issue a new :class:`EmbedGrant` authorizing ``event`` to be publicly
    embedded, valid for ``[issued_at, expires_at)``.

    Requires ``actor`` (the caller authorizing the embed) to hold
    ``PlatformPermission.MANAGE_TENANT_CHANNELS`` within ``tenant`` — RAISES
    ``PermissionError`` otherwise (fail-closed, mirrors every gate in this
    codebase's platform-RBAC-gated modules). Requires ``event`` to belong to
    ``tenant`` — RAISES ``ValueError`` otherwise. ``expires_at`` must be
    strictly after ``issued_at`` and within :data:`MAX_EMBED_GRANT_LIFETIME`
    of it (enforced by :class:`EmbedGrant` itself — see Fork C in ADR-0030).

    Returns the new ``EmbedGrant`` with a freshly minted ``grant_id`` — the
    caller owns storing/distributing it (this function is pure and holds no
    state, exactly as ``event.schedule_session`` holds none).
    """
    _require_authorize_permission(tenant, actor)
    if event.tenant_id != tenant.tenant_id:
        raise ValueError("cross-tenant event rejected: event.tenant_id != tenant.tenant_id")

    return EmbedGrant(
        grant_id=new_embed_grant_id(),
        tenant_id=tenant.tenant_id,
        event_id=event.event_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def is_grant_active(grant: EmbedGrant, *, as_of: datetime) -> bool:
    """Whether ``grant`` is currently valid at ``as_of``
    (``issued_at <= as_of < expires_at``)."""
    as_of = require_aware_utc(as_of, "as_of")
    return grant.issued_at <= as_of < grant.expires_at


def render_embed_manifest(
    grant: EmbedGrant,
    event: Event,
    sessions: Sequence[EventSession],
    *,
    as_of: datetime,
) -> EmbedManifest:
    """Render the public-safe :class:`EmbedManifest` for ``grant``, projecting
    ``event``'s title and ``sessions`` agenda.

    Requires ``grant`` to actually name ``event`` (``grant.event_id`` /
    ``grant.tenant_id`` must match ``event.event_id`` / ``event.tenant_id``) —
    RAISES ``ValueError`` otherwise. Requires ``grant`` to be active at
    ``as_of`` (:func:`is_grant_active`) — RAISES ``PermissionError`` otherwise
    (an expired grant is an authorization failure, not a data-shape one, and
    fails the same way an unheld ``PlatformPermission`` does elsewhere in this
    codebase). Every entry of ``sessions`` MUST belong to ``event`` — RAISES
    ``ValueError`` on the first entry that does not (a cross-event session is
    a caller bug, never silently dropped from the manifest — mirrors
    ``workspace.py``'s ``_require_same_workspace`` discipline). ``sessions``
    beyond :data:`MAX_MANIFEST_SESSIONS` is rejected outright rather than
    silently truncated.

    The returned agenda is sorted via :func:`rendly.event.agenda` (deterministic
    ``(starts_at, session_id)`` order) before the session id itself is dropped
    from the public projection — see :class:`EmbedSessionSummary`.
    """
    if grant.event_id != event.event_id or grant.tenant_id != event.tenant_id:
        raise ValueError(
            "grant does not name this event: grant.event_id/tenant_id != "
            "event.event_id/tenant_id"
        )
    if not is_grant_active(grant, as_of=as_of):
        raise PermissionError(
            "embed grant is not active at as_of (expired, or not yet issued): a public embed "
            "may only be rendered within [grant.issued_at, grant.expires_at)"
        )

    if len(sessions) > MAX_MANIFEST_SESSIONS:
        raise ValueError(f"sessions must not exceed {MAX_MANIFEST_SESSIONS} entries")

    for session in sessions:
        if session.event_id != event.event_id or session.tenant_id != event.tenant_id:
            raise ValueError(
                "cross-event session rejected: session event_id/tenant_id != "
                "event.event_id/tenant_id (a public embed's agenda is scoped to ONE event only)"
            )

    ordered = agenda(sessions)
    return EmbedManifest(
        grant_id=grant.grant_id,
        event_title=event.title,
        sessions=tuple(
            EmbedSessionSummary(
                title=session.title,
                starts_at=session.starts_at,
                ends_at=session.ends_at,
            )
            for session in ordered
        ),
    )
