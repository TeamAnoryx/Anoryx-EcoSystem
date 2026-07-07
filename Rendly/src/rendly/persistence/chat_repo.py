"""Async row <-> frozen-domain mapping + chat write/read primitives (R-005).

The async analog of ``identity_repo.py`` for the chat schema (migration 0002): free functions
that take an explicit ``AsyncSession`` (opened by the caller via
``async_database.get_tenant_session`` so RLS scopes every statement to the GUC tenant), do the
narrow work, and leave the commit to the caller. Reconstruction rebuilds the FROZEN domain types
(``rendly.Channel`` / ``rendly.Membership`` / ``rendly.realtime.Message``) via their constructors
— ids verbatim (NO canonicalization), timestamps tz-aware UTC, enums rebuilt from their text.

ORDERING (FORK C): :func:`insert_message` assigns the per-channel ``seq`` under a ``SELECT ...
FOR UPDATE`` row lock on the channel (mirrors ``refresh_store``'s FOR UPDATE rotation lock), so
concurrent sends in one channel are serialized and seq is strictly monotonic with no gaps.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..channel import Channel
from ..enums import ChannelRole, ChannelSource, ChannelType
from ..membership import Membership
from ..realtime.inspector import DetectorFinding
from ..realtime.message import Message
from ..user import User
from .chat_models import ChannelRow, InspectionAuditLogRow, MembershipRow, MessageRow
from .identity_repo import user_from_row  # reuse the one row->User mapper (DRY)
from .models import UserRow


def _detectors_from_json(raw: list | None) -> tuple[DetectorFinding, ...]:
    if not raw:
        return ()
    return tuple(
        DetectorFinding(category=item["category"], outcome=item["outcome"]) for item in raw
    )


def _detectors_to_json(detectors: tuple[DetectorFinding, ...]) -> list[dict]:
    return [{"category": f.category, "outcome": f.outcome} for f in detectors]


# --- row -> frozen domain --------------------------------------------------------------


def channel_from_row(row: ChannelRow) -> Channel:
    return Channel(
        channel_id=row.channel_id,
        tenant_id=row.tenant_id,
        name=row.name,
        type=ChannelType(row.type),
        source=ChannelSource(row.source),
        external_ref=row.external_ref,
        created_by=row.created_by,
        created_at=row.created_at,
        archived=row.archived,
    )


def message_from_row(row: MessageRow) -> Message:
    return Message(
        message_id=row.message_id,
        tenant_id=row.tenant_id,
        channel_id=row.channel_id,
        sender_user_id=row.sender_user_id,
        content=row.content,
        content_type=row.content_type,
        seq=row.seq,
        created_at=row.created_at,
        inspection_status=row.inspection_status,
        inspection_evaluated_at=row.inspection_evaluated_at,
        detectors=_detectors_from_json(row.detectors),
    )


# --- channel + membership writes -------------------------------------------------------


async def insert_channel(session: AsyncSession, channel: Channel) -> None:
    """Insert a channel row under a TENANT session (RLS WITH CHECK binds it to the GUC tenant)."""
    session.add(
        ChannelRow(
            tenant_id=channel.tenant_id,
            channel_id=channel.channel_id,
            name=channel.name,
            type=channel.type.value,
            source=channel.source.value,
            external_ref=channel.external_ref,
            created_by=channel.created_by,
            created_at=channel.created_at,
            archived=channel.archived,
            next_seq=0,
        )
    )


async def map_channel_to_team(
    session: AsyncSession, *, tenant_id: str, channel_id: str, external_ref: str
) -> bool:
    """Map a channel to a team label: set ``source='delta_team'`` + ``external_ref`` (R-006).

    FORK A (reuse the R-001 ``source``/``external_ref`` columns): a Core UPDATE flips ``source`` to
    ``delta_team`` and stores the opaque tenant-scoped ``external_ref`` label. Runs under a TENANT
    session, so RLS's ``USING`` + ``WITH CHECK`` bind the write to the GUC tenant — a caller can
    never map another tenant's channel. Setting both columns together satisfies the biconditional
    ``ck_channels_external_ref_seam`` CHECK (``(source='delta_team') = (external_ref IS NOT NULL)``).
    Returns True iff an in-tenant channel row was updated (RLS-scoped). The caller commits and owns
    the response shape (a Core UPDATE is used, not an ORM load+mutate, so a channel row loaded
    earlier in this session for the authz decision is not re-read stale from the identity map).

    HONESTY BOUNDARY: this is the MANUAL writer only. ``delta_team`` names the reserved Delta-team
    seam; the automatic Delta-event writer is NOT built (D-016 + an Orchestrator team-event contract
    are required and not shipped). ``external_ref`` is an OPAQUE label — it is never dereferenced to
    resolve membership (see ``realtime.resolver.ManualResolver``), so it cannot become an access
    vector, cross-tenant or otherwise.
    """
    result = await session.execute(
        update(ChannelRow)
        .where(ChannelRow.tenant_id == tenant_id, ChannelRow.channel_id == channel_id)
        .values(source=ChannelSource.DELTA_TEAM.value, external_ref=external_ref)
    )
    await session.flush()  # surface the biconditional CHECK before the caller commits
    return result.rowcount > 0


async def insert_membership(session: AsyncSession, membership: Membership) -> None:
    """Insert a membership row under a TENANT session.

    The caller MUST build ``membership`` via ``rendly.bind_membership`` (the cross-tenant
    ``ValueError`` guard runs first); the composite same-tenant FKs + RLS are the next two layers.
    """
    session.add(
        MembershipRow(
            tenant_id=membership.tenant_id,
            channel_id=membership.channel_id,
            user_id=membership.user_id,
            role=membership.role.value,
            added_at=membership.added_at,
        )
    )


async def delete_membership(
    session: AsyncSession, *, tenant_id: str, channel_id: str, user_id: str
) -> bool:
    """Remove a member from a channel. Returns True iff a row was deleted (RLS-scoped).

    Uses a Core DELETE (not an ORM ``session.delete`` of a loaded row): the role-change upsert
    deletes-then-inserts the SAME primary key in one transaction, and loading the old row into the
    identity map would make SQLAlchemy treat the colliding-PK insert as an UPDATE (which rendly_app
    deliberately cannot do). A Core DELETE executes immediately and touches no identity map.
    """
    result = await session.execute(
        delete(MembershipRow).where(
            MembershipRow.tenant_id == tenant_id,
            MembershipRow.channel_id == channel_id,
            MembershipRow.user_id == user_id,
        )
    )
    return result.rowcount > 0


# --- channel + membership reads --------------------------------------------------------


async def load_channel(session: AsyncSession, *, tenant_id: str, channel_id: str) -> Channel | None:
    """Load a channel within the session's tenant scope (RLS applies)."""
    row = (
        await session.execute(
            select(ChannelRow).where(
                ChannelRow.tenant_id == tenant_id, ChannelRow.channel_id == channel_id
            )
        )
    ).scalar_one_or_none()
    return channel_from_row(row) if row is not None else None


async def load_user(session: AsyncSession, *, tenant_id: str, user_id: str) -> User | None:
    """Load a user within the session's tenant scope (RLS applies on a tenant session).

    Used by the member-management REST path so ``bind_membership`` can run its cross-tenant
    ``ValueError`` guard on a REAL ``User`` before insert; a user in another tenant is invisible
    here (RLS -> None), so member-add can only ever target an in-tenant user.
    """
    row = (
        await session.execute(
            select(UserRow).where(UserRow.tenant_id == tenant_id, UserRow.user_id == user_id)
        )
    ).scalar_one_or_none()
    return user_from_row(row) if row is not None else None


async def channel_ids_for_user(session: AsyncSession, *, tenant_id: str, user_id: str) -> list[str]:
    """The channel ids the user is a member of (the connect-time deliverable-channel set)."""
    rows = (
        await session.execute(
            select(MembershipRow.channel_id).where(
                MembershipRow.tenant_id == tenant_id, MembershipRow.user_id == user_id
            )
        )
    ).all()
    return [r[0] for r in rows]


async def is_member(
    session: AsyncSession, *, tenant_id: str, channel_id: str, user_id: str
) -> bool:
    """LIVE membership check (send authorization always re-checks the DB, never a cached set)."""
    row = (
        await session.execute(
            select(MembershipRow.user_id).where(
                MembershipRow.tenant_id == tenant_id,
                MembershipRow.channel_id == channel_id,
                MembershipRow.user_id == user_id,
            )
        )
    ).first()
    return row is not None


async def member_role(
    session: AsyncSession, *, tenant_id: str, channel_id: str, user_id: str
) -> ChannelRole | None:
    """The caller's per-channel ``ChannelRole``, or None if not a member (RLS-scoped, LIVE).

    The role counterpart to :func:`is_member`: R-006's channel-authz decision point reads the
    per-channel role (which R-005 persisted but never consulted) to gate role-differentiated
    actions. Returns None for a non-member — or for a channel/tenant not visible under the session's
    RLS scope — which the authz layer treats as a fail-closed DENY (a forged tenant's GUC collapses
    the RLS predicate to zero rows, so this returns None, never another tenant's role).
    """
    row = (
        await session.execute(
            select(MembershipRow.role).where(
                MembershipRow.tenant_id == tenant_id,
                MembershipRow.channel_id == channel_id,
                MembershipRow.user_id == user_id,
            )
        )
    ).first()
    return ChannelRole(row[0]) if row is not None else None


# --- message write (seq under a per-channel row lock) ----------------------------------


async def insert_message(
    session: AsyncSession,
    *,
    message_id: str,
    tenant_id: str,
    channel_id: str,
    sender_user_id: str,
    content: str,
    content_type: str,
    created_at: datetime,
    inspection_evaluated_at: datetime,
    detectors: tuple[DetectorFinding, ...] = (),
) -> Message:
    """Persist a chat message, assigning the per-channel ``seq`` under a row lock.

    FORK C: locks the channel row (``SELECT ... FOR UPDATE``), reads ``next_seq``, writes the
    message with that seq, and increments the counter — strictly monotonic, gap-free, and
    serialized per channel. A persisted message has ALWAYS passed inspection
    (``inspection_status='pass'``); the hash columns stay NULL (R-009). ``detectors`` (R-008) is
    the per-category findings the seam evaluated for THIS message (metadata only). Returns the
    frozen :class:`Message`. The caller commits.
    """
    channel = (
        await session.execute(
            select(ChannelRow)
            .where(ChannelRow.tenant_id == tenant_id, ChannelRow.channel_id == channel_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if channel is None:  # pragma: no cover - defensive; authz already proved the channel exists
        # Authorization (live is_member, re-checked in this same transaction) proves the sender is
        # a member, which requires the channel to exist in-tenant — so this is unreachable on the
        # live path; fail-closed if it ever isn't.
        raise LookupError("channel not found for the tenant session (RLS-scoped)")

    seq = channel.next_seq
    session.add(
        MessageRow(
            tenant_id=tenant_id,
            message_id=message_id,
            channel_id=channel_id,
            sender_user_id=sender_user_id,
            content=content,
            content_type=content_type,
            seq=seq,
            created_at=created_at,
            prev_record_hash=None,  # RESERVED (R-009)
            content_hash=None,  # RESERVED (R-009)
            inspection_status="pass",
            inspection_evaluated_at=inspection_evaluated_at,
            detectors=_detectors_to_json(detectors),
        )
    )
    channel.next_seq = seq + 1
    await session.flush()  # surface FK/CHECK/unique violations before the caller commits
    return Message(
        message_id=message_id,
        tenant_id=tenant_id,
        channel_id=channel_id,
        sender_user_id=sender_user_id,
        content=content,
        content_type=content_type,
        seq=seq,
        created_at=created_at,
        inspection_status="pass",
        inspection_evaluated_at=inspection_evaluated_at,
        detectors=detectors,
    )


# --- message history (keyset by seq, newest first) -------------------------------------


async def load_message_history(
    session: AsyncSession,
    *,
    tenant_id: str,
    channel_id: str,
    limit: int,
    before_seq: int | None = None,
) -> list[Message]:
    """Page a channel's messages newest-first, ordered by the archival ``seq`` (keyset).

    ``before_seq`` is the exclusive upper bound from the previous page's cursor (omit for the
    first page). Returns up to ``limit`` messages in DESC seq order. RLS scopes to the tenant.
    """
    query = select(MessageRow).where(
        MessageRow.tenant_id == tenant_id, MessageRow.channel_id == channel_id
    )
    if before_seq is not None:
        query = query.where(MessageRow.seq < before_seq)
    query = query.order_by(MessageRow.seq.desc()).limit(limit)
    rows = (await session.execute(query)).scalars().all()
    return [message_from_row(row) for row in rows]


# --- inspection audit log (R-008: the administrative-oversight complement to messages) -----


async def insert_inspection_audit(
    session: AsyncSession,
    *,
    audit_id: str,
    tenant_id: str,
    channel_id: str,
    sender_user_id: str,
    status: str,
    detectors: tuple[DetectorFinding, ...],
    evaluated_at: datetime,
    created_at: datetime,
) -> None:
    """Record a BLOCKED / SEAM-UNAVAILABLE send attempt (never a ``pass`` — see ADR-0008).

    A passed message is already fully durable in ``messages``; this is the ONLY durable trace of
    a rejected send. Metadata only — the caller never passes message content here. The caller
    commits (mirrors every other write helper in this module).
    """
    session.add(
        InspectionAuditLogRow(
            tenant_id=tenant_id,
            audit_id=audit_id,
            channel_id=channel_id,
            sender_user_id=sender_user_id,
            status=status,
            detectors=_detectors_to_json(detectors),
            evaluated_at=evaluated_at,
            created_at=created_at,
        )
    )
    await session.flush()  # surface FK/CHECK violations before the caller commits


async def load_inspection_audit_log(
    session: AsyncSession, *, tenant_id: str, limit: int = 50
) -> list[dict]:
    """The tenant's most recent inspection incidents, newest first (RLS-scoped, metadata only).

    Returns plain dicts (there is no wire contract for this yet — see ADR-0008's honesty
    boundary: a dedicated admin REST surface is deferred, not built).
    """
    rows = (
        (
            await session.execute(
                select(InspectionAuditLogRow)
                .where(InspectionAuditLogRow.tenant_id == tenant_id)
                .order_by(InspectionAuditLogRow.created_at.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return [
        {
            "audit_id": row.audit_id,
            "channel_id": row.channel_id,
            "sender_user_id": row.sender_user_id,
            "status": row.status,
            "detectors": _detectors_from_json(row.detectors),
            "evaluated_at": row.evaluated_at,
            "created_at": row.created_at,
        }
        for row in rows
    ]
