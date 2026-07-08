"""SQLAlchemy declarative models for Rendly chat persistence (R-005).

ORM row classes for the chat schema (migration ``0002_chat_schema.py``), schema-qualified
into ``rendly`` and declared on the SAME :class:`rendly.persistence.models.Base` as the R-004
identity rows so the unit-of-work can order cross-table INSERTs (users -> channels ->
memberships/messages). As in R-004, the AUTHORITATIVE DDL is the migration; these classes
describe only the columns the query layer references (the FK/RLS/role/grant/CHECK objects all
live in the migration), and ``create_all`` is never called.

ID/COLUMN SHAPE (same rule as ``models.py``): ids are PLAIN dashed-hex UUID strings
(``String(64)``, case-INSENSITIVE, NEVER canonicalized); timestamps are ``timestamptz``
(tz-aware UTC); enums persist as their lowercase ``StrEnum`` ``.value`` text.
"""

from __future__ import annotations

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKeyConstraint, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import mapped_column

from . import RENDLY_SCHEMA
from .models import Base


class ChannelRow(Base):
    """A tenant-scoped chat channel (RLS table). PK is (tenant_id, channel_id)."""

    __tablename__ = "channels"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], [f"{RENDLY_SCHEMA}.tenants.tenant_id"]),
        ForeignKeyConstraint(
            ["tenant_id", "created_by"],
            [f"{RENDLY_SCHEMA}.users.tenant_id", f"{RENDLY_SCHEMA}.users.user_id"],
        ),
        {"schema": RENDLY_SCHEMA},
    )

    tenant_id = mapped_column(String(64), primary_key=True)
    channel_id = mapped_column(String(64), primary_key=True)
    name = mapped_column(String(128), nullable=False)
    type = mapped_column(String(16), nullable=False)
    source = mapped_column(String(16), nullable=False)
    external_ref = mapped_column(String(64), nullable=True)
    created_by = mapped_column(String(64), nullable=False)
    created_at = mapped_column(DateTime(timezone=True), nullable=False)
    archived = mapped_column(Boolean, nullable=False, default=False)
    # Per-channel monotonic ordering counter (the send path locks the row, reads, increments).
    next_seq = mapped_column(BigInteger, nullable=False, default=0)
    # R-009: this channel's message hash-chain TIP — the ``content_hash`` of the last message
    # inserted, or NULL before the channel's first message. Read/written under the SAME row
    # lock (``SELECT ... FOR UPDATE``) that already serializes ``next_seq`` assignment, so the
    # chain link and the seq assignment are always consistent with no extra lock.
    last_row_hash = mapped_column(String(64), nullable=True)


class MembershipRow(Base):
    """The User<->Channel relation (RLS table). PK (tenant_id, channel_id, user_id).

    The two composite FKs (both carrying tenant_id) are what make a cross-tenant membership
    impossible at the DB layer — the DB-level proof of ``bind_membership``'s invariant.
    """

    __tablename__ = "memberships"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "channel_id"],
            [f"{RENDLY_SCHEMA}.channels.tenant_id", f"{RENDLY_SCHEMA}.channels.channel_id"],
        ),
        ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            [f"{RENDLY_SCHEMA}.users.tenant_id", f"{RENDLY_SCHEMA}.users.user_id"],
        ),
        {"schema": RENDLY_SCHEMA},
    )

    tenant_id = mapped_column(String(64), primary_key=True)
    channel_id = mapped_column(String(64), primary_key=True)
    user_id = mapped_column(String(64), primary_key=True)
    role = mapped_column(String(16), nullable=False)
    added_at = mapped_column(DateTime(timezone=True), nullable=False)


class MessageRow(Base):
    """A persisted chat message = the archival record (RLS table). PK (tenant_id, message_id).

    APPEND-ONLY (rendly_app has SELECT,INSERT only). ``prev_record_hash`` / ``content_hash``
    (R-009) form a hash chain scoped per (tenant_id, channel_id), linked over ``seq`` — see
    ``persistence/hash_chain.py`` + ``chat_repo.insert_message``. NULL on any row inserted
    before R-009 shipped (there was no chain yet to link into); every row inserted since
    carries a real SHA-256 hex digest.
    """

    __tablename__ = "messages"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "channel_id"],
            [f"{RENDLY_SCHEMA}.channels.tenant_id", f"{RENDLY_SCHEMA}.channels.channel_id"],
        ),
        ForeignKeyConstraint(
            ["tenant_id", "sender_user_id"],
            [f"{RENDLY_SCHEMA}.users.tenant_id", f"{RENDLY_SCHEMA}.users.user_id"],
        ),
        {"schema": RENDLY_SCHEMA},
    )

    tenant_id = mapped_column(String(64), primary_key=True)
    message_id = mapped_column(String(64), primary_key=True)
    channel_id = mapped_column(String(64), nullable=False)
    sender_user_id = mapped_column(String(64), nullable=False)
    content = mapped_column(Text, nullable=False)
    content_type = mapped_column(String(16), nullable=False)
    seq = mapped_column(BigInteger, nullable=False)
    created_at = mapped_column(DateTime(timezone=True), nullable=False)
    prev_record_hash = mapped_column(String(64), nullable=True)  # R-009 hash-chain link
    content_hash = mapped_column(String(64), nullable=True)  # R-009 hash-chain digest
    inspection_status = mapped_column(String(16), nullable=False)
    inspection_evaluated_at = mapped_column(DateTime(timezone=True), nullable=False)
    # R-008: the per-category findings the seam evaluated for this message (metadata only —
    # [{"category": "pii", "outcome": "pass"}, ...], NEVER the offending content).
    detectors = mapped_column(JSONB, nullable=False, server_default="[]")


class InspectionAuditLogRow(Base):
    """R-008: an append-only record of every BLOCKED / SEAM-UNAVAILABLE send attempt (RLS table).

    The administrative-oversight complement to ``messages`` — a passed message is already fully
    durable (content + sender + channel) in ``messages``; a blocked one is fail-closed and NEVER
    persisted there, so without this table a rejected send leaves no trace anywhere. Metadata
    only — content is NEVER stored here either (mirrors ``InspectionResult.detectors``).
    APPEND-ONLY (rendly_app has SELECT,INSERT only, same posture as ``messages``).
    """

    __tablename__ = "inspection_audit_log"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "channel_id"],
            [f"{RENDLY_SCHEMA}.channels.tenant_id", f"{RENDLY_SCHEMA}.channels.channel_id"],
        ),
        ForeignKeyConstraint(
            ["tenant_id", "sender_user_id"],
            [f"{RENDLY_SCHEMA}.users.tenant_id", f"{RENDLY_SCHEMA}.users.user_id"],
        ),
        {"schema": RENDLY_SCHEMA},
    )

    tenant_id = mapped_column(String(64), primary_key=True)
    audit_id = mapped_column(String(64), primary_key=True)
    channel_id = mapped_column(String(64), nullable=False)
    sender_user_id = mapped_column(String(64), nullable=False)
    status = mapped_column(String(16), nullable=False)
    detectors = mapped_column(JSONB, nullable=False, server_default="[]")
    evaluated_at = mapped_column(DateTime(timezone=True), nullable=False)
    created_at = mapped_column(DateTime(timezone=True), nullable=False)


class HuddleRow(Base):
    """R-009: the persisted session record for an ENDED huddle (RLS table), 2-8 participants
    since R-011.

    A huddle is ephemeral/in-memory for its LIVE lifetime (``realtime/huddle.py``, ADR-0007) —
    this row is written exactly once, at the terminal ``ended`` transition
    (``persistence/huddle_repo.archive_ended_huddle``). A ``declined`` ring never connects and
    carries no session content, so it is never archived (matches the wire's own "archival is
    present once the huddle reaches a durable (ended) state"). APPEND-ONLY (rendly_app has
    SELECT,INSERT only). ``prev_record_hash``/``content_hash`` chain per TENANT (not per
    channel — a huddle has no channel), linked over the per-tenant ``seq``.

    R-011 (ADR-0011 Fork F): ``caller_id`` is always the original inviter (NOT NULL — there is
    always exactly one). ``callee_id`` is a convenience column populated ONLY when the archived
    session had exactly 2 participants (preserving its exact historical meaning for that case);
    NULL for a genuine 3+-participant session. ``HuddleParticipantRow`` (below) is the
    AUTHORITATIVE full participant list for every huddle archived from R-011 forward — 1-on-1
    included, for a uniform read path.
    """

    __tablename__ = "huddles"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], [f"{RENDLY_SCHEMA}.tenants.tenant_id"]),
        ForeignKeyConstraint(
            ["tenant_id", "caller_id"],
            [f"{RENDLY_SCHEMA}.users.tenant_id", f"{RENDLY_SCHEMA}.users.user_id"],
        ),
        ForeignKeyConstraint(
            ["tenant_id", "callee_id"],
            [f"{RENDLY_SCHEMA}.users.tenant_id", f"{RENDLY_SCHEMA}.users.user_id"],
        ),
        {"schema": RENDLY_SCHEMA},
    )

    tenant_id = mapped_column(String(64), primary_key=True)
    huddle_id = mapped_column(String(64), primary_key=True)
    caller_id = mapped_column(String(64), nullable=False)
    callee_id = mapped_column(String(64), nullable=True)
    state = mapped_column(String(16), nullable=False)
    seq = mapped_column(BigInteger, nullable=False)
    created_at = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at = mapped_column(DateTime(timezone=True), nullable=False)
    prev_record_hash = mapped_column(String(64), nullable=False)
    content_hash = mapped_column(String(64), nullable=False)


class HuddleParticipantRow(Base):
    """R-011: the AUTHORITATIVE full participant list for an archived huddle (RLS table).

    One row per (tenant_id, huddle_id, user_id) — composite PK, FK to both ``huddles`` and
    ``users`` (the DB-level proof every participant is a real same-tenant user, the per-row
    analog of ``HuddleRow``'s own caller/callee FKs). APPEND-ONLY (rendly_app has SELECT,INSERT
    only — same posture as ``huddles``). Written for EVERY archived huddle, including
    2-participant ones, for a uniform read path (ADR-0011 Fork F). No backfill of historical
    (pre-R-011) rows — coverage starts at the migration boundary, disclosed, not silently
    implied as retroactive (mirrors ADR-0009's own chain-coverage-boundary precedent).
    """

    __tablename__ = "huddle_participants"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tenant_id", "huddle_id"],
            [f"{RENDLY_SCHEMA}.huddles.tenant_id", f"{RENDLY_SCHEMA}.huddles.huddle_id"],
        ),
        ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            [f"{RENDLY_SCHEMA}.users.tenant_id", f"{RENDLY_SCHEMA}.users.user_id"],
        ),
        {"schema": RENDLY_SCHEMA},
    )

    tenant_id = mapped_column(String(64), primary_key=True)
    huddle_id = mapped_column(String(64), primary_key=True)
    user_id = mapped_column(String(64), primary_key=True)


class HuddleChainStateRow(Base):
    """R-009: the per-tenant lock + tip holder for the huddle hash chain. One row per tenant.

    The huddle analog of ``ChannelRow.next_seq``/``last_row_hash`` — ``huddle_repo`` locks
    this row (``SELECT ... FOR UPDATE``, lazily upserted on a tenant's first archived huddle)
    to serialize concurrent huddle-archive writes for the SAME tenant and read/advance the
    chain tip under that lock, exactly mirroring the channel-row-lock pattern
    ``chat_repo.insert_message`` uses for messages.
    """

    __tablename__ = "huddle_chain_state"
    __table_args__ = (
        ForeignKeyConstraint(["tenant_id"], [f"{RENDLY_SCHEMA}.tenants.tenant_id"]),
        {"schema": RENDLY_SCHEMA},
    )

    tenant_id = mapped_column(String(64), primary_key=True)
    next_seq = mapped_column(BigInteger, nullable=False, default=0)
    last_row_hash = mapped_column(String(64), nullable=True)
