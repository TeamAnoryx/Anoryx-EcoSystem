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
    are RESERVED archival columns — define-only, always NULL in R-005; the hash chain is R-009.
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
    prev_record_hash = mapped_column(String(64), nullable=True)  # RESERVED (R-009)
    content_hash = mapped_column(String(64), nullable=True)  # RESERVED (R-009)
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
