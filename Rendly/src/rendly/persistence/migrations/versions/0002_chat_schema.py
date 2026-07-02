"""Rendly chat schema: channels, memberships, messages + RLS (R-005).

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-01

The SECOND Rendly DDL. It closes the Channel + Membership persistence DEFERRED by R-004
(ADR-0004 Fork C) and adds the Message store the WebSocket chat runtime writes to. Mirrors
the 0001 two-role RLS pattern exactly (OWNED ``rendly`` schema, ``rendly_app`` NOBYPASSRLS,
the strict NULLIF tenant predicate in USING + WITH CHECK).

1. channels (RLS) — a tenant-scoped chat channel. PK (tenant_id, channel_id) so the child
   tables can carry a SAME-TENANT composite FK. ``type ∈ {public,private,dm}``;
   ``source ∈ {manual,delta_team}`` default ``manual`` with ``external_ref`` non-null IFF
   ``source=delta_team`` (the R-006/D-016 Delta-mapping seam — persisted nullable, NO mapping
   logic built here). ``next_seq`` is the per-channel monotonic sequence counter the send
   path increments under a row lock (FORK C ordering).

2. memberships (RLS) — the User<->Channel relation (R-002 ``Membership``). PK
   (tenant_id, channel_id, user_id). TWO same-tenant composite FKs —
   (tenant_id,channel_id)->channels and (tenant_id,user_id)->users — make a cross-tenant
   membership STRUCTURALLY IMPOSSIBLE: a row's tenant_id must equal BOTH the channel's and
   the user's tenant, so the R-002 ``bind_membership`` cross-tenant invariant is re-proven at
   the DB layer (app ``ValueError`` is the first gate, these FKs + RLS are the next two).

3. messages (RLS) — a persisted chat message = the archival record. PK (tenant_id, message_id).
   Same-tenant composite FKs to channels and to the sender user. UNIQUE (tenant_id, channel_id,
   seq) is the per-channel ordering key AND the keyset index for history. ``prev_record_hash`` /
   ``content_hash`` are RESERVED archival columns — define-only, ALWAYS NULL in R-005; the hash
   CHAIN that links over ``seq`` is R-009 (NOT built here). Messages are APPEND-ONLY by grant
   (rendly_app gets SELECT,INSERT — never UPDATE/DELETE); cryptographic immutability is R-009.

DOWN: reverses every object child->parent. Does NOT drop the ``rendly`` schema or the
``rendly_app`` role (0001 owns those). Never touches data.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA = "rendly"
_APP_ROLE = "rendly_app"

# The strict fail-closed RLS predicate — IDENTICAL to 0001 (F-003b Option α / Delta D-003).
_TENANT_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"

# All three chat tables are tenant-scoped and carry RLS.
_RLS_TABLES = ("channels", "memberships", "messages")


def _enable_rls(table: str) -> None:
    """ENABLE + FORCE RLS and create the single tenant policy on a rendly table.

    One ``FOR ALL`` policy carries the tenant predicate for every command; the GRANTs decide
    which commands rendly_app may actually issue (effective op = policy ∩ grant). Identical
    shape to 0001's ``_enable_rls``.
    """
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} FORCE ROW LEVEL SECURITY")
    op.execute(f"DROP POLICY IF EXISTS {table}_tenant ON {_SCHEMA}.{table}")
    op.execute(
        f"CREATE POLICY {table}_tenant ON {_SCHEMA}.{table} "
        f"FOR ALL USING ({_TENANT_PREDICATE}) WITH CHECK ({_TENANT_PREDICATE})"
    )


def upgrade() -> None:
    # --------------------------------------------------------------------------- channels
    op.create_table(
        "channels",
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("channel_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("type", sa.String(16), nullable=False),
        sa.Column("source", sa.String(16), nullable=False, server_default=sa.text("'manual'")),
        sa.Column("external_ref", sa.String(64), nullable=True),
        sa.Column("created_by", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("archived", sa.Boolean, nullable=False, server_default=sa.text("false")),
        # Per-channel monotonic ordering counter; the send path takes a row lock, reads it,
        # assigns it to the message, and increments it (FORK C). First message gets seq 0.
        sa.Column("next_seq", sa.BigInteger, nullable=False, server_default=sa.text("0")),
        # PK (tenant_id, channel_id) so the child tables can carry a same-tenant composite FK.
        sa.PrimaryKeyConstraint("tenant_id", "channel_id", name="pk_channels"),
        sa.ForeignKeyConstraint(
            ["tenant_id"], [f"{_SCHEMA}.tenants.tenant_id"], name="fk_channels_tenant"
        ),
        # The creator is a real same-tenant user.
        sa.ForeignKeyConstraint(
            ["tenant_id", "created_by"],
            [f"{_SCHEMA}.users.tenant_id", f"{_SCHEMA}.users.user_id"],
            name="fk_channels_creator",
        ),
        sa.CheckConstraint("type IN ('public','private','dm')", name="ck_channels_type"),
        sa.CheckConstraint("source IN ('manual','delta_team')", name="ck_channels_source"),
        # The reserved-seam invariant (R-002 Channel._source_external_ref_consistent), at rest:
        # external_ref is non-null IFF source=delta_team.
        sa.CheckConstraint(
            "(source = 'delta_team') = (external_ref IS NOT NULL)",
            name="ck_channels_external_ref_seam",
        ),
        sa.CheckConstraint("next_seq >= 0", name="ck_channels_next_seq_nonneg"),
        schema=_SCHEMA,
    )

    # ------------------------------------------------------------------------ memberships
    op.create_table(
        "memberships",
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("channel_id", sa.String(64), nullable=False),
        sa.Column("user_id", sa.String(64), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "channel_id", "user_id", name="pk_memberships"),
        # SAME-TENANT composite FKs — the DB-layer proof of bind_membership's cross-tenant
        # invariant. Both carry tenant_id, so a membership's tenant_id must equal BOTH the
        # channel's and the user's tenant; a cross-tenant pair is unconstructible at the DB.
        sa.ForeignKeyConstraint(
            ["tenant_id", "channel_id"],
            [f"{_SCHEMA}.channels.tenant_id", f"{_SCHEMA}.channels.channel_id"],
            name="fk_memberships_channel",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            [f"{_SCHEMA}.users.tenant_id", f"{_SCHEMA}.users.user_id"],
            name="fk_memberships_user",
        ),
        sa.CheckConstraint(
            "role IN ('owner','admin','member','guest')", name="ck_memberships_role"
        ),
        schema=_SCHEMA,
    )
    # "Which channels does this user belong to" (connect-time deliverable-channel load) is
    # keyed by (tenant_id, user_id), which the PK (tenant_id, channel_id, user_id) does not
    # prefix — give it its own index.
    op.create_index("ix_memberships_user", "memberships", ["tenant_id", "user_id"], schema=_SCHEMA)

    # --------------------------------------------------------------------------- messages
    op.create_table(
        "messages",
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("message_id", sa.String(64), nullable=False),
        sa.Column("channel_id", sa.String(64), nullable=False),
        sa.Column("sender_user_id", sa.String(64), nullable=False),
        sa.Column("content", sa.Text, nullable=False),
        sa.Column("content_type", sa.String(16), nullable=False, server_default=sa.text("'text'")),
        # archival.seq — monotonic per-channel; the field R-009's hash chain links over.
        sa.Column("seq", sa.BigInteger, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        # RESERVED archival columns (R-009). Define-only — ALWAYS NULL in R-005; no hash is
        # ever computed here. The CHECK keeps a future value well-formed (sha256 hex).
        sa.Column("prev_record_hash", sa.String(64), nullable=True),
        sa.Column("content_hash", sa.String(64), nullable=True),
        # The inspection outcome at rest. A persisted message has ALWAYS passed (a blocked or
        # seam-unavailable send is fail-closed and never persisted), so this is 'pass' in
        # R-005; the column + evaluated_at make the row R-008-ready and let history rebuild
        # the required InspectionResult faithfully.
        sa.Column(
            "inspection_status", sa.String(16), nullable=False, server_default=sa.text("'pass'")
        ),
        sa.Column("inspection_evaluated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "message_id", name="pk_messages"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "channel_id"],
            [f"{_SCHEMA}.channels.tenant_id", f"{_SCHEMA}.channels.channel_id"],
            name="fk_messages_channel",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "sender_user_id"],
            [f"{_SCHEMA}.users.tenant_id", f"{_SCHEMA}.users.user_id"],
            name="fk_messages_sender",
        ),
        # Per-channel ordering: no two messages in a channel share a seq. Also the keyset
        # index history pages over (ORDER BY seq).
        sa.UniqueConstraint("tenant_id", "channel_id", "seq", name="uq_messages_channel_seq"),
        sa.CheckConstraint("char_length(content) <= 16384", name="ck_messages_content_len"),
        sa.CheckConstraint("content_type IN ('text','markdown')", name="ck_messages_content_type"),
        sa.CheckConstraint("seq >= 0", name="ck_messages_seq_nonneg"),
        sa.CheckConstraint(
            "prev_record_hash IS NULL OR prev_record_hash ~ '^[0-9a-f]{64}$'",
            name="ck_messages_prev_hash_hex",
        ),
        sa.CheckConstraint(
            "content_hash IS NULL OR content_hash ~ '^[0-9a-f]{64}$'",
            name="ck_messages_content_hash_hex",
        ),
        sa.CheckConstraint(
            "inspection_status IN ('pass','blocked','seam_unavailable')",
            name="ck_messages_inspection_status",
        ),
        schema=_SCHEMA,
    )

    # ----------------------------------------------------- rendly_app grants (per table)
    # channels: read + insert + update (next_seq increment under the send-path row lock;
    # archived toggle). NEVER DELETE.
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.channels TO {_APP_ROLE}")
    # memberships: read + insert + delete (add/remove a member). NEVER UPDATE (role change is
    # remove+re-add in the MVP).
    op.execute(f"GRANT SELECT, INSERT, DELETE ON {_SCHEMA}.memberships TO {_APP_ROLE}")
    # messages: read + insert ONLY — APPEND-ONLY by grant. No UPDATE/DELETE; cryptographic
    # immutability (the hash chain) is R-009.
    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.messages TO {_APP_ROLE}")

    # ------------------------------------------------------------------------------- RLS
    for table in _RLS_TABLES:
        _enable_rls(table)


def downgrade() -> None:
    # Reverse dependency order. The `rendly` schema + `rendly_app` role are 0001's to own.
    for table in _RLS_TABLES:
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant ON {_SCHEMA}.{table}")

    # Revoke grants before dropping the tables they reference.
    for table in _RLS_TABLES:
        op.execute(f"REVOKE ALL ON {_SCHEMA}.{table} FROM {_APP_ROLE}")

    # Drop child->parent (messages -> memberships -> channels).
    op.drop_table("messages", schema=_SCHEMA)
    op.drop_index("ix_memberships_user", table_name="memberships", schema=_SCHEMA)
    op.drop_table("memberships", schema=_SCHEMA)
    op.drop_table("channels", schema=_SCHEMA)
