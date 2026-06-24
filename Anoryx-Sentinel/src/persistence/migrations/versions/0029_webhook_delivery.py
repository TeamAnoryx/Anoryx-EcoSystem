"""F-020 webhook_delivery ledger — per-delivery tracking + at-least-once dedup (ADR-0023 §5.2).

Revision ID: 0029
Revises: 0028
Create Date: 2026-06-24

Creates the `webhook_delivery` table: the delivery ledger for F-020 outbound webhook
dispatch. One row per (event_id, config_id) pair — the natural dedup key for the
at-least-once delivery model (ADR-0023 §5.3 D3, ADR-0018 R5/R7 pattern).

Design (ADR-0023 §5.2):
  - event_id     VARCHAR(64)  — the source audit-log event_id (UUID) being forwarded.
  - config_id    VARCHAR(64)  — FK → webhook_config.config_id (the target config).
  - tenant_id    VARCHAR(64)  — denormalized for RLS enforcement; always == the
                                 source event's tenant_id (verified by the dispatcher).
  - status       VARCHAR(16)  — 'pending' | 'delivered' | 'failed' | 'dead_lettered'.
                                 Terminal status is the worker checkpoint (R5/R7).
  - attempts     SMALLINT     — number of delivery attempts made. Bounded ≤ 100.
  - last_http_status_class VARCHAR(8)  — bounded HTTP status class string (e.g.
                                 '2xx', '4xx', '5xx') or NULL. Never response body.
  - created_at / updated_at  — standard audit timestamps.

UNIQUE (event_id, config_id) — the at-least-once dedup key (ADR-0023 §5.2):
  the dispatcher INSERTs ON CONFLICT DO NOTHING before dispatch; the worker
  updates status after each attempt. If the worker restarts mid-delivery, it
  sees the existing row (not 'pending') and skips (effectively-once semantic).

Tenant-scoped RLS (verbatim fail-closed NULLIF predicate from ADR-0005 / migrations
0006/0007/0018/0026/0028): ENABLE + FORCE + CREATE POLICY + GRANT to sentinel_app.

Down revision: 0028.

Reversible: downgrade() revokes, drops policy, disables RLS, drops table.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0029"
down_revision: Union[str, None] = "0028"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "webhook_delivery"

# Fail-closed NULLIF predicate — verbatim from ADR-0005 / migrations 0006/0007/0018/0026/0028.
_NULLIF_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"


def _enable_rls(conn) -> None:
    conn.execute(sa.text(f"ALTER TABLE {_TABLE} ENABLE ROW LEVEL SECURITY"))
    conn.execute(sa.text(f"ALTER TABLE {_TABLE} FORCE ROW LEVEL SECURITY"))
    conn.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation ON {_TABLE}"))
    conn.execute(
        sa.text(
            f"""
            CREATE POLICY tenant_isolation ON {_TABLE}
            USING ({_NULLIF_PREDICATE})
            WITH CHECK ({_NULLIF_PREDICATE})
            """
        )
    )
    conn.execute(sa.text(f"GRANT SELECT, INSERT, UPDATE ON {_TABLE} TO sentinel_app"))


def upgrade() -> None:
    op.create_table(
        _TABLE,
        # Primary key — opaque UUID string.
        sa.Column("delivery_id", sa.String(64), primary_key=True, nullable=False),
        # Source event being forwarded — the UUID from events_audit_log.event_id.
        sa.Column("event_id", sa.String(64), nullable=False),
        # Target webhook configuration — FK to webhook_config; cascade-restrict
        # (blocking delete of a config that has delivery rows).
        sa.Column(
            "config_id",
            sa.String(64),
            sa.ForeignKey("webhook_config.config_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        # Denormalized tenant_id for RLS enforcement (always == source event tenant).
        sa.Column(
            "tenant_id",
            sa.String(64),
            sa.ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        # Delivery lifecycle status. Terminal statuses: 'delivered' | 'dead_lettered'.
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        # Number of delivery attempts. SMALLINT (≤ 32767 >> ADR bounded retry budget).
        sa.Column("attempts", sa.SmallInteger(), nullable=False, server_default="0"),
        # Bounded HTTP status class — coarse label only, never a response body.
        # 'pending' rows have NULL here (no attempt yet).
        sa.Column("last_http_status_class", sa.String(8), nullable=True),
        # Standard audit timestamps.
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        # At-least-once dedup key (ADR-0023 §5.2 / §5.3).
        # One row per (event_id, config_id) pair prevents double-posting on restart.
        sa.UniqueConstraint("event_id", "config_id", name="uq_webhook_delivery_event_config"),
        # Bounded enum CHECK constraints.
        sa.CheckConstraint(
            "status IN ('pending', 'delivered', 'failed', 'dead_lettered')",
            name="ck_webhook_delivery_status",
        ),
        sa.CheckConstraint(
            "last_http_status_class IS NULL OR "
            "last_http_status_class IN ('1xx', '2xx', '3xx', '4xx', '5xx')",
            name="ck_webhook_delivery_http_class",
        ),
        sa.CheckConstraint(
            "attempts >= 0 AND attempts <= 100",
            name="ck_webhook_delivery_attempts",
        ),
    )

    op.create_index("ix_webhook_delivery_tenant_id", _TABLE, ["tenant_id"])
    op.create_index("ix_webhook_delivery_config_id", _TABLE, ["config_id"])
    op.create_index("ix_webhook_delivery_status", _TABLE, ["tenant_id", "status"])
    # Composite index to support the dedup query (event_id + config_id).
    op.create_index("ix_webhook_delivery_event_config", _TABLE, ["event_id", "config_id"])

    conn = op.get_bind()
    _enable_rls(conn)


def downgrade() -> None:
    conn = op.get_bind()

    conn.execute(sa.text(f"REVOKE SELECT, INSERT, UPDATE ON {_TABLE} FROM sentinel_app"))
    conn.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation ON {_TABLE}"))
    conn.execute(sa.text(f"ALTER TABLE {_TABLE} DISABLE ROW LEVEL SECURITY"))

    op.drop_index("ix_webhook_delivery_event_config", table_name=_TABLE)
    op.drop_index("ix_webhook_delivery_status", table_name=_TABLE)
    op.drop_index("ix_webhook_delivery_config_id", table_name=_TABLE)
    op.drop_index("ix_webhook_delivery_tenant_id", table_name=_TABLE)
    op.drop_table(_TABLE)
