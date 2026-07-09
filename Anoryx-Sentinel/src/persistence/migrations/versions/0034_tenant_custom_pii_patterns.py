"""F-028 tenant_custom_pii_patterns table — per-tenant custom PII regex (ADR-0034).

Revision ID: 0034
Revises: 0033
Create Date: 2026-07-09

Creates the `tenant_custom_pii_patterns` table: per-tenant client-defined
custom PII regex patterns (F-028, ADR-0034), matched by a standalone
`regex`-module engine alongside the built-in F-005 Presidio entities.

Design (mirrors tenant_mcp_servers / migration 0033 — same per-tenant
config-table shape, same RLS):
  - pattern_id   VARCHAR(64)  — PK, opaque UUID.
  - name         VARCHAR(64)  — entity label surfaced in masks/events, non-empty
                                 (CHECK). Uppercase-normalized at registration.
  - pattern      TEXT         — the regex text, validated (compile + length +
                                 ReDoS-heuristic) BEFORE write by
                                 src/data_protection/custom_pii/validator.py.
  - score        FLOAT        — [0,1] confidence attached to matches (CHECK).
  - action       VARCHAR(16)  — per-pattern override mask|tokenize|block; NULL =
                                 use tenant/global default.
  - version      INTEGER      — hot-reload staleness signal.
  - is_active    BOOLEAN      — soft-enable/disable; no DELETE path.
  - team_id/project_id — optional scope; NULL = tenant-wide.
  - created_at / updated_at — standard audit timestamps.

Tenant-scoped RLS (verbatim fail-closed NULLIF predicate from ADR-0005,
established in migrations 0006/0007/0018/0026/0028/0033): ENABLE + FORCE +
DROP-IF-EXISTS + CREATE POLICY + GRANT SELECT/INSERT/UPDATE to sentinel_app
(no DELETE — soft-disable via 'is_active').

Down revision: 0033 (verified current head).

Reversible: downgrade() revokes, drops policy, disables RLS, drops table.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0034"
down_revision: Union[str, None] = "0033"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "tenant_custom_pii_patterns"

# Fail-closed NULLIF predicate — verbatim from ADR-0005 / migrations 0006/0007/0018/0026/0028/0033.
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
        sa.Column("pattern_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column(
            "tenant_id",
            sa.String(64),
            sa.ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("team_id", sa.String(64), nullable=True),
        sa.Column("project_id", sa.String(64), nullable=True),
        sa.Column("name", sa.String(64), nullable=False),
        sa.Column("pattern", sa.Text(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False, server_default=sa.text("0.85")),
        sa.Column("action", sa.String(16), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
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
        sa.CheckConstraint("length(name) > 0", name="ck_tenant_custom_pii_name_nonempty"),
        sa.CheckConstraint("length(pattern) > 0", name="ck_tenant_custom_pii_pattern_nonempty"),
        sa.CheckConstraint("score >= 0 AND score <= 1", name="ck_tenant_custom_pii_score_range"),
    )

    op.create_index("ix_tenant_custom_pii_tenant_id", _TABLE, ["tenant_id"])
    op.create_index("ix_tenant_custom_pii_tenant_active", _TABLE, ["tenant_id", "is_active"])

    conn = op.get_bind()
    _enable_rls(conn)


def downgrade() -> None:
    conn = op.get_bind()

    conn.execute(sa.text(f"REVOKE SELECT, INSERT, UPDATE ON {_TABLE} FROM sentinel_app"))
    conn.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation ON {_TABLE}"))
    conn.execute(sa.text(f"ALTER TABLE {_TABLE} DISABLE ROW LEVEL SECURITY"))

    op.drop_index("ix_tenant_custom_pii_tenant_active", table_name=_TABLE)
    op.drop_index("ix_tenant_custom_pii_tenant_id", table_name=_TABLE)
    op.drop_table(_TABLE)
