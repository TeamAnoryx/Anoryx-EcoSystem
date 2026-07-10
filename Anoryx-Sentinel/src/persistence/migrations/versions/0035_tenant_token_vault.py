"""F-033 tenant_token_vault table — reversible tokenization vault (ADR-0039).

Revision ID: 0035
Revises: 0034
Create Date: 2026-07-10

Creates `tenant_token_vault`: the LAYER-2 store mapping a format-preserving
surrogate token -> AES-256-GCM ciphertext of the original PII value, per tenant
(F-033, ADR-0039). No plaintext is stored.

Design (mirrors tenant_custom_pii_patterns / migration 0034 — same per-tenant
RLS shape):
  - vault_id       VARCHAR(64)  — PK, opaque UUID.
  - token          VARCHAR(128) — the format-preserving surrogate, unique per
                                   tenant (stable lookup key).
  - token_type     VARCHAR(16)  — card|ssn|digits|generic.
  - ciphertext_b64 TEXT         — base64(nonce ‖ AESGCM(original)); NO plaintext.
  - created_at     TIMESTAMPTZ.

Tenant-scoped RLS (verbatim fail-closed NULLIF predicate, established in
migrations 0006..0034): ENABLE + FORCE + DROP-IF-EXISTS + CREATE POLICY +
GRANT SELECT/INSERT to sentinel_app (no UPDATE/DELETE — a token mapping is
immutable; a purge is a future operator decision).

Down revision: 0034 (verified current head).

Reversible: downgrade() revokes, drops policy, disables RLS, drops table.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0035"
down_revision: Union[str, None] = "0034"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "tenant_token_vault"

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
    # No UPDATE/DELETE grant — a token->ciphertext mapping is immutable.
    conn.execute(sa.text(f"GRANT SELECT, INSERT ON {_TABLE} TO sentinel_app"))


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column("vault_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column(
            "tenant_id",
            sa.String(64),
            sa.ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("token", sa.String(128), nullable=False),
        sa.Column("token_type", sa.String(16), nullable=False),
        sa.Column("ciphertext_b64", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("tenant_id", "token", name="uq_tenant_token_vault_tenant_token"),
        sa.CheckConstraint("length(token) > 0", name="ck_tenant_token_vault_token_nonempty"),
        sa.CheckConstraint("length(ciphertext_b64) > 0", name="ck_tenant_token_vault_ct_nonempty"),
    )

    op.create_index("ix_tenant_token_vault_tenant_id", _TABLE, ["tenant_id"])
    op.create_index("ix_tenant_token_vault_tenant_token", _TABLE, ["tenant_id", "token"])

    conn = op.get_bind()
    _enable_rls(conn)


def downgrade() -> None:
    conn = op.get_bind()

    conn.execute(sa.text(f"REVOKE SELECT, INSERT ON {_TABLE} FROM sentinel_app"))
    conn.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation ON {_TABLE}"))
    conn.execute(sa.text(f"ALTER TABLE {_TABLE} DISABLE ROW LEVEL SECURITY"))

    op.drop_index("ix_tenant_token_vault_tenant_token", table_name=_TABLE)
    op.drop_index("ix_tenant_token_vault_tenant_id", table_name=_TABLE)
    op.drop_table(_TABLE)
