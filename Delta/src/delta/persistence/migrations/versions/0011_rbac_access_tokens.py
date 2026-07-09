"""Delta RBAC-gated dashboards: access_tokens (D-017).

Revision ID: 0011
Revises: 0010
Create Date: 2026-07-09

The roadmap's literal text for D-017 is: "Org-tier-scoped dashboards — users
view/execute only what their tier authorizes." This migration scopes that down to a
deliberately bounded vertical slice (ADR-0017): locally-issued, role-tagged bearer
tokens (two seeded roles, `tenant_admin`/`tenant_auditor` — mirroring Anoryx-
Sentinel's own already-shipped F-014/ADR-0017 role vocabulary for ecosystem naming
consistency) gating D-008's dashboards router — not real SSO/OIDC/SAML (Sentinel's
F-014 already built that, for Sentinel's own admin surface; federating Delta's admin
console with it is out of scope for this task, named explicitly in ADR-0017 §3), and
not a retrofit across every other D-007-D-016 admin surface (also named explicitly as
deferred).

One new table:

``access_tokens`` — one row per issued token. Only ``token_hash`` (SHA-256 hex
digest) is ever stored; the raw token is generated, shown to the caller exactly once
at creation, and never persisted or returned again (mirrors ordinary API-key/secret
issuance hygiene). ``revoked_at`` is nullable and set (never deleted) when a token is
revoked — matches the ecosystem-wide no-DELETE convention.

Grants: ``delta_app`` gets SELECT, INSERT, UPDATE (revocation is an UPDATE) — no
DELETE. Same strict fail-closed NULLIF RLS predicate as every prior migration — a
presented token is looked up via the CALLER-SUPPLIED ``tenant_id`` query param's own
RLS-scoped session, so a token that does not belong to that tenant is simply
invisible (fails closed as "not found", not a separate cross-tenant check).

DOWN: drops ``access_tokens``. Retains the ``delta`` schema and never touches
D-001..D-016 data.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SCHEMA = "delta"
_APP_ROLE = "delta_app"

_TENANT_PREDICATE = "tenant_id = NULLIF(current_setting('app.current_tenant_id', true), '')"


def _enable_rls(table: str, *, insert: bool, update: bool) -> None:
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} ENABLE ROW LEVEL SECURITY")
    op.execute(f"ALTER TABLE {_SCHEMA}.{table} FORCE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY {table}_tenant_select ON {_SCHEMA}.{table} "
        f"FOR SELECT USING ({_TENANT_PREDICATE})"
    )
    if insert:
        op.execute(
            f"CREATE POLICY {table}_tenant_insert ON {_SCHEMA}.{table} "
            f"FOR INSERT WITH CHECK ({_TENANT_PREDICATE})"
        )
    if update:
        op.execute(
            f"CREATE POLICY {table}_tenant_update ON {_SCHEMA}.{table} "
            f"FOR UPDATE USING ({_TENANT_PREDICATE}) WITH CHECK ({_TENANT_PREDICATE})"
        )


def upgrade() -> None:
    op.create_table(
        "access_tokens",
        sa.Column("token_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("role", sa.String(16), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "role IN ('tenant_admin', 'tenant_auditor')", name="ck_access_token_role"
        ),
        sa.UniqueConstraint("token_id", "tenant_id", name="uq_access_token_id_tenant"),
        sa.UniqueConstraint("token_hash", name="uq_access_token_hash"),
        schema=_SCHEMA,
    )
    op.create_index("ix_access_tokens_tenant", "access_tokens", ["tenant_id"], schema=_SCHEMA)
    op.create_index("ix_access_tokens_hash", "access_tokens", ["token_hash"], schema=_SCHEMA)

    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.access_tokens TO {_APP_ROLE}")
    _enable_rls("access_tokens", insert=True, update=True)


def downgrade() -> None:
    op.execute(f"DROP POLICY IF EXISTS access_tokens_tenant_update ON {_SCHEMA}.access_tokens")
    op.execute(f"DROP POLICY IF EXISTS access_tokens_tenant_insert ON {_SCHEMA}.access_tokens")
    op.execute(f"DROP POLICY IF EXISTS access_tokens_tenant_select ON {_SCHEMA}.access_tokens")
    op.execute(f"REVOKE ALL ON {_SCHEMA}.access_tokens FROM {_APP_ROLE}")

    op.drop_index("ix_access_tokens_hash", table_name="access_tokens", schema=_SCHEMA)
    op.drop_index("ix_access_tokens_tenant", table_name="access_tokens", schema=_SCHEMA)
    op.drop_table("access_tokens", schema=_SCHEMA)
