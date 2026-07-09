"""Delta unified CRM: clients, deals, stakeholders, interactions (D-013).

Revision ID: 0007
Revises: 0006
Create Date: 2026-07-08

The Phase-3 (post-investment vision) roadmap item is scoped down here to a
deliberately bounded vertical slice (ADR-0013): a client record, its deal pipeline,
its stakeholder roster, and its interaction history. "Relationship scoring" and
stakeholder engagement are computed LIVE by ``delta.crm.scoring``/``store`` from these
rows at request time — nothing in this migration stores a score.

Four tables:

1. ``clients`` — one row per client/account. Bare identity + optional primary contact.
2. ``deals`` — one row per pipeline opportunity, FK-scoped to its client + tenant (the
   same composite-FK-to-prevent-cross-tenant-reference pattern D-007's
   ``allocation_targets`` uses against ``allocations``). ``stage`` is app-validated
   (delta.crm.schemas' Literal), not DB-CHECK-constrained to a closed set, because
   'won'/'lost' terminality is an app-level business rule (ADR-0013 Fork 2), not a
   structural database invariant a future stage vocabulary change should have to
   migrate around.
3. ``stakeholders`` — roster of named contacts per client, optionally scoped to one
   deal. Structured data entered explicitly, not free-text-extracted (ADR-0013 Fork 3).
4. ``interactions`` — append-only interaction log (call/email/meeting/note), optionally
   tied to one deal AND one stakeholder. This IS the client's interaction history;
   there is no separate summary table. The optional ``stakeholder_id`` tag is the
   "automated" half of stakeholder mapping (ADR-0013 Fork 3): engagement
   (interaction_count/last_interaction_at) is computed by a plain GROUP BY over this
   column, never by fragile name-matching or NLP-style extraction from ``summary``.

Grants: ``delta_app`` gets SELECT, INSERT, UPDATE on ``clients``/``deals``/
``stakeholders`` (mutable-but-append records — name/stage/role edits), and only
SELECT, INSERT on ``interactions`` (an interaction log entry, once written, is never
edited — mirrors ``change_history``'s INSERT-only grant from migration 0005). No table
gets DELETE. Same strict fail-closed NULLIF RLS predicate as every prior migration.

This migration is NOT wired into D-009's hash-chained financial audit log
(``delta.persistence.audit_log``): that chain's own docstring scopes it to Delta's
AUTOMATED FINANCIAL WORKFLOWS (allocations, budget-engine, kill-switch enforcement,
reconciliation failures) — CRM deal-stage transitions and stakeholder edits are
business-process data, not financial transactions or enforcement decisions. Named as a
deliberate scope boundary in ADR-0013 §3, not a silent omission.

DOWN: reverses every object in dependency order. Retains the ``delta`` schema and never
touches D-001..D-012 data.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0007"
down_revision: Union[str, None] = "0006"
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
    # ---------------------------------------------------------------------- clients
    op.create_table(
        "clients",
        sa.Column("client_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("primary_contact_name", sa.String(256), nullable=True),
        sa.Column("primary_contact_email", sa.String(320), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("client_id", "tenant_id", name="uq_client_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_index("ix_clients_tenant", "clients", ["tenant_id"], schema=_SCHEMA)

    # ------------------------------------------------------------------------ deals
    op.create_table(
        "deals",
        sa.Column("deal_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("client_id", sa.String(64), nullable=False),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("stage", sa.String(16), nullable=False, server_default="lead"),
        sa.Column("value_minor_units", sa.BigInteger, nullable=True),
        sa.Column("currency", sa.String(3), nullable=True),
        sa.Column("expected_close_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "value_minor_units IS NULL OR value_minor_units >= 0", name="ck_deal_value_nonneg"
        ),
        # A value and a currency always travel together (security-review finding,
        # ADR-0013 §4): a row with one and not the other is structurally impossible,
        # not just app-layer-enforced.
        sa.CheckConstraint(
            "(value_minor_units IS NULL) = (currency IS NULL)", name="ck_deal_value_currency_pair"
        ),
        sa.ForeignKeyConstraint(
            ["client_id", "tenant_id"],
            [f"{_SCHEMA}.clients.client_id", f"{_SCHEMA}.clients.tenant_id"],
            name="fk_deal_client",
        ),
        sa.UniqueConstraint("deal_id", "tenant_id", name="uq_deal_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_index("ix_deals_client", "deals", ["client_id"], schema=_SCHEMA)
    op.create_index("ix_deals_tenant_stage", "deals", ["tenant_id", "stage"], schema=_SCHEMA)

    # ------------------------------------------------------------------ stakeholders
    op.create_table(
        "stakeholders",
        sa.Column("stakeholder_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("client_id", sa.String(64), nullable=False),
        sa.Column("deal_id", sa.String(64), nullable=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("role", sa.String(16), nullable=False, server_default="unknown"),
        sa.Column("email", sa.String(320), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["client_id", "tenant_id"],
            [f"{_SCHEMA}.clients.client_id", f"{_SCHEMA}.clients.tenant_id"],
            name="fk_stakeholder_client",
        ),
        sa.ForeignKeyConstraint(
            ["deal_id", "tenant_id"],
            [f"{_SCHEMA}.deals.deal_id", f"{_SCHEMA}.deals.tenant_id"],
            name="fk_stakeholder_deal",
        ),
        sa.UniqueConstraint("stakeholder_id", "tenant_id", name="uq_stakeholder_id_tenant"),
        schema=_SCHEMA,
    )
    op.create_index("ix_stakeholders_client", "stakeholders", ["client_id"], schema=_SCHEMA)

    # ------------------------------------------------------------------ interactions
    op.create_table(
        "interactions",
        sa.Column("interaction_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("client_id", sa.String(64), nullable=False),
        sa.Column("deal_id", sa.String(64), nullable=True),
        sa.Column("stakeholder_id", sa.String(64), nullable=True),
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("interaction_type", sa.String(16), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("summary", sa.String(2048), nullable=False),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["client_id", "tenant_id"],
            [f"{_SCHEMA}.clients.client_id", f"{_SCHEMA}.clients.tenant_id"],
            name="fk_interaction_client",
        ),
        sa.ForeignKeyConstraint(
            ["deal_id", "tenant_id"],
            [f"{_SCHEMA}.deals.deal_id", f"{_SCHEMA}.deals.tenant_id"],
            name="fk_interaction_deal",
        ),
        sa.ForeignKeyConstraint(
            ["stakeholder_id", "tenant_id"],
            [f"{_SCHEMA}.stakeholders.stakeholder_id", f"{_SCHEMA}.stakeholders.tenant_id"],
            name="fk_interaction_stakeholder",
        ),
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_interactions_client_occurred",
        "interactions",
        ["client_id", "occurred_at"],
        schema=_SCHEMA,
    )
    op.create_index(
        "ix_interactions_stakeholder",
        "interactions",
        ["stakeholder_id"],
        schema=_SCHEMA,
    )

    # ----------------------------------------------------- delta_app grants + RLS
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.clients TO {_APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.deals TO {_APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT, UPDATE ON {_SCHEMA}.stakeholders TO {_APP_ROLE}")
    op.execute(f"GRANT SELECT, INSERT ON {_SCHEMA}.interactions TO {_APP_ROLE}")

    _enable_rls("clients", insert=True, update=True)
    _enable_rls("deals", insert=True, update=True)
    _enable_rls("stakeholders", insert=True, update=True)
    _enable_rls("interactions", insert=True, update=False)


def downgrade() -> None:
    for table in ("interactions", "stakeholders", "deals", "clients"):
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_update ON {_SCHEMA}.{table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_insert ON {_SCHEMA}.{table}")
        op.execute(f"DROP POLICY IF EXISTS {table}_tenant_select ON {_SCHEMA}.{table}")
        op.execute(f"REVOKE ALL ON {_SCHEMA}.{table} FROM {_APP_ROLE}")

    op.drop_index("ix_interactions_stakeholder", table_name="interactions", schema=_SCHEMA)
    op.drop_index("ix_interactions_client_occurred", table_name="interactions", schema=_SCHEMA)
    op.drop_table("interactions", schema=_SCHEMA)

    op.drop_index("ix_stakeholders_client", table_name="stakeholders", schema=_SCHEMA)
    op.drop_table("stakeholders", schema=_SCHEMA)

    op.drop_index("ix_deals_tenant_stage", table_name="deals", schema=_SCHEMA)
    op.drop_index("ix_deals_client", table_name="deals", schema=_SCHEMA)
    op.drop_table("deals", schema=_SCHEMA)

    op.drop_index("ix_clients_tenant", table_name="clients", schema=_SCHEMA)
    op.drop_table("clients", schema=_SCHEMA)
