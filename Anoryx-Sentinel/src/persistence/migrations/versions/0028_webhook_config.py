"""F-020 webhook_config table — per-tenant outbound webhook configuration (ADR-0023 §5.2).

Revision ID: 0028
Revises: 0027
Create Date: 2026-06-24

Creates the `webhook_config` table: the per-tenant registry of outbound webhook
targets (Slack / Jira / Splunk). One row per enabled integration per tenant.

Design (ADR-0023 §5.2 / D1–D4):
  - provider         VARCHAR(16)  — 'slack' | 'jira' | 'splunk'
  - target_url       TEXT         — validated at write AND re-validated at send
                                    by the SSRF guard (§7).  Plain VARCHAR not used
                                    because Splunk HEC self-hosted URLs may be long.
  - credential       BYTEA        — secret_box(AES-256-GCM) ciphertext.  The admin
                                    builder encrypts at write; the webhook-dispatcher
                                    worker decrypts at send.  NEVER plaintext.
  - signing_secret   BYTEA        — HMAC-SHA256 per-config signing key, secret_box
                                    ciphertext (D4).  Generic/Splunk deliveries sign
                                    the timestamp-in-body with this key; Slack/Jira
                                    use native auth and do NOT use this field.
  - min_severity     VARCHAR(16)  — 'high' | 'critical' — only events at or above
                                    this threshold are forwarded.
  - enabled          BOOLEAN      — soft-enable/disable without deleting the config.
  - team_id          VARCHAR(64)  — optional scope; NULL = all teams in the tenant.
  - project_id       VARCHAR(64)  — optional scope; NULL = all projects in the team.
  - created_at / updated_at — standard audit timestamps.

Tenant-scoped RLS (verbatim fail-closed NULLIF predicate from ADR-0005, established
in migrations 0006/0007/0018/0026): ENABLE + FORCE + DROP-IF-EXISTS + CREATE POLICY
+ GRANT SELECT/INSERT/UPDATE to sentinel_app (no DELETE — soft-disable via 'enabled').

Down revision: 0027 (verified as current head; 0028 is the first F-020 migration).

Reversible: downgrade() revokes, drops policy, disables RLS, drops table.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0028"
down_revision: Union[str, None] = "0027"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLE = "webhook_config"

# Fail-closed NULLIF predicate — verbatim from ADR-0005 / migrations 0006/0007/0018/0026.
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
        # Primary key — opaque UUID string matching the four-stable-IDs convention.
        sa.Column("config_id", sa.String(64), primary_key=True, nullable=False),
        # Tenant FK — RLS enforces row isolation per tenant.
        sa.Column(
            "tenant_id",
            sa.String(64),
            sa.ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        # Optional scope: NULL = all teams / all projects under the tenant.
        sa.Column("team_id", sa.String(64), nullable=True),
        sa.Column("project_id", sa.String(64), nullable=True),
        # Provider label — the three supported third parties (ADR-0023 D6).
        sa.Column("provider", sa.String(16), nullable=False),
        # Outbound target URL — validated by SSRF guard at write AND at send.
        # TEXT (not VARCHAR) to accommodate long Splunk HEC self-hosted URLs.
        sa.Column("target_url", sa.Text(), nullable=False),
        # Encrypted credential blob (secret_box AES-256-GCM ciphertext).
        # Admin builder seals at write; dispatcher unseals at send. Never plaintext.
        sa.Column("credential", sa.LargeBinary(), nullable=True),
        # Per-config HMAC signing key (secret_box ciphertext). Used for generic /
        # Splunk deliveries; NULL for Slack/Jira which use native auth.
        sa.Column("signing_secret", sa.LargeBinary(), nullable=True),
        # Minimum severity threshold — events below this are not forwarded.
        sa.Column("min_severity", sa.String(16), nullable=False, server_default="high"),
        # Soft enable/disable toggle — no DELETE path (R6).
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
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
        # CHECK constraints (bounded enums matching events.schema.json + ADR-0023).
        sa.CheckConstraint(
            "provider IN ('slack', 'jira', 'splunk')",
            name="ck_webhook_config_provider",
        ),
        sa.CheckConstraint(
            "min_severity IN ('high', 'critical')",
            name="ck_webhook_config_min_severity",
        ),
    )

    op.create_index("ix_webhook_config_tenant_id", _TABLE, ["tenant_id"])
    op.create_index("ix_webhook_config_tenant_provider", _TABLE, ["tenant_id", "provider"])
    op.create_index("ix_webhook_config_enabled", _TABLE, ["tenant_id", "enabled"])

    conn = op.get_bind()
    _enable_rls(conn)


def downgrade() -> None:
    conn = op.get_bind()

    conn.execute(sa.text(f"REVOKE SELECT, INSERT, UPDATE ON {_TABLE} FROM sentinel_app"))
    conn.execute(sa.text(f"DROP POLICY IF EXISTS tenant_isolation ON {_TABLE}"))
    conn.execute(sa.text(f"ALTER TABLE {_TABLE} DISABLE ROW LEVEL SECURITY"))

    op.drop_index("ix_webhook_config_enabled", table_name=_TABLE)
    op.drop_index("ix_webhook_config_tenant_provider", table_name=_TABLE)
    op.drop_index("ix_webhook_config_tenant_id", table_name=_TABLE)
    op.drop_table(_TABLE)
