"""WebhookConfig ORM model (F-020, ADR-0023 §5.2).

Per-tenant registry of outbound webhook targets (Slack / Jira / Splunk).
One row per integration per tenant. The presence and content of this row
determines whether events are forwarded, to which provider, and at what
severity threshold.

Credentials are NEVER stored in plaintext. The `credential` and `signing_secret`
columns hold secret_box(AES-256-GCM) ciphertext only — sealed by the admin builder
at write time, unsealed by the webhook-dispatcher worker at send time (D4).

Tenant-scoped under RLS (migration 0028, verbatim NULLIF predicate from ADR-0005 /
migrations 0006/0007/0018/0026). One tenant's webhook config is never visible to
another tenant's session (R4). No DELETE path — use `enabled=False` to disable
(soft-disable). The GRANT covers SELECT, INSERT, UPDATE to sentinel_app only.

Scope columns (team_id, project_id) are optional. NULL = all teams / all projects
under the tenant. Non-NULL scope restricts forwarding to matching event scopes
(checked by the dispatcher filter, not enforced by DB — the DB stores intent).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from persistence.models.base import Base

# Provider labels (matches contracts/events.schema.json WebhookDeliveredEvent.webhook_provider).
WEBHOOK_PROVIDERS = ("slack", "jira", "splunk")

# Minimum severity thresholds (ADR-0023 §5.2 / D6).
WEBHOOK_SEVERITY_THRESHOLDS = ("high", "critical")


class WebhookConfig(Base):
    """A single tenant-scoped outbound webhook configuration row."""

    __tablename__ = "webhook_config"

    config_id: Mapped[str] = mapped_column(String(64), primary_key=True)

    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # Optional scope. NULL = tenant-wide (all teams / all projects).
    team_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    project_id: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # Third-party provider target — 'slack' | 'jira' | 'splunk'.
    provider: Mapped[str] = mapped_column(String(16), nullable=False)

    # Outbound target URL. Validated by SSRF guard at write AND at send (§7).
    # TEXT (not VARCHAR) to accommodate long Splunk HEC self-hosted URLs.
    target_url: Mapped[str] = mapped_column(Text(), nullable=False)

    # secret_box(AES-256-GCM) ciphertext blobs — NEVER plaintext (D4).
    # credential: provider auth material (Slack webhook URL secret, Jira token, Splunk
    #   HEC token). Nullable — may be absent if the provider uses URL-embedded auth.
    # signing_secret: per-config HMAC-SHA256 signing key for generic/Splunk deliveries.
    #   NULL for Slack/Jira (native auth; no Sentinel HMAC layer added).
    credential: Mapped[bytes | None] = mapped_column(LargeBinary(), nullable=True)
    signing_secret: Mapped[bytes | None] = mapped_column(LargeBinary(), nullable=True)

    # Minimum severity threshold. Events below this are not forwarded.
    min_severity: Mapped[str] = mapped_column(String(16), nullable=False, server_default="high")

    # Soft enable/disable — no DELETE path. Disabled configs are skipped by
    # the dispatcher filter; no rows are removed.
    enabled: Mapped[bool] = mapped_column(Boolean(), nullable=False, server_default="true")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        CheckConstraint(
            "provider IN ('slack', 'jira', 'splunk')",
            name="ck_webhook_config_provider",
        ),
        CheckConstraint(
            "min_severity IN ('high', 'critical')",
            name="ck_webhook_config_min_severity",
        ),
        Index("ix_webhook_config_tenant_id", "tenant_id"),
        Index("ix_webhook_config_tenant_provider", "tenant_id", "provider"),
        Index("ix_webhook_config_enabled", "tenant_id", "enabled"),
    )

    def __repr__(self) -> str:
        return (
            f"<WebhookConfig config_id={self.config_id!r} "
            f"tenant={self.tenant_id!r} provider={self.provider!r} "
            f"enabled={self.enabled!r}>"
        )
