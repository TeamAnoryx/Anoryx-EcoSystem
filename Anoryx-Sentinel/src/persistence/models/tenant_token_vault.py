"""TenantTokenVault ORM model (F-033, ADR-0039).

The LAYER-2 vault: maps a surface token -> AES-256-GCM ciphertext of the
original PII value, per tenant. One row per tokenized value.

Tenant-scoped under RLS (migration 0035, verbatim NULLIF predicate from
ADR-0005 / migrations 0006..0034). One tenant's tokens are never visible to
another tenant's session (R4) — detokenization goes through a tenant session,
so a token from tenant A cannot be reversed under tenant B.

`ciphertext_b64` holds `base64(nonce ‖ AESGCM(original))` (tokenization.crypto);
NO plaintext is stored. `token` is the format-preserving surrogate (unique per
tenant so it is a stable lookup key). No DELETE path here — a `purge` is a
future addition (soft-retention decisions belong with the operator).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from persistence.models.base import Base


class TenantTokenVault(Base):
    """A single tenant-scoped reversible tokenization vault entry."""

    __tablename__ = "tenant_token_vault"

    vault_id: Mapped[str] = mapped_column(String(64), primary_key=True)

    tenant_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("tenants.tenant_id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )

    # The format-preserving surrogate token that replaced the PII value.
    token: Mapped[str] = mapped_column(String(128), nullable=False)

    # "card" | "ssn" | "digits" | "generic".
    token_type: Mapped[str] = mapped_column(String(16), nullable=False)

    # base64(nonce ‖ AESGCM(original)). NO plaintext.
    ciphertext_b64: Mapped[str] = mapped_column(Text(), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        # A token is a stable lookup key WITHIN a tenant.
        UniqueConstraint("tenant_id", "token", name="uq_tenant_token_vault_tenant_token"),
        CheckConstraint("length(token) > 0", name="ck_tenant_token_vault_token_nonempty"),
        CheckConstraint("length(ciphertext_b64) > 0", name="ck_tenant_token_vault_ct_nonempty"),
        Index("ix_tenant_token_vault_tenant_id", "tenant_id"),
        Index("ix_tenant_token_vault_tenant_token", "tenant_id", "token"),
    )

    def __repr__(self) -> str:
        return (
            f"<TenantTokenVault vault_id={self.vault_id!r} tenant={self.tenant_id!r} "
            f"token_type={self.token_type!r}>"
        )
