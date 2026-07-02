"""query_service_tokens — the per-tenant read/query principal (O-006, ADR-0006).

OPERATOR-GLOBAL infra (NOT tenant-scoped, NO RLS), mirroring the sentinel_registry
precedent: one row per issued per-tenant service token. It maps the SHA-256 hash of a
presented Bearer secret to the tenant_id that credential authenticates as. The auth lookup
must resolve the tenant BEFORE a tenant GUC can be set, so this table cannot be RLS-scoped
on itself (chicken-and-egg); it is read on the PRIVILEGED session and carries no
orchestrator_app grants (least privilege).

Only the SHA-256 hash is stored — the plaintext token is NEVER stored or logged. `enabled`
lets an operator revoke a credential without deleting the row. Tokens are operator-seeded
via the privileged role (no self-service issuance API in O-006). A miss / disabled / absent
token resolves to no tenant → a uniform 401 at the request boundary (no enumeration oracle).
"""

from __future__ import annotations

from sqlalchemy import Boolean, String, text
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class QueryServiceToken(Base):
    __tablename__ = "query_service_tokens"

    # Logical, operator-chosen credential id.
    token_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # The tenant this credential authenticates as (the resolved principal).
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # SHA-256 hex of the presented Bearer secret. UNIQUE (the auth lookup key). The plaintext
    # is never stored. The unique index is created in the migration (mirrors registry style).
    token_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    # Operator-facing description.
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    # Operator revoke without delete (a disabled token resolves to no tenant → 401).
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    created_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
