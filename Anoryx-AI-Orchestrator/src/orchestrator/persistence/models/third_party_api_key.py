"""third_party_api_keys — the external-gateway credential (O-013, ADR-0013).

OPERATOR-GLOBAL infra (NOT tenant-scoped, NO RLS), mirroring the query_service_tokens
precedent (ADR-0006): the auth lookup must resolve the tenant BEFORE a tenant GUC can be
set, so this table cannot be RLS-scoped on itself (chicken-and-egg). It is read on the
PRIVILEGED session and carries no orchestrator_app grants (least privilege).

Only the SHA-256 hash of the issued secret is stored — the plaintext key is returned
exactly once, at issuance, and never stored or logged again. `status` lets an operator
revoke a credential without deleting the row (a revoked key's requests are still
chain-audited, unlike a wholly unknown key — see external_gateway/router.py). `scopes` is
a caller-declared allow-list of route capabilities (a closed enum checked at issuance
time, see external_gateway/router.py `_KNOWN_SCOPES`) — the gateway's own authorization
layer, independent of the tenant the key authenticates as.
"""

from __future__ import annotations

from sqlalchemy import Integer, String, text
from sqlalchemy.dialects.postgresql import ARRAY, TIMESTAMP
from sqlalchemy.orm import Mapped, mapped_column

from orchestrator.persistence.models.base import Base


class ThirdPartyApiKey(Base):
    __tablename__ = "third_party_api_keys"

    # Server-generated logical id ("extkey-" + uuid4 hex), issued by the router.
    key_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # The tenant this credential authenticates as (the resolved principal).
    tenant_id: Mapped[str] = mapped_column(String(64), nullable=False)
    # SHA-256 hex of the issued secret. UNIQUE (the auth lookup key). The plaintext is
    # returned once at issuance and never stored.
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    # Operator-facing description.
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    # Allow-listed route capabilities this key may call (e.g. "events:read").
    scopes: Mapped[list[str]] = mapped_column(ARRAY(String(64)), nullable=False)
    # active | revoked
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'active'"))
    rate_limit_per_minute: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[object] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False, server_default=text("now()")
    )
    revoked_at: Mapped[object | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
