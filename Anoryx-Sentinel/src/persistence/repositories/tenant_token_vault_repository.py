"""TenantTokenVaultRepository — data access for tenant_token_vault
(F-033, ADR-0039, migration 0035).
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.models.tenant_token_vault import TenantTokenVault


class TenantTokenVaultRepository:
    """Data-access object for the tenant_token_vault table."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self, tenant_id: str, token: str, token_type: str, ciphertext_b64: str
    ) -> TenantTokenVault:
        """Insert a token->ciphertext mapping. Caller MUST have already encrypted
        the original value (this repo never sees plaintext) and ensured the token
        is unique (retry on the (tenant_id, token) unique constraint)."""
        row = TenantTokenVault(
            vault_id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            token=token,
            token_type=token_type,
            ciphertext_b64=ciphertext_b64,
        )
        self._session.add(row)
        await self._session.flush()
        return row

    async def get_by_token(self, tenant_id: str, token: str) -> TenantTokenVault | None:
        """Return the vault row for (tenant_id, token), or None."""
        stmt = select(TenantTokenVault).where(
            TenantTokenVault.tenant_id == tenant_id,
            TenantTokenVault.token == token,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def token_exists(self, tenant_id: str, token: str) -> bool:
        stmt = select(TenantTokenVault.vault_id).where(
            TenantTokenVault.tenant_id == tenant_id,
            TenantTokenVault.token == token,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none() is not None
