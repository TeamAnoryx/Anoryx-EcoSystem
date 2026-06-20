"""VirtualApiKeyRepository — data access for virtual_api_keys table (F-003b).

SECURITY INVARIANTS:
1. Plaintext API keys are NEVER persisted. Only HMAC-SHA256 (hex) is stored.
2. Lookup uses hmac.compare_digest (constant-time) to prevent timing attacks.
3. The row is the authoritative source of tenant/team/project/agent IDs.
   Auth resolves IDs from this row — never from client-supplied headers.
4. SENTINEL_KEY_SECRET must be set in the environment. Absence raises RuntimeError.
5. lookup_by_plaintext() rejects expired keys (expires_at <= now()) and
   never-expiring keys (expires_at IS NULL) are accepted.

F-003b (ADR-0005): get_by_id now accepts caller_tenant_id as a defense-in-depth
guard. RLS on the tenant session is the primary boundary; the app-layer check is
the second lock and makes the security intent explicit in code review.

Key lifecycle:
- At creation: caller generates a random key, passes it as plaintext once.
  Repository computes HMAC, stores the fingerprint. Returns the ORM row.
  Caller is responsible for showing the plaintext to the user exactly once.
- At auth: caller passes the plaintext key. Repository computes HMAC, does
  constant-time compare against all active keys (via index lookup by fingerprint).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import uuid
from datetime import datetime

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.models.virtual_api_key import VirtualApiKey


class VirtualApiKeyNotFoundError(Exception):
    """Raised when a key lookup finds no matching active row."""


class VirtualApiKeyAuthError(Exception):
    """Raised when a plaintext key does not match any stored fingerprint."""


def _get_key_secret() -> bytes:
    """Return the SENTINEL_KEY_SECRET as bytes. Raises RuntimeError if absent."""
    secret = os.environ.get("SENTINEL_KEY_SECRET", "")
    if not secret:
        raise RuntimeError("SENTINEL_KEY_SECRET environment variable is not set.")
    return secret.encode("utf-8")


def compute_key_fingerprint(plaintext_key: str) -> str:
    """Compute HMAC-SHA256 hex fingerprint of the plaintext key.

    Uses SENTINEL_KEY_SECRET as the HMAC key. Returns a 64-char hex string.
    """
    secret = _get_key_secret()
    return hmac.new(secret, plaintext_key.encode("utf-8"), hashlib.sha256).hexdigest()


class VirtualApiKeyRepository:
    """Data-access object for virtual_api_keys. Enforces HMAC-only storage."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        plaintext_key: str,
        tenant_id: str,
        team_id: str,
        project_id: str,
        agent_id: str,
        label: str | None = None,
        expires_at: datetime | None = None,
    ) -> VirtualApiKey:
        """Create a virtual API key. Stores HMAC fingerprint — NOT the plaintext.

        The caller must surface the plaintext key to the user exactly once
        before discarding it. This method never returns the plaintext.
        """
        fingerprint = compute_key_fingerprint(plaintext_key)
        key = VirtualApiKey(
            key_id=str(uuid.uuid4()),
            key_fingerprint=fingerprint,
            tenant_id=tenant_id,
            team_id=team_id,
            project_id=project_id,
            agent_id=agent_id,
            label=label,
            is_active=True,
            expires_at=expires_at,
        )
        self._session.add(key)
        await self._session.flush()
        return key

    async def lookup_by_plaintext(self, plaintext_key: str) -> VirtualApiKey:
        """Authenticate a plaintext API key.

        Computes HMAC of the supplied key, then queries by fingerprint.
        Rejects rows where:
          - is_active is False
          - expires_at IS NOT NULL AND expires_at <= now()  (expired)
        Never-expiring keys (expires_at IS NULL) are accepted.

        Uses hmac.compare_digest for constant-time comparison at the Python
        layer (defense-in-depth on top of the fingerprint DB query).

        Raises VirtualApiKeyAuthError on any failure (no timing leak between
        "not found" and "wrong key" — both surface the same error class).
        """
        candidate_fp = compute_key_fingerprint(plaintext_key)
        stmt = select(VirtualApiKey).where(
            VirtualApiKey.key_fingerprint == candidate_fp,
            VirtualApiKey.is_active.is_(True),
            # Accept only: never-expiring OR not yet expired.
            (VirtualApiKey.expires_at.is_(None) | (VirtualApiKey.expires_at > func.now())),
        )
        result = await self._session.execute(stmt)
        key_row = result.scalar_one_or_none()

        if key_row is None:
            raise VirtualApiKeyAuthError("Invalid or inactive API key.")

        # Constant-time comparison at the application layer as defense-in-depth.
        stored_fp = key_row.key_fingerprint
        if not hmac.compare_digest(candidate_fp, stored_fp):
            raise VirtualApiKeyAuthError("Invalid or inactive API key.")

        return key_row

    async def get_by_id(self, key_id: str, caller_tenant_id: str) -> VirtualApiKey:
        """Return the key row for key_id, or raise VirtualApiKeyNotFoundError.

        caller_tenant_id is REQUIRED (LOW-1, ADR-0005 round-2).  The WHERE
        clause always includes AND tenant_id = caller_tenant_id.  RLS on the
        tenant session is the primary boundary; this check is the second lock.
        """
        stmt = select(VirtualApiKey).where(VirtualApiKey.key_id == key_id)
        stmt = stmt.where(VirtualApiKey.tenant_id == caller_tenant_id)
        result = await self._session.execute(stmt)
        key_row = result.scalar_one_or_none()
        if key_row is None:
            raise VirtualApiKeyNotFoundError(f"Key not found: {key_id!r}")
        return key_row

    async def deactivate(self, key_id: str, caller_tenant_id: str) -> VirtualApiKey:
        """Revoke a virtual API key by marking it inactive."""
        key_row = await self.get_by_id(key_id, caller_tenant_id=caller_tenant_id)
        key_row.is_active = False
        await self._session.flush()
        return key_row

    async def list_for_tenant(self, tenant_id: str) -> list[VirtualApiKey]:
        """Return all keys for a tenant, newest-first (F-012 admin list).

        Defense-in-depth: explicit WHERE tenant_id = ... on top of RLS. The
        caller (admin list route) maps each row to a metadata-only response that
        NEVER includes key_fingerprint or any secret (R4).
        """
        stmt = (
            select(VirtualApiKey)
            .where(VirtualApiKey.tenant_id == tenant_id)
            .order_by(VirtualApiKey.created_at.desc(), VirtualApiKey.key_id)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def deactivate_all_for_tenant(self, tenant_id: str) -> int:
        """Bulk-deactivate all ACTIVE keys for a tenant. Returns the count affected.

        Used by the admin tenant-deactivate cascade (F-012, ADR-0014 — vector 13):
        when a tenant is soft-deactivated, its keys must be denied at the gateway.
        Runs on the privileged session (the tenant-deactivate path); the gateway
        then rejects each key via the is_active=False lookup filter.
        """
        stmt = (
            update(VirtualApiKey)
            .where(VirtualApiKey.tenant_id == tenant_id)
            .where(VirtualApiKey.is_active.is_(True))
            .values(is_active=False)
        )
        result = await self._session.execute(stmt)
        return int(result.rowcount or 0)

    async def rotate(self, key_id: str, plaintext_new: str, caller_tenant_id: str) -> VirtualApiKey:
        """Immediate-revoke rotation (F-012, ADR-0014 D4): deactivate the old key
        and mint a new one carrying the SAME tenant/team/project/agent/label, in a
        single transaction. The old key is dead the instant the new one is created.

        The new key does NOT inherit expires_at (a fresh key, never-expiring unless
        re-specified) so a rotated key is never dead-on-arrival from a stale expiry.
        Raises VirtualApiKeyNotFoundError if the old key is absent for this tenant.
        """
        old = await self.get_by_id(key_id, caller_tenant_id=caller_tenant_id)
        old.is_active = False
        await self._session.flush()
        return await self.create(
            plaintext_new,
            tenant_id=old.tenant_id,
            team_id=old.team_id,
            project_id=old.project_id,
            agent_id=old.agent_id,
            label=old.label,
        )
