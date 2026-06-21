"""SamlLoginTransactionRepository — pre-auth single-use SAML state store (F-014 STEP 5).

ADR-0017 §6 (D5). Backs the SP-initiated SAML flow (Fork 4) with the server-side,
single-use transaction required to bind a SAMLResponse to the AuthnRequest the SP
actually issued — the `InResponseTo` defence against replay AND IdP-initiated
response injection (vector 7).

GLOBAL / PRIVILEGED-ONLY (no RLS):
  The SAML login + ACS endpoints are UNAUTHENTICATED (the signed assertion IS the
  auth), so at login-start no tenant session context exists. This table is keyed by
  the SP-generated AuthnRequest `request_id` and binds `tenant_id` as a column. ALL
  methods here require a PRIVILEGED session (get_privileged_session()); the
  NOBYPASSRLS sentinel_app role has no grant on the table (migration 0017). This
  mirrors OidcLoginTransactionRepository and the global `tenants` registry pattern.

SINGLE-USE (the load-bearing replay guard, vector 7):
  consume() is a single atomic UPDATE ... WHERE request_id=:rid AND consumed_at IS
  NULL AND expires_at > now() ... RETURNING. Because the row-level write lock plus
  the `consumed_at IS NULL` predicate are evaluated together, two concurrent
  consumes of the same request_id can never BOTH succeed — exactly one sets
  consumed_at and gets the row; the loser's predicate no longer matches and it
  returns None. A second (later) consume of an already-consumed request_id likewise
  matches nothing. An unknown/forged request_id (e.g. an IdP-initiated response with
  no matching AuthnRequest) matches nothing. An expired row (`expires_at <= now()`)
  is never consumable (fail-closed).

R6: this store NEVER holds the SAMLResponse, the assertion, or any attribute — only
the server-side AuthnRequest handle (request_id) and the tenant binding.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.models.sso_identity import SamlLoginTransaction


class SamlLoginTransactionRepository:
    """Data-access object for saml_login_transaction. Privileged session only."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        request_id: str,
        tenant_id: str,
        idp_config_id: str,
        ttl_seconds: int,
    ) -> SamlLoginTransaction:
        """Persist a new single-use login transaction with a hard TTL.

        `request_id` is the SP-generated AuthnRequest ID (PK) that the IdP echoes
        back as `InResponseTo`. `tenant_id` is the SAML idp_config OWNER (the R1
        binding). The caller controls the transaction boundary (commit on the
        privileged session).
        """
        now = datetime.now(timezone.utc)
        row = SamlLoginTransaction(
            request_id=request_id,
            tenant_id=tenant_id,
            idp_config_id=idp_config_id,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        self._session.add(row)
        await self._session.flush()
        return row

    async def consume(self, *, request_id: str) -> SamlLoginTransaction | None:
        """Atomically consume the transaction for `request_id`, or return None.

        Returns the row IFF it exists AND is not expired AND was not already
        consumed — setting consumed_at in the SAME statement (single-use). A second
        consume of the same request_id, an unknown/forged request_id (an
        IdP-initiated response carrying no/foreign InResponseTo), or an expired
        request_id all return None (vector 7 — fail-closed; the caller MUST reject).

        Implemented as one UPDATE ... RETURNING so the existence check and the
        consumed_at write are a single atomic, concurrency-safe operation.
        """
        stmt = (
            update(SamlLoginTransaction)
            .where(
                SamlLoginTransaction.request_id == request_id,
                SamlLoginTransaction.consumed_at.is_(None),
                SamlLoginTransaction.expires_at > text("now()"),
            )
            .values(consumed_at=datetime.now(timezone.utc))
            .returning(SamlLoginTransaction)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def delete_expired(self) -> int:
        """Opportunistically delete expired rows. Returns the number removed.

        Best-effort cleanup of the pre-auth store; safe to call on the same
        privileged transaction as create(). Never touches live (unexpired) rows.
        """
        stmt = delete(SamlLoginTransaction).where(SamlLoginTransaction.expires_at <= text("now()"))
        result = await self._session.execute(stmt)
        return result.rowcount or 0
