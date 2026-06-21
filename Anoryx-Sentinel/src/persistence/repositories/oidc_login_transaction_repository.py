"""OidcLoginTransactionRepository — pre-auth single-use OIDC state store (F-014 STEP 4).

ADR-0017 §5 (D4). Backs the OIDC authorization-code + PKCE flow with the
server-side, single-use transaction required to defeat CSRF (vector 9) and
ID-token / nonce replay (vector 10) — a signed cookie alone is replayable, so
the single-use guarantee lives in the database.

GLOBAL / PRIVILEGED-ONLY (no RLS):
  The OIDC login endpoints are UNAUTHENTICATED (the assertion IS the auth), so at
  login-start no tenant session context exists. This table is keyed by an
  unguessable random `state` and binds `tenant_id` as a column. ALL methods here
  require a PRIVILEGED session (get_privileged_session()); the NOBYPASSRLS
  sentinel_app role has no grant on the table (migration 0016). This mirrors the
  global `tenants` registry pattern.

SINGLE-USE (the load-bearing replay guard, vector 10):
  consume() is a single atomic UPDATE ... WHERE state=:state AND consumed_at IS
  NULL AND expires_at > now() ... RETURNING. Because the row-level write lock plus
  the `consumed_at IS NULL` predicate are evaluated together, two concurrent
  consumes of the same state can never BOTH succeed — exactly one sets consumed_at
  and gets the row; the loser's predicate no longer matches and it returns None.
  A second (later) consume of an already-consumed state likewise matches nothing.
  An expired row (`expires_at <= now()`) is never consumable (fail-closed).

R6: this store NEVER holds tokens, the authorization code, or any claim — only the
server-side handles (state/nonce/code_verifier) and the tenant binding.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.models.sso_identity import OidcLoginTransaction


class OidcLoginTransactionRepository:
    """Data-access object for oidc_login_transaction. Privileged session only."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def create(
        self,
        *,
        state: str,
        nonce: str,
        code_verifier: str,
        tenant_id: str,
        idp_config_id: str,
        ttl_seconds: int,
    ) -> OidcLoginTransaction:
        """Persist a new single-use login transaction with a hard TTL.

        `state` is the unguessable random handle (PK). `nonce` and `code_verifier`
        are the server-side secrets that bind the eventual ID token / token
        exchange. `tenant_id` is the idp_config OWNER (the R1 binding). The caller
        controls the transaction boundary (commit on the privileged session).
        """
        now = datetime.now(timezone.utc)
        row = OidcLoginTransaction(
            state=state,
            nonce=nonce,
            code_verifier=code_verifier,
            tenant_id=tenant_id,
            idp_config_id=idp_config_id,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        self._session.add(row)
        await self._session.flush()
        return row

    async def consume(self, *, state: str) -> OidcLoginTransaction | None:
        """Atomically consume the transaction for `state`, or return None.

        Returns the row IFF it exists AND is not expired AND was not already
        consumed — setting consumed_at in the SAME statement (single-use). A second
        consume of the same state, an unknown/forged state, or an expired state all
        return None (vectors 9, 10 — fail-closed; the caller MUST reject).

        Implemented as one UPDATE ... RETURNING so the existence check and the
        consumed_at write are a single atomic, concurrency-safe operation.
        """
        stmt = (
            update(OidcLoginTransaction)
            .where(
                OidcLoginTransaction.state == state,
                OidcLoginTransaction.consumed_at.is_(None),
                OidcLoginTransaction.expires_at > text("now()"),
            )
            .values(consumed_at=datetime.now(timezone.utc))
            .returning(OidcLoginTransaction)
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def delete_expired(self) -> int:
        """Opportunistically delete expired rows. Returns the number removed.

        Best-effort cleanup of the pre-auth store; safe to call on the same
        privileged transaction as create(). Never touches live (unexpired) rows.
        """
        stmt = delete(OidcLoginTransaction).where(OidcLoginTransaction.expires_at <= text("now()"))
        result = await self._session.execute(stmt)
        return result.rowcount or 0
