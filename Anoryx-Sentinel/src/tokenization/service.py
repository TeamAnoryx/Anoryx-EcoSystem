"""tokenize() / detokenize() — the multi-layer service (F-033, ADR-0039).

tokenize(): LAYER 1 generates a format-preserving surrogate token; LAYER 2
encrypts the original (AES-256-GCM) and stores token->ciphertext in the
tenant's RLS vault. Returns the token. detokenize(): looks up the tenant's
vault row via a tenant session (RLS), decrypts, returns the original.

Both paths are fail-closed: no vault key -> refuse (TokenVaultKeyError); a
token not in this tenant's vault -> TokenNotFoundError (never a guessed value).
"""

from __future__ import annotations

from tokenization.crypto import decrypt, encrypt
from tokenization.exceptions import TokenNotFoundError
from tokenization.formats import generate_surrogate

_MAX_TOKEN_COLLISION_RETRIES = 5


def _tenant_aad(tenant_id: str) -> bytes:
    """AES-GCM associated data binding a vault ciphertext to its tenant."""
    return f"tenant:{tenant_id}".encode()


async def tokenize(
    tenant_id: str, value: str, *, token_type: str = "generic"  # noqa: S107 — a token-format name
) -> str:
    """Tokenize `value` for a tenant. Returns the format-preserving token.

    Idempotency note: surrogates are RANDOM, so calling tokenize twice on the
    same value yields two different tokens + two vault rows (both detokenize to
    the same value). Deterministic/referential tokenization is a documented
    alternative (ADR-0039), not the default.
    """
    from persistence.database import get_tenant_session
    from persistence.repositories.tenant_token_vault_repository import (
        TenantTokenVaultRepository,
    )

    # LAYER 2 (fail-closed if no vault key). Bind tenant_id as AES-GCM associated
    # data so a blob only decrypts under its own tenant (defence-in-depth
    # complement to RLS — see crypto.encrypt).
    ciphertext_b64 = encrypt(value, aad=_tenant_aad(tenant_id))

    async with get_tenant_session(tenant_id) as ts:
        repo = TenantTokenVaultRepository(ts)
        # LAYER 1: generate a unique surrogate (retry on the rare collision).
        for _attempt in range(_MAX_TOKEN_COLLISION_RETRIES):
            token = generate_surrogate(token_type, value)
            if not await repo.token_exists(tenant_id, token):
                await repo.create(tenant_id, token, token_type, ciphertext_b64)
                await ts.commit()
                return token
        raise RuntimeError("could not generate a unique token after retries")  # pragma: no cover


async def detokenize(tenant_id: str, token: str) -> str:
    """Reverse a token back to its original value for a tenant.

    Raises TokenNotFoundError if the token is not in THIS tenant's vault (RLS
    ensures a token from another tenant is invisible here — no cross-tenant
    detokenization)."""
    from persistence.database import get_tenant_session
    from persistence.repositories.tenant_token_vault_repository import (
        TenantTokenVaultRepository,
    )

    async with get_tenant_session(tenant_id) as ts:
        row = await TenantTokenVaultRepository(ts).get_by_token(tenant_id, token)
    if row is None:
        raise TokenNotFoundError("no vault entry for token in this tenant")
    # LAYER 2 reverse (fail-closed). Same tenant AAD as tokenize — a blob from
    # another tenant/row would fail authentication here even absent RLS.
    return decrypt(row.ciphertext_b64, aad=_tenant_aad(tenant_id))
