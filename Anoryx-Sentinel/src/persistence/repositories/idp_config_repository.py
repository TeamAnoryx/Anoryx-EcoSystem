"""IdpConfigRepository — data access for the idp_config table (F-014 STEP 3).

Per-tenant IdP configuration (OIDC or SAML) with encrypted-at-rest secrets
(ADR-0017 D3, R6). The two secret columns — client_secret_enc (OIDC) and
sp_private_key_enc (SAML SP private key) — ONLY ever hold AES-256-GCM ciphertext
produced by admin.sso.secret_box. Plaintext secrets are encrypted BEFORE the row
is written and are NEVER stored, returned to a client, or logged.

SECURITY INVARIANTS:
1. caller_tenant_id-guarded (app-layer defense-in-depth on top of RLS — the same
   pattern as VirtualApiKeyRepository / AdminUserRepository). All writes/reads
   include AND tenant_id = caller_tenant_id; RLS on the tenant session is the
   primary boundary.
2. Secrets are encrypted via secret_box.encrypt() before the column is set. If the
   encryption key is unset/invalid the encrypt RAISES (IdpSecretKeyError) and the
   write is aborted — the config is NEVER stored with a plaintext (or absent)
   secret silently (fail-closed, R6).
3. get_metadata() / list_for_tenant() return a dict that carries NO secret and NO
   ciphertext — only a boolean *_set indicator (R6). This is what endpoints return.
4. One active config per (tenant_id, protocol) — enforced by the partial unique
   index in migration 0014 AND by upsert() (it UPDATEs the existing active row in
   place, or inserts the first one).
5. get_decrypted_secret() is the ONLY method that decrypts, and it is used at the
   middleware use-site (OIDC/SAML), never on any logging/serialization path.

TYPE CONTRACT:
  id / tenant_id are VARCHAR(64); accepted/returned as plain str. IDs are
  str(uuid.uuid4()) at the app layer.

SESSION REQUIREMENT:
  All methods require a tenant-scoped session (get_tenant_session(tenant_id)).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from admin.sso import secret_box
from persistence.models.sso_identity import IdpConfig

_VALID_PROTOCOLS: frozenset[str] = frozenset({"oidc", "saml"})

# Secret-bearing columns — used to pick the right decrypt target and to keep the
# metadata projection honest (never leak these).
_OIDC_SECRET_FIELD = "client_secret"  # noqa: S105 — field-name label, not a secret value
_SAML_SECRET_FIELD = "sp_private_key"  # noqa: S105 — field-name label, not a secret value


class IdpConfigNotFoundError(Exception):
    """Raised when an idp_config lookup finds no matching active row."""


def _validate_protocol(protocol: str) -> None:
    if protocol not in _VALID_PROTOCOLS:
        raise ValueError(f"protocol must be one of {sorted(_VALID_PROTOCOLS)!r}, got {protocol!r}")


class IdpConfigRepository:
    """Data-access object for idp_config. All methods are caller_tenant_id-scoped."""

    # Non-secret, settable config fields (mirrors the OIDC + SAML columns).
    _SETTABLE_FIELDS = (
        "issuer",
        "client_id",
        "scopes",
        "idp_entity_id",
        "idp_sso_url",
        "idp_x509_cert",
        "sp_acs_url",
        "audience",
    )

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert(
        self,
        *,
        tenant_id: str,
        protocol: str,
        caller_tenant_id: str,
        client_secret_plaintext: str | None = None,
        sp_private_key_plaintext: str | None = None,
        **fields: Any,
    ) -> IdpConfig:
        """Create or update the active IdP config for (tenant_id, protocol).

        Encrypts client_secret_plaintext / sp_private_key_plaintext via secret_box
        BEFORE storing them in the *_enc columns. One active config per
        (tenant_id, protocol): if an active row exists it is UPDATEd in place,
        otherwise a new row is inserted. A provided plaintext secret REPLACES the
        stored ciphertext; passing None leaves the existing ciphertext untouched
        on update (and absent on insert).

        caller_tenant_id MUST equal tenant_id (defense-in-depth on top of RLS).
        Unknown keyword fields raise TypeError (closed input). Raises
        IdpSecretKeyError (fail-closed) if a secret is supplied but encryption is
        unavailable — the row is NOT written in that case.

        Returns the upserted IdpConfig row (ORM object; the *_enc columns hold
        ciphertext — callers MUST use get_metadata() for anything client-facing).
        """
        _validate_protocol(protocol)
        if tenant_id != caller_tenant_id:
            raise ValueError(
                f"tenant mismatch: caller_tenant_id={caller_tenant_id!r} "
                f"does not match tenant_id={tenant_id!r}"
            )
        unknown = set(fields) - set(self._SETTABLE_FIELDS)
        if unknown:
            raise TypeError(f"unknown idp_config field(s): {sorted(unknown)!r}")

        # Encrypt secrets up front (before any DB mutation). If the key is
        # unset/invalid this raises and nothing is written (fail-closed, R6).
        client_secret_enc = (
            secret_box.encrypt(client_secret_plaintext)
            if client_secret_plaintext is not None
            else None
        )
        sp_private_key_enc = (
            secret_box.encrypt(sp_private_key_plaintext)
            if sp_private_key_plaintext is not None
            else None
        )

        existing = await self._get_active_row(
            tenant_id=tenant_id, protocol=protocol, caller_tenant_id=caller_tenant_id
        )

        if existing is not None:
            values: dict[str, Any] = {k: v for k, v in fields.items()}
            if client_secret_enc is not None:
                values["client_secret_enc"] = client_secret_enc
            if sp_private_key_enc is not None:
                values["sp_private_key_enc"] = sp_private_key_enc
            values["updated_at"] = datetime.now(timezone.utc)
            stmt = (
                update(IdpConfig)
                .where(
                    IdpConfig.id == existing.id,
                    IdpConfig.tenant_id == caller_tenant_id,
                )
                .values(**values)
                .returning(IdpConfig)
            )
            result = await self._session.execute(stmt)
            return result.scalar_one()

        row = IdpConfig(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            protocol=protocol,
            is_active=True,
            client_secret_enc=client_secret_enc,
            sp_private_key_enc=sp_private_key_enc,
            **{k: fields.get(k) for k in self._SETTABLE_FIELDS},
        )
        self._session.add(row)
        await self._session.flush()
        return row

    async def _get_active_row(
        self, *, tenant_id: str, protocol: str, caller_tenant_id: str
    ) -> IdpConfig | None:
        """Return the active IdpConfig ORM row for (tenant, protocol), or None."""
        if tenant_id != caller_tenant_id:
            raise ValueError(
                f"tenant mismatch: caller_tenant_id={caller_tenant_id!r} "
                f"does not match tenant_id={tenant_id!r}"
            )
        stmt = select(IdpConfig).where(
            IdpConfig.tenant_id == caller_tenant_id,
            IdpConfig.protocol == protocol,
            IdpConfig.is_active.is_(True),
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_active(
        self, *, tenant_id: str, protocol: str, caller_tenant_id: str
    ) -> IdpConfig:
        """Return the active IdpConfig ORM row, or raise IdpConfigNotFoundError.

        For internal use by the OIDC/SAML middleware (the use-site). The returned
        row's *_enc columns hold ciphertext — decrypt via get_decrypted_secret().
        NEVER serialize this row to a client; use get_metadata() for that.
        """
        row = await self._get_active_row(
            tenant_id=tenant_id, protocol=protocol, caller_tenant_id=caller_tenant_id
        )
        if row is None:
            raise IdpConfigNotFoundError(
                f"no active idp_config for tenant_id={tenant_id!r} protocol={protocol!r}"
            )
        return row

    async def get_decrypted_secret(
        self, *, tenant_id: str, protocol: str, field: str, caller_tenant_id: str
    ) -> bytes | None:
        """Decrypt and return one secret (client_secret | sp_private_key) at the use-site.

        Returns the plaintext bytes, or None when the corresponding *_enc column
        is empty. This is the ONLY decryption path; callers MUST keep the result
        out of every log/audit/serialization path (R6). Raises IdpSecretKeyError
        (fail-closed) when the encryption key is unavailable.
        """
        if field not in (_OIDC_SECRET_FIELD, _SAML_SECRET_FIELD):
            raise ValueError(
                f"field must be {_OIDC_SECRET_FIELD!r} or {_SAML_SECRET_FIELD!r}, got {field!r}"
            )
        row = await self.get_active(
            tenant_id=tenant_id, protocol=protocol, caller_tenant_id=caller_tenant_id
        )
        enc = row.client_secret_enc if field == _OIDC_SECRET_FIELD else row.sp_private_key_enc
        if enc is None:
            return None
        return secret_box.decrypt(enc)

    async def get_metadata(
        self, *, tenant_id: str, protocol: str, caller_tenant_id: str
    ) -> dict[str, Any] | None:
        """Return client-facing config METADATA (no secret, no ciphertext), or None.

        The returned dict carries booleans `client_secret_set` / `sp_private_key_set`
        in place of the secret material (R6) — never the bytes themselves.
        """
        row = await self._get_active_row(
            tenant_id=tenant_id, protocol=protocol, caller_tenant_id=caller_tenant_id
        )
        if row is None:
            return None
        return self._to_metadata(row)

    async def list_for_tenant(
        self, *, tenant_id: str, caller_tenant_id: str
    ) -> list[dict[str, Any]]:
        """Return metadata for all active configs for the tenant (no secrets)."""
        if tenant_id != caller_tenant_id:
            raise ValueError(
                f"tenant mismatch: caller_tenant_id={caller_tenant_id!r} "
                f"does not match tenant_id={tenant_id!r}"
            )
        stmt = (
            select(IdpConfig)
            .where(
                IdpConfig.tenant_id == caller_tenant_id,
                IdpConfig.is_active.is_(True),
            )
            .order_by(IdpConfig.protocol)
        )
        result = await self._session.execute(stmt)
        return [self._to_metadata(row) for row in result.scalars().all()]

    @staticmethod
    def _to_metadata(row: IdpConfig) -> dict[str, Any]:
        """Project an IdpConfig row to a secret-free metadata dict (R6).

        Deliberately OMITS client_secret_enc and sp_private_key_enc; exposes only
        a boolean indicator that each secret is set. No ciphertext leaves here.
        """
        return {
            "id": row.id,
            "tenant_id": row.tenant_id,
            "protocol": row.protocol,
            "is_active": row.is_active,
            "issuer": row.issuer,
            "client_id": row.client_id,
            "scopes": row.scopes,
            "idp_entity_id": row.idp_entity_id,
            "idp_sso_url": row.idp_sso_url,
            "idp_x509_cert": row.idp_x509_cert,
            "sp_acs_url": row.sp_acs_url,
            "audience": row.audience,
            "client_secret_set": row.client_secret_enc is not None,
            "sp_private_key_set": row.sp_private_key_enc is not None,
            "created_at": row.created_at,
            "updated_at": row.updated_at,
        }
