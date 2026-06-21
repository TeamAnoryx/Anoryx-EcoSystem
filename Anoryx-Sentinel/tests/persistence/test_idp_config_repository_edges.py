"""IdpConfigRepository edge-branch coverage (F-014 STEP 3, additive).

Companion to test_idp_config_repository.py. That suite covers the main encrypt/
metadata/upsert paths; this file closes the remaining branches:

  * _validate_protocol rejects an unknown protocol (ValueError);
  * upsert rejects unknown keyword fields (TypeError);
  * upsert on an EXISTING row REPLACES both secret columns when new plaintexts are
    supplied (the update-branch *_enc assignments);
  * get_decrypted_secret rejects an unknown field, and returns None when the *_enc
    column is empty;
  * get_metadata returns None when no active config exists;
  * list_for_tenant enforces the caller_tenant_id guard.

Uses the privileged `session` fixture (BYPASSRLS / SAVEPOINT-isolated) to isolate
SQL behaviour, mirroring the existing repo tests. The AES key + any fake secret
material are assembled at runtime — never committed (R6). Skips when no DB.
"""

from __future__ import annotations

import base64
import os
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from admin.sso import secret_box
from persistence.repositories.idp_config_repository import IdpConfigRepository

pytestmark = pytest.mark.asyncio

_KEY_ENV = "SENTINEL_IDP_SECRET_KEY"


def _uid() -> str:
    return str(uuid.uuid4())


def _fresh_key_b64() -> str:
    return base64.b64encode(os.urandom(32)).decode("ascii")


def _fake_pem_material() -> str:
    """Assemble a PEM-shaped fake at runtime (no credential literal in source, R6)."""
    head = "-----BEGIN " + "PRIVATE KEY" + "-----"
    tail = "-----END " + "PRIVATE KEY" + "-----"
    return head + "\n" + base64.b64encode(os.urandom(48)).decode("ascii") + "\n" + tail


@pytest.fixture(autouse=True)
def _idp_key(monkeypatch):
    secret_box.reset_key_cache_for_testing()
    monkeypatch.setenv(_KEY_ENV, _fresh_key_b64())
    yield
    secret_box.reset_key_cache_for_testing()


async def _insert_tenant(session: AsyncSession, tenant_id: str) -> None:
    await session.execute(
        text(
            "INSERT INTO tenants (tenant_id, name, is_active) "
            "VALUES (:tid, :name, true) ON CONFLICT (tenant_id) DO NOTHING"
        ),
        {"tid": tenant_id, "name": "IdP edge tenant " + tenant_id[:8]},
    )


# --------------------------------------------------------------------------- #
# Input-validation branches (no DB write needed).
# --------------------------------------------------------------------------- #
async def test_upsert_invalid_protocol_raises(session: AsyncSession) -> None:
    """An unknown protocol raises ValueError before any DB mutation (line 60)."""
    repo = IdpConfigRepository(session)
    tid = _uid()
    with pytest.raises(ValueError, match="protocol must be one of"):
        await repo.upsert(tenant_id=tid, protocol="ldap", caller_tenant_id=tid)


async def test_upsert_unknown_field_raises(session: AsyncSession) -> None:
    """An unknown settable field raises TypeError (line 116)."""
    repo = IdpConfigRepository(session)
    tid = _uid()
    with pytest.raises(TypeError, match="unknown idp_config field"):
        await repo.upsert(
            tenant_id=tid,
            protocol="oidc",
            caller_tenant_id=tid,
            not_a_real_field="x",
        )


# --------------------------------------------------------------------------- #
# upsert UPDATE branch: a second upsert with NEW secrets replaces both *_enc cols.
# --------------------------------------------------------------------------- #
async def test_upsert_update_replaces_both_secrets(session: AsyncSession) -> None:
    """A second upsert supplying new client_secret AND sp_private_key updates both
    *_enc columns on the existing active row (lines 137-140)."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)
    repo = IdpConfigRepository(session)

    first = await repo.upsert(
        tenant_id=tenant_id,
        protocol="oidc",
        caller_tenant_id=tenant_id,
        client_secret_plaintext="cs-v1",
        client_id="cid-1",
    )
    await session.flush()

    new_pk = _fake_pem_material()
    second = await repo.upsert(
        tenant_id=tenant_id,
        protocol="oidc",
        caller_tenant_id=tenant_id,
        client_secret_plaintext="cs-v2",  # replaces client_secret_enc (line 138)
        sp_private_key_plaintext=new_pk,  # sets sp_private_key_enc (line 140)
        client_id="cid-2",
    )
    await session.flush()

    assert first.id == second.id  # same row updated in place
    # Both secrets now decrypt to the v2 values.
    cs = await repo.get_decrypted_secret(
        tenant_id=tenant_id, protocol="oidc", field="client_secret", caller_tenant_id=tenant_id
    )
    pk = await repo.get_decrypted_secret(
        tenant_id=tenant_id, protocol="oidc", field="sp_private_key", caller_tenant_id=tenant_id
    )
    assert cs == b"cs-v2"
    assert pk == new_pk.encode("utf-8")


# --------------------------------------------------------------------------- #
# get_decrypted_secret branches.
# --------------------------------------------------------------------------- #
async def test_get_decrypted_secret_invalid_field_raises(session: AsyncSession) -> None:
    """An unknown field name raises ValueError before any lookup (line 213)."""
    repo = IdpConfigRepository(session)
    tid = _uid()
    with pytest.raises(ValueError, match="field must be"):
        await repo.get_decrypted_secret(
            tenant_id=tid, protocol="oidc", field="totp_seed", caller_tenant_id=tid
        )


async def test_get_decrypted_secret_returns_none_when_unset(session: AsyncSession) -> None:
    """get_decrypted_secret returns None when the *_enc column is empty (line 221)."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)
    repo = IdpConfigRepository(session)
    # Config WITHOUT any client_secret set.
    await repo.upsert(
        tenant_id=tenant_id,
        protocol="oidc",
        caller_tenant_id=tenant_id,
        client_id="cid-no-secret",
    )
    await session.flush()

    secret = await repo.get_decrypted_secret(
        tenant_id=tenant_id, protocol="oidc", field="client_secret", caller_tenant_id=tenant_id
    )
    assert secret is None


# --------------------------------------------------------------------------- #
# get_metadata + list_for_tenant branches.
# --------------------------------------------------------------------------- #
async def test_get_metadata_returns_none_when_no_config(session: AsyncSession) -> None:
    """get_metadata returns None when the tenant has no active config (line 236)."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)
    repo = IdpConfigRepository(session)
    meta = await repo.get_metadata(tenant_id=tenant_id, protocol="oidc", caller_tenant_id=tenant_id)
    assert meta is None


async def test_list_for_tenant_tenant_mismatch_raises(session: AsyncSession) -> None:
    """list_for_tenant raises ValueError when caller_tenant_id != tenant_id (line 244)."""
    repo = IdpConfigRepository(session)
    with pytest.raises(ValueError, match="tenant mismatch"):
        await repo.list_for_tenant(tenant_id=_uid(), caller_tenant_id=_uid())
