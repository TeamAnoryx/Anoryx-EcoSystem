"""Unit + RLS tests for IdpConfigRepository and IdpGroupRoleMapRepository (F-014 STEP 3).

Covers (ADR-0017 D3/D6, R6):
  - upsert ENCRYPTS the secrets (stored *_enc bytes != plaintext);
  - get_metadata NEVER contains the secret or ciphertext (client_secret_set true);
  - one active config per (tenant, protocol) (upsert updates in place);
  - get_decrypted_secret round-trips the secret at the use-site;
  - group_role_map set/list/resolve_role (highest wins; unmapped -> None fail-closed);
  - RLS cross-tenant isolation (tenant A cannot read tenant B's idp_config) —
    empirical, two committed tenants over a real sentinel_app connection (vector 3).

Repo-logic tests use the privileged `session` fixture (BYPASSRLS) so they isolate
SQL behaviour; the RLS proof uses committed rows + the tenant_session fixture.
The encryption key and any fake secret material are assembled at runtime — never
committed (R6 / push-protection lesson). Skips when no DB is configured.
"""

from __future__ import annotations

import base64
import os
import re
import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from admin.sso import secret_box
from persistence.models.sso_identity import IdpConfig
from persistence.repositories.idp_config_repository import (
    IdpConfigNotFoundError,
    IdpConfigRepository,
)
from persistence.repositories.idp_group_role_map_repository import (
    IdpGroupRoleMapRepository,
)

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
    """Set a runtime AES key and reset the load-once cache for every test."""
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
        {"tid": tenant_id, "name": "IdP test tenant " + tenant_id[:8]},
    )


# ---------------------------------------------------------------------------
# IdpConfigRepository — encryption-at-rest
# ---------------------------------------------------------------------------


async def test_upsert_encrypts_client_secret(session: AsyncSession) -> None:
    """The stored client_secret_enc is ciphertext bytes, never the plaintext."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)
    plaintext = "oidc-client-secret-xyz"

    repo = IdpConfigRepository(session)
    row = await repo.upsert(
        tenant_id=tenant_id,
        protocol="oidc",
        caller_tenant_id=tenant_id,
        client_secret_plaintext=plaintext,
        issuer="https://idp.example.com",
        client_id="client-123",
    )
    await session.flush()

    assert isinstance(row.client_secret_enc, (bytes, bytearray))
    assert bytes(row.client_secret_enc) != plaintext.encode("utf-8")
    # Reload from DB to confirm what is actually persisted is ciphertext.
    fetched = (await session.execute(select(IdpConfig).where(IdpConfig.id == row.id))).scalar_one()
    assert plaintext.encode("utf-8") not in bytes(fetched.client_secret_enc)
    # And it decrypts back at the use-site.
    secret = await repo.get_decrypted_secret(
        tenant_id=tenant_id, protocol="oidc", field="client_secret", caller_tenant_id=tenant_id
    )
    assert secret == plaintext.encode("utf-8")


async def test_metadata_never_contains_secret(session: AsyncSession) -> None:
    """get_metadata exposes client_secret_set=True but no secret/ciphertext (R6)."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)
    plaintext = "do-not-leak-me"

    repo = IdpConfigRepository(session)
    await repo.upsert(
        tenant_id=tenant_id,
        protocol="oidc",
        caller_tenant_id=tenant_id,
        client_secret_plaintext=plaintext,
        client_id="cid",
    )
    await session.flush()

    meta = await repo.get_metadata(tenant_id=tenant_id, protocol="oidc", caller_tenant_id=tenant_id)
    assert meta is not None
    assert meta["client_secret_set"] is True
    assert meta["sp_private_key_set"] is False
    # No secret-bearing column may appear in the metadata projection.
    assert "client_secret_enc" not in meta
    assert "sp_private_key_enc" not in meta
    assert "client_secret" not in meta
    # The plaintext must not appear anywhere in the serialized metadata.
    assert plaintext not in repr(meta)


async def test_one_active_config_per_protocol_updates_in_place(session: AsyncSession) -> None:
    """A second upsert for the same (tenant, protocol) updates the existing row."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)
    repo = IdpConfigRepository(session)

    first = await repo.upsert(
        tenant_id=tenant_id,
        protocol="oidc",
        caller_tenant_id=tenant_id,
        client_secret_plaintext="secret-v1",
        client_id="cid-1",
    )
    await session.flush()
    second = await repo.upsert(
        tenant_id=tenant_id,
        protocol="oidc",
        caller_tenant_id=tenant_id,
        client_id="cid-2",  # no new secret -> existing ciphertext retained
    )
    await session.flush()

    assert first.id == second.id  # same row updated in place
    rows = (
        (
            await session.execute(
                select(IdpConfig).where(
                    IdpConfig.tenant_id == tenant_id, IdpConfig.protocol == "oidc"
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(rows) == 1
    # Secret from v1 is still decryptable (not wiped by the metadata-only update).
    secret = await repo.get_decrypted_secret(
        tenant_id=tenant_id, protocol="oidc", field="client_secret", caller_tenant_id=tenant_id
    )
    assert secret == b"secret-v1"
    assert rows[0].client_id == "cid-2"


async def test_upsert_saml_private_key_encrypted(session: AsyncSession) -> None:
    """SAML sp_private_key is encrypted at rest and round-trips."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)
    pk = _fake_pem_material()

    repo = IdpConfigRepository(session)
    row = await repo.upsert(
        tenant_id=tenant_id,
        protocol="saml",
        caller_tenant_id=tenant_id,
        sp_private_key_plaintext=pk,
        idp_entity_id="https://idp.example.com/entity",
        sp_acs_url="https://sp.example.com/acs",
    )
    await session.flush()
    assert bytes(row.sp_private_key_enc) != pk.encode("utf-8")
    secret = await repo.get_decrypted_secret(
        tenant_id=tenant_id, protocol="saml", field="sp_private_key", caller_tenant_id=tenant_id
    )
    assert secret == pk.encode("utf-8")


async def test_tenant_mismatch_guard_raises(session: AsyncSession) -> None:
    """caller_tenant_id != tenant_id raises before any write (defense-in-depth)."""
    repo = IdpConfigRepository(session)
    with pytest.raises(ValueError):
        await repo.upsert(
            tenant_id=_uid(),
            protocol="oidc",
            caller_tenant_id=_uid(),
            client_secret_plaintext="x",
        )


async def test_get_active_not_found_raises(session: AsyncSession) -> None:
    """get_active raises IdpConfigNotFoundError when no active config exists."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)
    with pytest.raises(IdpConfigNotFoundError):
        await IdpConfigRepository(session).get_active(
            tenant_id=tenant_id, protocol="oidc", caller_tenant_id=tenant_id
        )


# ---------------------------------------------------------------------------
# IdpGroupRoleMapRepository
# ---------------------------------------------------------------------------


async def test_group_role_set_and_list(session: AsyncSession) -> None:
    """set_mapping then list_for_tenant returns the mapping."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)
    repo = IdpGroupRoleMapRepository(session)
    await repo.set_mapping(
        tenant_id=tenant_id, idp_group="admins", role="tenant_admin", caller_tenant_id=tenant_id
    )
    await session.flush()

    mappings = await repo.list_for_tenant(tenant_id=tenant_id, caller_tenant_id=tenant_id)
    assert len(mappings) == 1
    assert mappings[0]["idp_group"] == "admins"
    assert mappings[0]["role"] == "tenant_admin"


async def test_group_role_set_upsert_updates_role(session: AsyncSession) -> None:
    """A second set_mapping for the same group updates the role (one row per group)."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)
    repo = IdpGroupRoleMapRepository(session)
    await repo.set_mapping(
        tenant_id=tenant_id, idp_group="g1", role="tenant_auditor", caller_tenant_id=tenant_id
    )
    await session.flush()
    await repo.set_mapping(
        tenant_id=tenant_id, idp_group="g1", role="tenant_admin", caller_tenant_id=tenant_id
    )
    await session.flush()

    mappings = await repo.list_for_tenant(tenant_id=tenant_id, caller_tenant_id=tenant_id)
    assert len(mappings) == 1
    assert mappings[0]["role"] == "tenant_admin"


async def test_resolve_role_returns_highest(session: AsyncSession) -> None:
    """resolve_role returns tenant_admin when the subject is in both roles' groups."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)
    repo = IdpGroupRoleMapRepository(session)
    await repo.set_mapping(
        tenant_id=tenant_id, idp_group="auditors", role="tenant_auditor", caller_tenant_id=tenant_id
    )
    await repo.set_mapping(
        tenant_id=tenant_id, idp_group="admins", role="tenant_admin", caller_tenant_id=tenant_id
    )
    await session.flush()

    role = await repo.resolve_role(
        tenant_id=tenant_id, groups=["auditors", "admins"], caller_tenant_id=tenant_id
    )
    assert role == "tenant_admin"  # highest wins


async def test_resolve_role_unmapped_returns_none(session: AsyncSession) -> None:
    """A group with no mapping resolves to None (fail-closed, D6 / vector 14)."""
    tenant_id = _uid()
    await _insert_tenant(session, tenant_id)
    repo = IdpGroupRoleMapRepository(session)
    await repo.set_mapping(
        tenant_id=tenant_id, idp_group="admins", role="tenant_admin", caller_tenant_id=tenant_id
    )
    await session.flush()

    assert (
        await repo.resolve_role(
            tenant_id=tenant_id, groups=["unknown-group"], caller_tenant_id=tenant_id
        )
        is None
    )
    # Empty group list also fail-closes.
    assert (
        await repo.resolve_role(tenant_id=tenant_id, groups=[], caller_tenant_id=tenant_id) is None
    )


async def test_group_role_invalid_role_raises(session: AsyncSession) -> None:
    """An unknown role raises ValueError before any DB write."""
    repo = IdpGroupRoleMapRepository(session)
    with pytest.raises(ValueError):
        await repo.set_mapping(
            tenant_id=_uid(), idp_group="g", role="superuser", caller_tenant_id=_uid()
        )


# ---------------------------------------------------------------------------
# RLS cross-tenant isolation (vector 3) — empirical, two committed tenants.
# ---------------------------------------------------------------------------


def _make_async_url(raw: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    return re.sub(r"^postgresql://", "postgresql+asyncpg://", url)


async def _commit_idp_config(priv_url: str, tenant_id: str) -> str:
    """Insert + COMMIT a tenant and an idp_config row via a privileged connection."""
    engine = create_async_engine(
        priv_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )
    factory = async_sessionmaker(
        bind=engine, expire_on_commit=False, autoflush=False, autocommit=False
    )
    cfg_id = str(uuid.uuid4())
    async with factory() as sess:
        async with sess.begin():
            await sess.execute(
                text(
                    "INSERT INTO tenants (tenant_id, name, is_active) "
                    "VALUES (:t, :n, true) ON CONFLICT (tenant_id) DO NOTHING"
                ),
                {"t": tenant_id, "n": "rls-idp " + tenant_id[:8]},
            )
            await sess.execute(
                text(
                    "INSERT INTO idp_config (id, tenant_id, protocol, is_active, client_id) "
                    "VALUES (:id, :t, 'oidc', true, 'cid')"
                ),
                {"id": cfg_id, "t": tenant_id},
            )
    await engine.dispose()
    return cfg_id


async def _delete_tenant_and_config(priv_url: str, tenant_id: str) -> None:
    engine = create_async_engine(
        priv_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )
    factory = async_sessionmaker(
        bind=engine, expire_on_commit=False, autoflush=False, autocommit=False
    )
    async with factory() as sess:
        async with sess.begin():
            await sess.execute(
                text("DELETE FROM idp_config WHERE tenant_id = :t"), {"t": tenant_id}
            )
            await sess.execute(text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": tenant_id})
    await engine.dispose()


@pytest.fixture
def tenant_a_id() -> str:
    return _uid()


@pytest.fixture
def tenant_b_id() -> str:
    return _uid()


@pytest.fixture
def test_tenant_id(tenant_a_id: str) -> str:
    """Route the conftest tenant_session fixture to tenant A."""
    return tenant_a_id


async def test_idp_config_rls_cross_tenant_invisible(
    tenant_session: AsyncSession,
    tenant_a_id: str,
    tenant_b_id: str,
) -> None:
    """Tenant A's RLS-scoped session CANNOT see tenant B's idp_config (vector 3)."""
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        pytest.skip("DATABASE_URL not set")
    priv_url = _make_async_url(raw)

    cfg_b = await _commit_idp_config(priv_url, tenant_b_id)
    cfg_a = await _commit_idp_config(priv_url, tenant_a_id)
    try:
        result = await tenant_session.execute(
            text("SELECT id FROM idp_config WHERE id = :a OR id = :b"),
            {"a": cfg_a, "b": cfg_b},
        )
        visible = {r[0] for r in result.fetchall()}
        assert cfg_a in visible, "Tenant A could not read its own idp_config (RLS too strict)."
        assert cfg_b not in visible, (
            "Tenant A saw tenant B's idp_config — RLS isolation FAILED on idp_config. "
            f"visible={visible!r}"
        )
    finally:
        await _delete_tenant_and_config(priv_url, tenant_a_id)
        await _delete_tenant_and_config(priv_url, tenant_b_id)
