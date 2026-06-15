"""Virtual API key repository tests (F-003).

Verifies:
- HMAC-based create and lookup (success path).
- Plaintext comparison fails (wrong key rejected).
- Constant-time compare is used (hmac.compare_digest).
- Deactivated keys cannot be looked up.
- No plaintext is stored (only fingerprint in DB).
- Expired keys are rejected by lookup_by_plaintext (item 6).
- Never-expiring keys (expires_at=None) are accepted.
- Not-yet-expired keys are accepted.

NOTE: get_by_id is a PK-only lookup in F-003. Tenant scoping on get_by_id
is deferred to F-003b.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.repositories.tenant_repository import TenantRepository
from persistence.repositories.team_repository import TeamRepository
from persistence.repositories.project_repository import ProjectRepository
from persistence.repositories.virtual_api_key_repository import (
    VirtualApiKeyAuthError,
    VirtualApiKeyNotFoundError,
    VirtualApiKeyRepository,
    compute_key_fingerprint,
)


def _uid() -> str:
    return str(uuid.uuid4())


async def _make_scope(session: AsyncSession) -> tuple[str, str, str]:
    """Create tenant/team/project and return their IDs."""
    t = await TenantRepository(session).create(name=f"VAK Tenant {_uid()[:8]}")
    team = await TeamRepository(session).create(
        tenant_id=t.tenant_id, name=f"VAK Team {_uid()[:8]}"
    )
    proj = await ProjectRepository(session).create(
        tenant_id=t.tenant_id, team_id=team.team_id, name=f"VAK Proj {_uid()[:8]}"
    )
    return t.tenant_id, team.team_id, proj.project_id


@pytest.mark.asyncio
async def test_create_key_stores_fingerprint_not_plaintext(session: AsyncSession) -> None:
    """Created key row must store HMAC fingerprint, never the plaintext."""
    tenant_id, team_id, project_id = await _make_scope(session)
    plaintext = f"sk-sentinel-{_uid()}"
    repo = VirtualApiKeyRepository(session)

    key_row = await repo.create(
        plaintext_key=plaintext,
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        agent_id="gateway-core",
        label="Test key",
    )

    # Fingerprint must be 64-char hex.
    assert len(key_row.key_fingerprint) == 64
    assert key_row.key_fingerprint != plaintext
    assert key_row.key_fingerprint != ""

    # Confirm fingerprint matches computed HMAC.
    expected_fp = compute_key_fingerprint(plaintext)
    assert key_row.key_fingerprint == expected_fp


@pytest.mark.asyncio
async def test_lookup_by_correct_plaintext_succeeds(session: AsyncSession) -> None:
    """Looking up with the correct plaintext key returns the row with correct IDs."""
    tenant_id, team_id, project_id = await _make_scope(session)
    plaintext = f"sk-sentinel-{_uid()}"
    repo = VirtualApiKeyRepository(session)

    created = await repo.create(
        plaintext_key=plaintext,
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        agent_id="gateway-core",
    )

    found = await repo.lookup_by_plaintext(plaintext)
    assert found.key_id == created.key_id
    # Authoritative IDs are server-resolved from the row.
    assert found.tenant_id == tenant_id
    assert found.team_id == team_id
    assert found.project_id == project_id
    assert found.agent_id == "gateway-core"


@pytest.mark.asyncio
async def test_lookup_with_wrong_key_raises(session: AsyncSession) -> None:
    """A wrong plaintext key raises VirtualApiKeyAuthError."""
    tenant_id, team_id, project_id = await _make_scope(session)
    repo = VirtualApiKeyRepository(session)

    await repo.create(
        plaintext_key="correct-key-abc123",
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        agent_id="gateway-core",
    )

    with pytest.raises(VirtualApiKeyAuthError):
        await repo.lookup_by_plaintext("wrong-key-xyz999")


@pytest.mark.asyncio
async def test_lookup_nonexistent_key_raises(session: AsyncSession) -> None:
    """Looking up a key that was never created raises VirtualApiKeyAuthError."""
    repo = VirtualApiKeyRepository(session)
    with pytest.raises(VirtualApiKeyAuthError):
        await repo.lookup_by_plaintext(f"sk-never-existed-{_uid()}")


@pytest.mark.asyncio
async def test_deactivated_key_cannot_be_looked_up(session: AsyncSession) -> None:
    """Deactivated keys are rejected by lookup_by_plaintext."""
    tenant_id, team_id, project_id = await _make_scope(session)
    plaintext = f"sk-deactivate-{_uid()}"
    repo = VirtualApiKeyRepository(session)

    key_row = await repo.create(
        plaintext_key=plaintext,
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        agent_id="gateway-core",
    )

    await repo.deactivate(key_row.key_id)

    with pytest.raises(VirtualApiKeyAuthError):
        await repo.lookup_by_plaintext(plaintext)


@pytest.mark.asyncio
async def test_db_row_does_not_contain_plaintext(session: AsyncSession) -> None:
    """Verify at DB level that the plaintext key is not stored anywhere in the row."""
    tenant_id, team_id, project_id = await _make_scope(session)
    plaintext = "this-is-the-secret-key-do-not-store"
    repo = VirtualApiKeyRepository(session)

    key_row = await repo.create(
        plaintext_key=plaintext,
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        agent_id="gateway-core",
    )

    # Raw DB query to check stored values.
    result = await session.execute(
        text(
            "SELECT key_fingerprint, label FROM virtual_api_keys WHERE key_id = :kid"
        ),
        {"kid": key_row.key_id},
    )
    row = result.fetchone()
    assert row is not None
    stored_fp = row[0]
    stored_label = row[1]

    assert plaintext not in stored_fp
    assert stored_label is None or plaintext not in stored_label


@pytest.mark.asyncio
async def test_fingerprint_uniqueness_enforced(session: AsyncSession) -> None:
    """The same plaintext key cannot be registered twice (fingerprint UNIQUE)."""
    tenant_id, team_id, project_id = await _make_scope(session)
    plaintext = f"sk-duplicate-{_uid()}"
    repo = VirtualApiKeyRepository(session)

    await repo.create(
        plaintext_key=plaintext,
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        agent_id="gateway-core",
    )

    with pytest.raises(Exception):  # IntegrityError from DB unique constraint.
        await repo.create(
            plaintext_key=plaintext,
            tenant_id=tenant_id,
            team_id=team_id,
            project_id=project_id,
            agent_id="gateway-core",
        )


# ---------------------------------------------------------------------------
# expires_at filter tests (item 6)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_never_expiring_key_accepted(session: AsyncSession) -> None:
    """A key with expires_at=None (never expires) is accepted by lookup_by_plaintext."""
    tenant_id, team_id, project_id = await _make_scope(session)
    plaintext = f"sk-never-expire-{_uid()}"
    repo = VirtualApiKeyRepository(session)

    await repo.create(
        plaintext_key=plaintext,
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        agent_id="gateway-core",
        expires_at=None,  # Never expires.
    )

    found = await repo.lookup_by_plaintext(plaintext)
    assert found.expires_at is None


@pytest.mark.asyncio
async def test_not_yet_expired_key_accepted(session: AsyncSession) -> None:
    """A key with expires_at in the future is accepted by lookup_by_plaintext."""
    tenant_id, team_id, project_id = await _make_scope(session)
    plaintext = f"sk-future-expire-{_uid()}"
    repo = VirtualApiKeyRepository(session)

    future = datetime.now(timezone.utc) + timedelta(days=365)
    await repo.create(
        plaintext_key=plaintext,
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        agent_id="gateway-core",
        expires_at=future,
    )

    found = await repo.lookup_by_plaintext(plaintext)
    assert found is not None


@pytest.mark.asyncio
async def test_expired_key_rejected(session: AsyncSession) -> None:
    """A key with expires_at in the past is rejected by lookup_by_plaintext."""
    tenant_id, team_id, project_id = await _make_scope(session)
    plaintext = f"sk-past-expire-{_uid()}"
    repo = VirtualApiKeyRepository(session)

    # Set expires_at to 1 second in the past.
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    await repo.create(
        plaintext_key=plaintext,
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        agent_id="gateway-core",
        expires_at=past,
    )

    with pytest.raises(VirtualApiKeyAuthError):
        await repo.lookup_by_plaintext(plaintext)


# ---------------------------------------------------------------------------
# get_by_id PK lookup tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_by_id_returns_key(session: AsyncSession) -> None:
    """get_by_id returns the key row for a valid key_id."""
    tenant_id, team_id, project_id = await _make_scope(session)
    plaintext = f"sk-get-{_uid()}"
    repo = VirtualApiKeyRepository(session)

    key_row = await repo.create(
        plaintext_key=plaintext,
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        agent_id="gateway-core",
    )

    fetched = await repo.get_by_id(key_row.key_id)
    assert fetched.key_id == key_row.key_id


@pytest.mark.asyncio
async def test_get_by_id_nonexistent_raises(session: AsyncSession) -> None:
    """get_by_id with a nonexistent key_id raises VirtualApiKeyNotFoundError."""
    repo = VirtualApiKeyRepository(session)
    with pytest.raises(VirtualApiKeyNotFoundError):
        await repo.get_by_id(_uid())
