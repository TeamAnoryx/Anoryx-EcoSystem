"""Unit tests for the per-tenant principal gate (O-006, ADR-0006). No DB.

Exercises require_tenant_principal directly with the query_service_tokens lookup mocked, so
the whole gate (header parsing → hash → resolve → uniform-401) is covered without Postgres.
Proves: missing / malformed / empty / unknown / disabled tokens all raise PrincipalAuthError
(the app renders a uniform 401 — no enumeration oracle); a valid token returns its tenant_id;
and the value passed to the resolver is the SHA-256 hex of the presented secret (plaintext is
never used for the lookup).
"""

from __future__ import annotations

import contextlib
import hashlib

import pytest

from orchestrator import security
from orchestrator.security import PrincipalAuthError, require_tenant_principal


@contextlib.asynccontextmanager
async def _fake_privileged_session():
    """A fake privileged session CM — never opens a real connection (the resolver is mocked)."""
    yield object()


def _mock_resolver(monkeypatch, *, returns=None, capture=None):
    """Patch security.get_privileged_session + resolve_principal_tenant so no DB is touched."""

    async def _resolve(_session, token_sha256):
        if capture is not None:
            capture["hash"] = token_sha256
        return returns

    monkeypatch.setattr(security, "get_privileged_session", _fake_privileged_session)
    monkeypatch.setattr(security, "resolve_principal_tenant", _resolve)


async def test_missing_header_raises(monkeypatch):
    _mock_resolver(monkeypatch, returns="tenant-A")  # would resolve, but header is absent
    with pytest.raises(PrincipalAuthError):
        await require_tenant_principal(authorization=None)


async def test_non_bearer_header_raises(monkeypatch):
    _mock_resolver(monkeypatch, returns="tenant-A")
    with pytest.raises(PrincipalAuthError):
        await require_tenant_principal(authorization="Basic abc123")


async def test_empty_bearer_raises(monkeypatch):
    _mock_resolver(monkeypatch, returns="tenant-A")
    with pytest.raises(PrincipalAuthError):
        await require_tenant_principal(authorization="Bearer ")


async def test_unknown_token_raises(monkeypatch):
    # A present, well-formed token that the store does not know → resolver returns None → 401.
    _mock_resolver(monkeypatch, returns=None)
    with pytest.raises(PrincipalAuthError):
        await require_tenant_principal(authorization="Bearer totally-unknown-token")


async def test_disabled_token_raises(monkeypatch):
    # A disabled token is filtered out by the `AND enabled` predicate → resolver returns None →
    # 401, indistinguishable from unknown (no enumeration oracle).
    _mock_resolver(monkeypatch, returns=None)
    with pytest.raises(PrincipalAuthError):
        await require_tenant_principal(authorization="Bearer a-disabled-token")


async def test_valid_token_returns_tenant(monkeypatch):
    _mock_resolver(monkeypatch, returns="tenant-A")
    tenant = await require_tenant_principal(authorization="Bearer good-token")
    assert tenant == "tenant-A"


async def test_lookup_uses_sha256_of_presented_secret(monkeypatch):
    capture: dict[str, str] = {}
    _mock_resolver(monkeypatch, returns="tenant-A", capture=capture)
    await require_tenant_principal(authorization="Bearer secret-value")
    assert capture["hash"] == hashlib.sha256(b"secret-value").hexdigest()
    # The plaintext must never be the lookup key.
    assert capture["hash"] != "secret-value"
