"""F-033 real tokenize/detokenize drill — no mocks on the DB path.

Requires DATABASE_URL / APP_DATABASE_URL (skips at collection if absent).
"""

from __future__ import annotations

import base64
import os
import uuid

import pytest

from persistence.database import get_privileged_session
from persistence.repositories.tenant_repository import TenantRepository
from tokenization.crypto import reset_key_cache_for_testing
from tokenization.exceptions import TokenNotFoundError
from tokenization.formats import luhn_valid
from tokenization.service import detokenize, tokenize

if not os.environ.get("DATABASE_URL") or not os.environ.get("APP_DATABASE_URL"):
    pytest.skip("DATABASE_URL/APP_DATABASE_URL not set", allow_module_level=True)


@pytest.fixture(autouse=True)
def _vault_key(monkeypatch):
    monkeypatch.setenv("SENTINEL_TOKEN_VAULT_KEY", base64.b64encode(os.urandom(32)).decode())
    reset_key_cache_for_testing()
    yield
    reset_key_cache_for_testing()


async def _new_tenant() -> str:
    async with get_privileged_session() as ps, ps.begin():
        row = await TenantRepository(ps).create(name=f"tok-test-{uuid.uuid4().hex[:12]}")
        return row.tenant_id


@pytest.mark.asyncio
async def test_tokenize_detokenize_round_trip_card():
    tenant = await _new_tenant()
    original = "4111111111111111"
    token = await tokenize(tenant, original, token_type="card")
    # format preserved (16 digits, Luhn-valid) and NOT the original
    assert len(token) == 16 and token.isdigit() and luhn_valid(token)
    assert token != original
    assert await detokenize(tenant, token) == original


@pytest.mark.asyncio
async def test_tokenize_generic_round_trip():
    tenant = await _new_tenant()
    token = await tokenize(tenant, "some-secret-value", token_type="generic")
    assert token.startswith("tok_")
    assert await detokenize(tenant, token) == "some-secret-value"


@pytest.mark.asyncio
async def test_detokenize_unknown_token_raises():
    tenant = await _new_tenant()
    with pytest.raises(TokenNotFoundError):
        await detokenize(tenant, "tok_deadbeef")


@pytest.mark.asyncio
async def test_cross_tenant_detokenize_isolated():
    tenant_a = await _new_tenant()
    tenant_b = await _new_tenant()
    token = await tokenize(tenant_a, "a-secret", token_type="generic")
    # tenant B cannot reverse tenant A's token (RLS)
    with pytest.raises(TokenNotFoundError):
        await detokenize(tenant_b, token)


@pytest.mark.asyncio
async def test_two_tokenizations_same_value_differ_but_both_reverse():
    tenant = await _new_tenant()
    t1 = await tokenize(tenant, "555-66-7777", token_type="ssn")
    t2 = await tokenize(tenant, "555-66-7777", token_type="ssn")
    assert t1 != t2  # random surrogate
    assert await detokenize(tenant, t1) == "555-66-7777"
    assert await detokenize(tenant, t2) == "555-66-7777"
