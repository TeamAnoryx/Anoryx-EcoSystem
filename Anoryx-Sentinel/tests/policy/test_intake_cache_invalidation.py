"""F-023 (ADR-0029): an accepted model-decision policy write must invalidate the
eval_cache for its tenant; a budget write (never cached) must not bother to."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from policy import crypto
from policy.intake import intake_policy
from policy.results import Accepted


@pytest.mark.asyncio
async def test_allowlist_accept_invalidates_tenant_cache(
    priv_session, signing_keypair, make_allowlist_record, seeded_tenant
) -> None:
    record = crypto.sign_policy_record(
        make_allowlist_record(tenant_id=seeded_tenant), signing_keypair
    )
    with patch("policy.intake.eval_cache.invalidate_tenant", new=AsyncMock()) as inv:
        result = await intake_policy(record, session=priv_session)
    assert isinstance(result, Accepted)
    inv.assert_awaited_once_with(seeded_tenant)


@pytest.mark.asyncio
async def test_denylist_accept_invalidates_tenant_cache(
    priv_session, signing_keypair, make_denylist_record, seeded_tenant
) -> None:
    record = crypto.sign_policy_record(
        make_denylist_record(tenant_id=seeded_tenant), signing_keypair
    )
    with patch("policy.intake.eval_cache.invalidate_tenant", new=AsyncMock()) as inv:
        result = await intake_policy(record, session=priv_session)
    assert isinstance(result, Accepted)
    inv.assert_awaited_once_with(seeded_tenant)


@pytest.mark.asyncio
async def test_budget_accept_does_not_invalidate_cache(
    priv_session, signing_keypair, make_budget_record, seeded_tenant
) -> None:
    record = crypto.sign_policy_record(make_budget_record(tenant_id=seeded_tenant), signing_keypair)
    with patch("policy.intake.eval_cache.invalidate_tenant", new=AsyncMock()) as inv:
        result = await intake_policy(record, session=priv_session)
    assert isinstance(result, Accepted)
    inv.assert_not_awaited()
