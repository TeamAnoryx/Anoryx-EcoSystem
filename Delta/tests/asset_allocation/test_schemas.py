"""D-023 pure schema-validation unit tests (no DB, no I/O)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from delta.asset_allocation.schemas import (
    RISK_TIER_TARGET_ALLOCATION_PCT,
    AllocationRecommendationRequest,
)

_TENANT = "11111111-1111-4111-8111-111111111111"
_ACCOUNT = "22222222-2222-4222-8222-222222222222"


def _now() -> datetime:
    return datetime.now(timezone.utc)


@pytest.mark.parametrize("risk_tier", ["conservative", "moderate", "aggressive"])
def test_every_risk_tier_allocation_sums_to_100(risk_tier: str) -> None:
    pcts = RISK_TIER_TARGET_ALLOCATION_PCT[risk_tier]
    assert sum(pcts.values()) == 100


def test_risk_tier_allocations_are_all_nonnegative() -> None:
    for pcts in RISK_TIER_TARGET_ALLOCATION_PCT.values():
        assert all(v >= 0 for v in pcts.values())


def test_valid_request_accepted() -> None:
    req = AllocationRecommendationRequest(
        tenant_id=_TENANT,
        account_id=_ACCOUNT,
        risk_tier="moderate",
        period_start=_now() - timedelta(days=30),
        period_end=_now(),
    )
    assert req.risk_tier == "moderate"


def test_unknown_risk_tier_rejected() -> None:
    with pytest.raises(ValidationError):
        AllocationRecommendationRequest(
            tenant_id=_TENANT,
            account_id=_ACCOUNT,
            risk_tier="yolo",
            period_start=_now() - timedelta(days=30),
            period_end=_now(),
        )


def test_period_end_before_start_rejected() -> None:
    with pytest.raises(ValidationError):
        AllocationRecommendationRequest(
            tenant_id=_TENANT,
            account_id=_ACCOUNT,
            risk_tier="moderate",
            period_start=_now(),
            period_end=_now() - timedelta(days=30),
        )


def test_period_end_equal_start_rejected() -> None:
    same = _now()
    with pytest.raises(ValidationError):
        AllocationRecommendationRequest(
            tenant_id=_TENANT,
            account_id=_ACCOUNT,
            risk_tier="moderate",
            period_start=same,
            period_end=same,
        )


def test_naive_period_start_rejected() -> None:
    with pytest.raises(ValidationError):
        AllocationRecommendationRequest(
            tenant_id=_TENANT,
            account_id=_ACCOUNT,
            risk_tier="moderate",
            period_start=datetime(2026, 6, 1, 0, 0, 0),  # no tzinfo
            period_end=_now(),
        )


def test_request_extra_field_rejected() -> None:
    with pytest.raises(ValidationError):
        AllocationRecommendationRequest(
            tenant_id=_TENANT,
            account_id=_ACCOUNT,
            risk_tier="moderate",
            period_start=_now() - timedelta(days=30),
            period_end=_now(),
            unexpected="nope",
        )


def test_malformed_tenant_id_rejected() -> None:
    with pytest.raises(ValidationError):
        AllocationRecommendationRequest(
            tenant_id="not-a-uuid",
            account_id=_ACCOUNT,
            risk_tier="moderate",
            period_start=_now() - timedelta(days=30),
            period_end=_now(),
        )
