"""D-023 pure schema validation (no DB)."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from delta.investments.schemas import (
    ASSET_CLASSES,
    AllocationRecommendationQuery,
    HoldingRecordRequest,
)
from delta.investments.service import _TARGET_ALLOCATIONS

_TENANT = str(uuid.uuid4())
_ACCOUNT = str(uuid.uuid4())
_START = datetime(2026, 7, 1, tzinfo=timezone.utc)
_END = _START + timedelta(days=30)


def test_holding_record_request_accepts_valid_payload() -> None:
    req = HoldingRecordRequest(
        tenant_id=_TENANT,
        account_id=_ACCOUNT,
        asset_class="stocks",
        value_minor_units=100_000,
        currency="USD",
    )
    assert req.value_minor_units == 100_000


def test_holding_record_request_rejects_negative_value() -> None:
    with pytest.raises(ValidationError):
        HoldingRecordRequest(
            tenant_id=_TENANT,
            account_id=_ACCOUNT,
            asset_class="stocks",
            value_minor_units=-1,
            currency="USD",
        )


def test_holding_record_request_rejects_overflow_value() -> None:
    with pytest.raises(ValidationError):
        HoldingRecordRequest(
            tenant_id=_TENANT,
            account_id=_ACCOUNT,
            asset_class="stocks",
            value_minor_units=10**12,
            currency="USD",
        )


def test_holding_record_request_rejects_float_value() -> None:
    with pytest.raises(ValidationError):
        HoldingRecordRequest(
            tenant_id=_TENANT,
            account_id=_ACCOUNT,
            asset_class="stocks",
            value_minor_units=100.0,
            currency="USD",
        )


def test_holding_record_request_rejects_unknown_asset_class() -> None:
    with pytest.raises(ValidationError):
        HoldingRecordRequest(
            tenant_id=_TENANT,
            account_id=_ACCOUNT,
            asset_class="nfts",
            value_minor_units=100,
            currency="USD",
        )


def test_holding_record_request_rejects_unknown_field() -> None:
    with pytest.raises(ValidationError):
        HoldingRecordRequest(
            tenant_id=_TENANT,
            account_id=_ACCOUNT,
            asset_class="stocks",
            value_minor_units=100,
            currency="USD",
            unexpected="nope",
        )


def test_allocation_query_accepts_valid_window() -> None:
    query = AllocationRecommendationQuery(
        tenant_id=_TENANT, risk_profile="moderate", start=_START, end=_END
    )
    assert query.end > query.start


def test_allocation_query_rejects_end_before_start() -> None:
    with pytest.raises(ValidationError):
        AllocationRecommendationQuery(
            tenant_id=_TENANT, risk_profile="moderate", start=_END, end=_START
        )


def test_allocation_query_rejects_naive_start() -> None:
    with pytest.raises(ValidationError):
        AllocationRecommendationQuery(
            tenant_id=_TENANT, risk_profile="moderate", start=datetime(2026, 7, 1), end=_END
        )


def test_allocation_query_rejects_unknown_risk_profile() -> None:
    with pytest.raises(ValidationError):
        AllocationRecommendationQuery(
            tenant_id=_TENANT, risk_profile="yolo", start=_START, end=_END
        )


def test_target_allocations_sum_to_one() -> None:
    for profile, weights in _TARGET_ALLOCATIONS.items():
        assert set(weights) == set(ASSET_CLASSES)
        assert abs(sum(weights.values()) - 1.0) < 1e-9, profile


def test_target_allocations_cover_every_canonical_risk_profile() -> None:
    assert set(_TARGET_ALLOCATIONS) == {"conservative", "moderate", "aggressive"}
