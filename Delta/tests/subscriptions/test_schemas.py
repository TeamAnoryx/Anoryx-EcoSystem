"""D-022 pure schema-validation unit tests (no DB, no I/O)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from delta.subscriptions.schemas import (
    ChargeRecordRequest,
    SubscriptionAnomalyQuery,
    SubscriptionCreateRequest,
)

_TENANT = "11111111-1111-4111-8111-111111111111"


def test_expected_amount_rejects_float() -> None:
    with pytest.raises(ValidationError):
        SubscriptionCreateRequest(
            tenant_id=_TENANT,
            name="Notion",
            expected_amount_minor_units=999.0,
            cadence="monthly",
            created_by="Jane",
        )


def test_expected_amount_rejects_bool() -> None:
    with pytest.raises(ValidationError):
        SubscriptionCreateRequest(
            tenant_id=_TENANT,
            name="Notion",
            expected_amount_minor_units=True,
            cadence="monthly",
            created_by="Jane",
        )


def test_name_rejects_control_characters() -> None:
    with pytest.raises(ValidationError):
        SubscriptionCreateRequest(
            tenant_id=_TENANT, name="Notion\x00", cadence="monthly", created_by="Jane"
        )


def test_cadence_rejects_unknown_value() -> None:
    with pytest.raises(ValidationError):
        SubscriptionCreateRequest(
            tenant_id=_TENANT, name="Notion", cadence="biweekly", created_by="Jane"
        )


def test_subscription_create_extra_field_rejected() -> None:
    with pytest.raises(ValidationError):
        SubscriptionCreateRequest(
            tenant_id=_TENANT,
            name="Notion",
            cadence="monthly",
            created_by="Jane",
            unexpected="nope",
        )


def test_charge_amount_rejects_float() -> None:
    with pytest.raises(ValidationError):
        ChargeRecordRequest(
            tenant_id=_TENANT,
            amount_minor_units=999.99,
            charged_at=datetime.now(timezone.utc),
            recorded_by="Jane",
        )


def test_charge_amount_rejects_negative() -> None:
    with pytest.raises(ValidationError):
        ChargeRecordRequest(
            tenant_id=_TENANT,
            amount_minor_units=-1,
            charged_at=datetime.now(timezone.utc),
            recorded_by="Jane",
        )


def test_naive_charged_at_rejected() -> None:
    with pytest.raises(ValidationError):
        ChargeRecordRequest(
            tenant_id=_TENANT,
            amount_minor_units=1000,
            charged_at=datetime(2026, 7, 1, 12, 0, 0),  # no tzinfo
            recorded_by="Jane",
        )


def test_aware_charged_at_accepted() -> None:
    req = ChargeRecordRequest(
        tenant_id=_TENANT,
        amount_minor_units=1000,
        charged_at=datetime.now(timezone.utc),
        recorded_by="Jane",
    )
    assert req.amount_minor_units == 1000


def test_note_rejects_control_characters() -> None:
    with pytest.raises(ValidationError):
        ChargeRecordRequest(
            tenant_id=_TENANT,
            amount_minor_units=1000,
            charged_at=datetime.now(timezone.utc),
            recorded_by="Jane",
            note="line1\nline2",
        )


def test_baseline_window_out_of_range_rejected() -> None:
    with pytest.raises(ValidationError):
        SubscriptionAnomalyQuery(tenant_id=_TENANT, baseline_window=0)
    with pytest.raises(ValidationError):
        SubscriptionAnomalyQuery(tenant_id=_TENANT, baseline_window=25)


def test_baseline_window_default() -> None:
    query = SubscriptionAnomalyQuery(tenant_id=_TENANT)
    assert query.baseline_window == 6
