"""Pure Pydantic validation tests for D-013 CRM schemas — no DB, no I/O."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from delta.crm.schemas import (
    MAX_DEAL_VALUE_MINOR_UNITS,
    ClientCreateRequest,
    DealCreateRequest,
    DealStageTransitionRequest,
    InteractionCreateRequest,
    StakeholderCreateRequest,
)

_TENANT = "11111111-1111-4111-8111-111111111111"
_DEAL = "22222222-2222-4222-8222-222222222222"
_AWARE_NOW = datetime(2026, 7, 8, 12, 0, 0, tzinfo=timezone.utc)


def test_client_create_accepts_minimal_valid_request() -> None:
    req = ClientCreateRequest(tenant_id=_TENANT, name="Acme Corp")
    assert req.name == "Acme Corp"
    assert req.primary_contact_email is None


def test_client_create_rejects_control_chars_in_name() -> None:
    with pytest.raises(ValidationError):
        ClientCreateRequest(tenant_id=_TENANT, name="Acme\nCorp")


def test_client_create_rejects_malformed_email() -> None:
    with pytest.raises(ValidationError):
        ClientCreateRequest(tenant_id=_TENANT, name="Acme", primary_contact_email="not-an-email")


def test_client_create_accepts_well_formed_email() -> None:
    req = ClientCreateRequest(
        tenant_id=_TENANT, name="Acme", primary_contact_email="ops@acme.example"
    )
    assert req.primary_contact_email == "ops@acme.example"


def test_client_create_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        ClientCreateRequest(tenant_id=_TENANT, name="Acme", unexpected="field")


def test_deal_create_rejects_negative_value() -> None:
    with pytest.raises(ValidationError):
        DealCreateRequest(tenant_id=_TENANT, name="Big Deal", value_minor_units=-1)


def test_deal_create_rejects_value_above_max() -> None:
    with pytest.raises(ValidationError):
        DealCreateRequest(
            tenant_id=_TENANT, name="Big Deal", value_minor_units=MAX_DEAL_VALUE_MINOR_UNITS + 1
        )


def test_deal_create_accepts_value_at_max() -> None:
    req = DealCreateRequest(
        tenant_id=_TENANT, name="Big Deal", value_minor_units=MAX_DEAL_VALUE_MINOR_UNITS
    )
    assert req.value_minor_units == MAX_DEAL_VALUE_MINOR_UNITS


def test_deal_create_rejects_naive_expected_close_date() -> None:
    with pytest.raises(ValidationError):
        DealCreateRequest(
            tenant_id=_TENANT,
            name="Big Deal",
            expected_close_date=datetime(2026, 12, 1),  # naive
        )


def test_deal_create_accepts_aware_expected_close_date() -> None:
    req = DealCreateRequest(tenant_id=_TENANT, name="Big Deal", expected_close_date=_AWARE_NOW)
    assert req.expected_close_date == _AWARE_NOW


def test_deal_stage_transition_rejects_control_chars_in_actor() -> None:
    with pytest.raises(ValidationError):
        DealStageTransitionRequest(tenant_id=_TENANT, stage="won", actor="Jane\rDoe")


def test_deal_stage_transition_rejects_unknown_stage() -> None:
    with pytest.raises(ValidationError):
        DealStageTransitionRequest(tenant_id=_TENANT, stage="unknown-stage", actor="Jane Doe")


def test_interaction_create_rejects_naive_occurred_at() -> None:
    with pytest.raises(ValidationError):
        InteractionCreateRequest(
            tenant_id=_TENANT,
            interaction_type="call",
            occurred_at=datetime(2026, 7, 8, 12, 0, 0),  # naive
            summary="Quick call",
            created_by="Jane Doe",
        )


def test_interaction_create_rejects_control_chars_in_summary() -> None:
    with pytest.raises(ValidationError):
        InteractionCreateRequest(
            tenant_id=_TENANT,
            interaction_type="note",
            occurred_at=_AWARE_NOW,
            summary="line1\x00line2",
            created_by="Jane Doe",
        )


def test_interaction_create_accepts_optional_deal_and_stakeholder() -> None:
    req = InteractionCreateRequest(
        tenant_id=_TENANT,
        deal_id=_DEAL,
        interaction_type="meeting",
        occurred_at=_AWARE_NOW,
        summary="Kickoff meeting",
        created_by="Jane Doe",
    )
    assert req.deal_id == _DEAL
    assert req.stakeholder_id is None


def test_stakeholder_create_defaults_role_unknown() -> None:
    req = StakeholderCreateRequest(tenant_id=_TENANT, name="Bob Smith")
    assert req.role == "unknown"


def test_stakeholder_create_rejects_malformed_email() -> None:
    with pytest.raises(ValidationError):
        StakeholderCreateRequest(tenant_id=_TENANT, name="Bob Smith", email="nope")


def test_stakeholder_create_rejects_unknown_role() -> None:
    with pytest.raises(ValidationError):
        StakeholderCreateRequest(tenant_id=_TENANT, name="Bob Smith", role="ceo")
