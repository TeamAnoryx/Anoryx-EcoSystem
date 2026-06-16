"""Tests for audit / terminal-emit logic (F-004, ADR-0006 Decision 3).

Covers:
- build_usage_event produces all 12 required fields
- build_usage_event uses server-resolved IDs (not headers)
- build_usage_event with no tenant_context uses safe sentinel values
- latency_ms clamped to [0, 3_600_000]
- tokens_in/tokens_out clamped to [0, 10_000_000]
- emit_terminal_record calls AuditLogRepository.append
- emit_terminal_record with failed append → raises GatewayError("internal_error")
- Usage event validates against events.schema.json (contract test)
"""

from __future__ import annotations

import json
import time
import uuid
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gateway.context import TenantContext
from gateway.exceptions import GatewayError
from gateway.middleware.audit import build_usage_event, emit_terminal_record
from tests.gateway.conftest import (
    TEST_AGENT_ID,
    TEST_KEY_ID,
    TEST_PROJECT_ID,
    TEST_TEAM_ID,
    TEST_TENANT_ID,
)

_TENANT_CTX = TenantContext(
    tenant_id=TEST_TENANT_ID,
    team_id=TEST_TEAM_ID,
    project_id=TEST_PROJECT_ID,
    agent_id=TEST_AGENT_ID,
    virtual_key_id=TEST_KEY_ID,
)


# ---------------------------------------------------------------------------
# build_usage_event unit tests
# ---------------------------------------------------------------------------


def test_build_usage_event_has_all_12_fields():
    """Usage event must have exactly the 12 required fields from events.schema.json."""
    required_fields = {
        "event_type",
        "tenant_id",
        "team_id",
        "project_id",
        "agent_id",
        "event_id",
        "event_timestamp",
        "request_id",
        "model",
        "tokens_in",
        "tokens_out",
        "latency_ms",
        "cost_estimate_cents",
    }
    event = build_usage_event(
        request_id="req-test-001",
        tenant_context=_TENANT_CTX,
        model="gpt-3.5-turbo",
        tokens_in=100,
        tokens_out=50,
        start_time=time.monotonic(),
    )
    for field in required_fields:
        assert field in event, f"Missing required field: {field}"


def test_build_usage_event_uses_server_resolved_ids():
    """Server-resolved IDs from TenantContext must appear in the event — not raw headers."""
    event = build_usage_event(
        request_id="req-resolved",
        tenant_context=_TENANT_CTX,
        model="gpt-3.5-turbo",
        tokens_in=0,
        tokens_out=0,
        start_time=time.monotonic(),
    )
    assert event["tenant_id"] == TEST_TENANT_ID
    assert event["team_id"] == TEST_TEAM_ID
    assert event["project_id"] == TEST_PROJECT_ID
    assert event["agent_id"] == TEST_AGENT_ID


def test_build_usage_event_event_type_is_usage():
    event = build_usage_event(
        request_id="req-type",
        tenant_context=_TENANT_CTX,
        model="gpt-3.5-turbo",
        tokens_in=0,
        tokens_out=0,
        start_time=time.monotonic(),
    )
    assert event["event_type"] == "usage"


def test_build_usage_event_without_tenant_context_uses_sentinel_values():
    """Pre-auth rejection: no context yet → safe sentinel values, event still appended."""
    event = build_usage_event(
        request_id="req-preauth",
        tenant_context=None,
        model="gpt-3.5-turbo",
        tokens_in=0,
        tokens_out=0,
        start_time=time.monotonic(),
    )
    assert event["tenant_id"] == "00000000-0000-0000-0000-000000000000"
    assert event["tokens_in"] == 0
    assert event["tokens_out"] == 0
    assert event["event_type"] == "usage"


def test_build_usage_event_clamps_latency_ms():
    """latency_ms is clamped to [0, 3_600_000]."""
    past_start = time.monotonic() - 9999  # more than 3_600_000 ms ago
    event = build_usage_event(
        request_id="req-clamp",
        tenant_context=_TENANT_CTX,
        model="test-model",
        tokens_in=0,
        tokens_out=0,
        start_time=past_start,
    )
    assert 0 <= event["latency_ms"] <= 3_600_000


def test_build_usage_event_clamps_tokens():
    """tokens_in and tokens_out are clamped to [0, 10_000_000]."""
    event = build_usage_event(
        request_id="req-tokens",
        tenant_context=_TENANT_CTX,
        model="test-model",
        tokens_in=99_999_999,  # exceeds max
        tokens_out=99_999_999,
        start_time=time.monotonic(),
    )
    assert event["tokens_in"] == 10_000_000
    assert event["tokens_out"] == 10_000_000


def test_build_usage_event_cost_estimate_is_float():
    """cost_estimate_cents must be a float ≥ 0."""
    event = build_usage_event(
        request_id="req-cost",
        tenant_context=_TENANT_CTX,
        model="gpt-3.5-turbo",
        tokens_in=1000,
        tokens_out=500,
        start_time=time.monotonic(),
    )
    assert isinstance(event["cost_estimate_cents"], float)
    assert event["cost_estimate_cents"] >= 0.0


# ---------------------------------------------------------------------------
# emit_terminal_record tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_emit_terminal_record_calls_append(settings_env):
    """emit_terminal_record calls AuditLogRepository.append once."""
    append_mock = AsyncMock()

    @asynccontextmanager
    async def _privileged_cm():
        mock_session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        mock_session.begin = _begin
        repo_mock = MagicMock()
        repo_mock.append = append_mock
        with patch("gateway.middleware.audit.AuditLogRepository", return_value=repo_mock):
            yield mock_session

    with patch("gateway.middleware.audit.get_privileged_session", return_value=_privileged_cm()):
        await emit_terminal_record(
            request_id="req-audit-001",
            tenant_context=_TENANT_CTX,
            model="gpt-3.5-turbo",
            tokens_in=50,
            tokens_out=30,
            start_time=time.monotonic(),
        )

    append_mock.assert_awaited_once()
    event_data = append_mock.call_args[0][0]
    assert event_data["event_type"] == "usage"
    assert event_data["tenant_id"] == TEST_TENANT_ID
    assert "request_id" in event_data


@pytest.mark.asyncio
async def test_emit_terminal_record_raises_gateway_error_on_append_failure(settings_env):
    """Audit append failure → GatewayError(internal_error) — un-auditable = failure."""
    @asynccontextmanager
    async def _privileged_cm():
        mock_session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        mock_session.begin = _begin
        repo_mock = MagicMock()
        repo_mock.append = AsyncMock(side_effect=RuntimeError("DB error"))
        with patch("gateway.middleware.audit.AuditLogRepository", return_value=repo_mock):
            yield mock_session

    with patch("gateway.middleware.audit.get_privileged_session", return_value=_privileged_cm()):
        with pytest.raises(GatewayError) as exc_info:
            await emit_terminal_record(
                request_id="req-audit-fail",
                tenant_context=_TENANT_CTX,
                model="gpt-3.5-turbo",
                tokens_in=0,
                tokens_out=0,
                start_time=time.monotonic(),
            )
    assert exc_info.value.error_code == "internal_error"


# ---------------------------------------------------------------------------
# CONTRACT TEST: validate usage event against events.schema.json
# ---------------------------------------------------------------------------


def test_usage_event_conforms_to_events_schema():
    """Contract test: a sample usage event validates against events.schema.json."""
    import jsonschema  # pip install jsonschema[format]
    import pathlib

    schema_path = (
        pathlib.Path(__file__).parent.parent.parent / "contracts" / "events.schema.json"
    )
    with open(schema_path) as f:
        schema = json.load(f)

    event = build_usage_event(
        request_id="req-contract-test-01",
        tenant_context=_TENANT_CTX,
        model="gpt-3.5-turbo",
        tokens_in=100,
        tokens_out=50,
        start_time=time.monotonic(),
    )

    # Validate against the full schema (oneOf dispatch on event_type='usage').
    try:
        jsonschema.validate(instance=event, schema=schema)
    except jsonschema.ValidationError as e:
        pytest.fail(f"Usage event failed events.schema.json validation: {e.message}")
