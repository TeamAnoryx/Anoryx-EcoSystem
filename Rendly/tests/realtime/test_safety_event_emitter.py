"""Unit tests for X-004's ``safety_event_emitter.py`` — no DB dependency itself.

Lives under tests/realtime (like test_detectors.py) so it shares the suite's DB-gated collection;
the module under test has no DB dependency of its own. These tests exercise the emitter in
isolation (request-shape correctness, idempotency-key derivation, unconfigured no-op behavior,
exception-swallowing on failure) using a real ``httpx.AsyncClient`` wired to an in-process
``httpx.MockTransport`` — no real network call, but no hand-rolled HTTP stub either. The
integration-style test that drives the REAL R-008 pipeline end-to-end and asserts THIS module
gets invoked correctly lives in ``test_chat_inspection_safety_events.py``.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

import httpx
import pytest

from rendly.realtime import safety_event_emitter as see
from rendly.realtime.inspector import DetectorFinding


@pytest.fixture(autouse=True)
def _clean_background_tasks() -> None:
    """The module-level fire-and-forget task set must start (and end) empty per test."""
    see._background_tasks.clear()
    yield
    see._background_tasks.clear()


@pytest.fixture(autouse=True)
def _unconfigured_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test starts with BOTH env vars unset; tests that need config set it explicitly."""
    monkeypatch.delenv(see.ORCHESTRATOR_SAFETY_URL_ENV, raising=False)
    monkeypatch.delenv(see.ORCHESTRATOR_SAFETY_TOKEN_ENV, raising=False)


def _patch_transport(monkeypatch: pytest.MonkeyPatch, handler) -> list[httpx.Request]:
    """Force every ``httpx.AsyncClient`` built anywhere in the process (this module only
    constructs one, in ``_post_event``) onto a ``MockTransport`` — no real socket, but a real
    httpx request/response round-trip (headers, JSON body, status code all genuinely exercised).
    """
    captured: list[httpx.Request] = []

    def _capturing_handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return handler(request)

    transport = httpx.MockTransport(_capturing_handler)
    original_init = httpx.AsyncClient.__init__

    def _patched_init(self: httpx.AsyncClient, *args: object, **kwargs: object) -> None:
        kwargs["transport"] = transport
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", _patched_init)
    return captured


async def _await_background_tasks() -> None:
    tasks = list(see._background_tasks)
    if tasks:
        await asyncio.gather(*tasks)


def _finding(category: str, outcome: str) -> DetectorFinding:
    return DetectorFinding(category=category, outcome=outcome)  # type: ignore[arg-type]


# --- payload shape ------------------------------------------------------------------------


def test_build_payload_shape_matches_wire_contract() -> None:
    occurred_at = datetime(2026, 7, 8, 12, 0, 0, tzinfo=timezone.utc)
    payload = see._build_payload(
        tenant_id="2a4f8c1e-0012-4b3d-9abc-d1e2f3a4b5c6",
        category="pii",
        target="room-7f3a",
        idempotency_key="rendly-inspection-abc-pii",
        occurred_at=occurred_at,
    )
    # Closed-schema equivalent: EXACTLY the SafetyEventIngestRequest keys, no source_product
    # (server-resolved from the bearer, per the contract — never supplied in the body).
    assert set(payload.keys()) == {
        "tenant_id",
        "category",
        "outcome",
        "target",
        "idempotency_key",
        "occurred_at",
    }
    assert payload["outcome"] == "block"
    assert payload["category"] == "pii"
    assert payload["target"] == "room-7f3a"
    assert payload["idempotency_key"] == "rendly-inspection-abc-pii"
    # Explicit UTC offset, as the contract requires.
    assert payload["occurred_at"] == "2026-07-08T12:00:00+00:00"


# --- unconfigured -> safe no-op ------------------------------------------------------------


def test_noop_when_both_env_vars_unset() -> None:
    see.emit_block_events_best_effort(
        tenant_id="t1",
        channel_id="c1",
        audit_id="a1",
        detectors=(_finding("pii", "block"),),
        occurred_at=datetime.now(timezone.utc),
    )
    assert see._background_tasks == set()


def test_noop_when_only_url_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(see.ORCHESTRATOR_SAFETY_URL_ENV, "https://orchestrator.internal")
    see.emit_block_events_best_effort(
        tenant_id="t1",
        channel_id="c1",
        audit_id="a1",
        detectors=(_finding("pii", "block"),),
        occurred_at=datetime.now(timezone.utc),
    )
    assert see._background_tasks == set()


def test_noop_when_only_token_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(see.ORCHESTRATOR_SAFETY_TOKEN_ENV, "tok")
    see.emit_block_events_best_effort(
        tenant_id="t1",
        channel_id="c1",
        audit_id="a1",
        detectors=(_finding("pii", "block"),),
        occurred_at=datetime.now(timezone.utc),
    )
    assert see._background_tasks == set()


def test_noop_when_no_detector_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """Even fully configured, a request with no ``outcome == "block"`` finding schedules nothing
    (this seam never reports a pass — the wire contract's ``outcome`` enum accepts only "block")."""
    monkeypatch.setenv(see.ORCHESTRATOR_SAFETY_URL_ENV, "https://orchestrator.internal")
    monkeypatch.setenv(see.ORCHESTRATOR_SAFETY_TOKEN_ENV, "tok")
    see.emit_block_events_best_effort(
        tenant_id="t1",
        channel_id="c1",
        audit_id="a1",
        detectors=(_finding("pii", "pass"), _finding("injection", "pass")),
        occurred_at=datetime.now(timezone.utc),
    )
    assert see._background_tasks == set()


# --- no running event loop -> logged, never raised -----------------------------------------


def test_configured_but_no_running_loop_logs_and_does_not_raise(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(see.ORCHESTRATOR_SAFETY_URL_ENV, "https://orchestrator.internal")
    monkeypatch.setenv(see.ORCHESTRATOR_SAFETY_TOKEN_ENV, "tok")
    with caplog.at_level(logging.WARNING, logger=see.logger.name):
        see.emit_block_events_best_effort(  # called with no asyncio event loop running
            tenant_id="t1",
            channel_id="c1",
            audit_id="a1",
            detectors=(_finding("pii", "block"),),
            occurred_at=datetime.now(timezone.utc),
        )
    assert "safety_event_emit_skipped_no_event_loop" in caplog.text
    assert see._background_tasks == set()


# --- configured + running loop: request shape, multi-category, idempotency -----------------


def test_emits_one_event_per_blocking_category_with_correct_request_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(see.ORCHESTRATOR_SAFETY_URL_ENV, "https://orchestrator.internal/")
    monkeypatch.setenv(see.ORCHESTRATOR_SAFETY_TOKEN_ENV, "s3cr3t-tok")
    captured = _patch_transport(
        monkeypatch, lambda request: httpx.Response(202, json={"status": "accepted"})
    )
    occurred_at = datetime(2026, 7, 8, 12, 0, 0, tzinfo=timezone.utc)

    async def _run() -> None:
        see.emit_block_events_best_effort(
            tenant_id="t-1",
            channel_id="room-7f3a",
            audit_id="audit-xyz",
            detectors=(
                _finding("pii", "block"),
                _finding("injection", "pass"),
                _finding("secret", "block"),
            ),
            occurred_at=occurred_at,
        )
        await _await_background_tasks()

    asyncio.run(_run())

    assert len(captured) == 2  # only the two BLOCKING findings, never the "pass" one
    payloads = [json.loads(req.content) for req in captured]
    categories = {p["category"] for p in payloads}
    assert categories == {"pii", "secret"}
    for p in payloads:
        assert p["tenant_id"] == "t-1"
        assert p["outcome"] == "block"
        assert p["target"] == "room-7f3a"
        assert p["occurred_at"] == "2026-07-08T12:00:00+00:00"
        assert p["idempotency_key"] == f"rendly-inspection-audit-xyz-{p['category']}"
    # trailing slash on the configured base URL is normalized, path is exactly the contract path
    for req in captured:
        assert str(req.url) == "https://orchestrator.internal/v1/safety/events"
        assert req.headers["authorization"] == "Bearer s3cr3t-tok"


def test_idempotency_key_stable_and_unique_per_row_and_category(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(see.ORCHESTRATOR_SAFETY_URL_ENV, "https://orchestrator.internal")
    monkeypatch.setenv(see.ORCHESTRATOR_SAFETY_TOKEN_ENV, "tok")
    captured = _patch_transport(monkeypatch, lambda request: httpx.Response(202))

    async def _run() -> None:
        see.emit_block_events_best_effort(
            tenant_id="t-1",
            channel_id="c-1",
            audit_id="row-1",
            detectors=(_finding("pii", "block"),),
            occurred_at=datetime.now(timezone.utc),
        )
        await _await_background_tasks()
        see.emit_block_events_best_effort(  # same audit_id, retried — same key (safe to retry)
            tenant_id="t-1",
            channel_id="c-1",
            audit_id="row-1",
            detectors=(_finding("pii", "block"),),
            occurred_at=datetime.now(timezone.utc),
        )
        await _await_background_tasks()

    asyncio.run(_run())

    keys = [json.loads(req.content)["idempotency_key"] for req in captured]
    assert keys == ["rendly-inspection-row-1-pii", "rendly-inspection-row-1-pii"]


# --- delivery-failure exception-swallowing (fail-open) --------------------------------------


def test_non_202_response_is_logged_and_swallowed(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(see.ORCHESTRATOR_SAFETY_URL_ENV, "https://orchestrator.internal")
    monkeypatch.setenv(see.ORCHESTRATOR_SAFETY_TOKEN_ENV, "tok")
    _patch_transport(monkeypatch, lambda request: httpx.Response(500))

    async def _run() -> None:
        see.emit_block_events_best_effort(
            tenant_id="t-1",
            channel_id="c-1",
            audit_id="row-1",
            detectors=(_finding("pii", "block"),),
            occurred_at=datetime.now(timezone.utc),
        )
        with caplog.at_level(logging.WARNING, logger=see.logger.name):
            await _await_background_tasks()

    asyncio.run(_run())  # must not raise
    assert "safety_event_emit_unexpected_status" in caplog.text


def test_transport_exception_is_logged_and_swallowed(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(see.ORCHESTRATOR_SAFETY_URL_ENV, "https://orchestrator.internal")
    monkeypatch.setenv(see.ORCHESTRATOR_SAFETY_TOKEN_ENV, "tok")

    def _raise(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    _patch_transport(monkeypatch, _raise)

    async def _run() -> None:
        see.emit_block_events_best_effort(
            tenant_id="t-1",
            channel_id="c-1",
            audit_id="row-1",
            detectors=(_finding("secret", "block"),),
            occurred_at=datetime.now(timezone.utc),
        )
        with caplog.at_level(logging.WARNING, logger=see.logger.name):
            await _await_background_tasks()

    asyncio.run(_run())  # must not raise — the whole point of fail-open (ADR-0023 Fork E / D5)
    assert "safety_event_emit_failed" in caplog.text
