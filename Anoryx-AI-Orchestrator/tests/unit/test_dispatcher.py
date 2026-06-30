"""Isolated unit tests for the forward_outbox -> Delta drain (D-004, ADR-0004 §3.1).

These exercise the REAL ``dispatch_pending`` -> ``_dispatch_row`` -> ``_apply`` flow with
NO live database and NO live Delta: the privileged session is monkeypatched to a fake that
serves canned ``forward_outbox`` x ``ingest_events`` join rows and records the UPDATE
parameters, and the HTTP client is a real ``httpx.AsyncClient`` over an
``httpx.MockTransport`` so the sign + POST path runs unchanged (signer crypto untouched).

Each test asserts the persisted ``status``/``attempt_count`` transition AND the
``DispatchSummary`` tally for one disposition:

  (a) Delta 2xx           -> status='forwarded', attempt_count unchanged (failed-attempt count)
  (b) Delta 4xx (422)     -> status='failed'   (Delta already dead-lettered; permanent)
  (c) Delta 5xx (503)     -> status='pending', attempt_count incremented (transient retry)
  (d) transport exception -> status='pending', attempt_count incremented (transient retry)
  (e) bounded retry       -> attempt at max_attempts -> status='failed' (no infinite loop)
  (f) join miss (payload None)  -> status='skipped' (no HTTP issued)
  (g) event_type != 'usage'     -> status='skipped' (no HTTP issued)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from contextlib import asynccontextmanager

import httpx
import pytest

from orchestrator.dispatch import dispatcher, signer

_SECRET = "dispatcher-unit-secret"  # noqa: S105 - test-only fake HMAC secret
_DELTA_URL = "http://delta.test/v1/ingest/usage"


# --------------------------------------------------------------------------- fake session
class _NullTx:
    """No-op async transaction context manager (stands in for session.begin())."""

    async def __aenter__(self) -> "_NullTx":
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False


class _Result:
    """Minimal stand-in for a SQLAlchemy Result: .mappings().all() -> rows."""

    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def mappings(self) -> "_Result":
        return self

    def all(self) -> list[dict]:
        return self._rows


class _FakeSession:
    """Fake privileged session.

    A SELECT (params carry ``limit``) returns the canned join rows; an UPDATE (params
    carry ``status``) is recorded into ``self.updates`` so a test can assert the exact
    persisted transition. begin() yields a no-op transaction.
    """

    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows
        self.updates: list[dict] = []

    def begin(self) -> _NullTx:
        return _NullTx()

    async def execute(self, _stmt: object, params: dict | None = None) -> _Result:
        params = params or {}
        if "status" in params:  # the _apply UPDATE
            self.updates.append(dict(params))
            return _Result([])
        return _Result(self._rows)  # the _select_pending SELECT


def _usage_row(*, attempt_count: int = 0, event_type: str = "usage", payload: dict | None = None):
    """A forward_outbox x ingest_events join row as _select_pending materializes it."""
    event_id = str(uuid.uuid4())
    body = payload
    if body is None and event_type is not None:
        body = {"event_type": event_type, "event_id": event_id, "cost_estimate_cents": 100}
    return {
        "id": str(uuid.uuid4()),
        "idempotency_key": event_id,
        "attempt_count": attempt_count,
        "event_type": event_type,
        "payload": body,
    }


@asynccontextmanager
async def _fake_priv_session(session: _FakeSession):
    yield session


async def _drain(monkeypatch, rows, handler, *, max_attempts: int = 5):
    """Run dispatch_pending with a fake session + MockTransport handler.

    Returns (DispatchSummary, recorded UPDATE param dicts).
    """
    monkeypatch.setenv("DELTA_INGEST_HMAC_SECRET", _SECRET)
    fake = _FakeSession(rows)

    def _factory() -> object:
        return _fake_priv_session(fake)

    monkeypatch.setattr(dispatcher, "get_privileged_session", _factory)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        summary = await dispatcher.dispatch_pending(
            _DELTA_URL, http_client=client, limit=100, max_attempts=max_attempts
        )
    return summary, fake.updates


# --------------------------------------------------------------------------- (a) success
async def test_delta_2xx_marks_row_forwarded(monkeypatch):
    rows = [_usage_row(attempt_count=2)]

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "accepted"})

    summary, updates = await _drain(monkeypatch, rows, handler)

    assert summary.forwarded == 1
    assert summary.scanned == 1
    assert len(updates) == 1
    assert updates[0]["status"] == "forwarded"
    # attempt_count records FAILED attempts, so a success keeps the prior value (2 here).
    assert updates[0]["attempt_count"] == 2
    assert updates[0]["err"] is None


# --------------------------------------------------------------------------- (b) permanent 4xx
async def test_delta_4xx_marks_row_failed_permanently(monkeypatch):
    rows = [_usage_row(attempt_count=0)]

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(422, json={"status": "dead_lettered"})

    summary, updates = await _drain(monkeypatch, rows, handler)

    assert summary.failed == 1
    assert updates[0]["status"] == "failed"
    # 4xx is permanent (Delta already dead-lettered); attempt_count is NOT bumped.
    assert updates[0]["attempt_count"] == 0
    assert updates[0]["err"] == "delta 422"


# --------------------------------------------------------------------------- (c) transient 5xx
async def test_delta_5xx_increments_attempt_and_stays_pending(monkeypatch):
    rows = [_usage_row(attempt_count=1)]

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"status": "retry"})

    summary, updates = await _drain(monkeypatch, rows, handler)

    assert summary.retried == 1
    assert updates[0]["status"] == "pending"
    # Transient: attempt_count goes 1 -> 2; the row is re-selected on the next drain.
    assert updates[0]["attempt_count"] == 2
    assert updates[0]["err"] == "delta 503"


# --------------------------------------------------------------------------- (d) transport error
@pytest.mark.parametrize(
    "boom",
    [
        lambda req: (_ for _ in ()).throw(httpx.ConnectError("connect refused", request=req)),
        lambda req: (_ for _ in ()).throw(OSError("connection refused")),
    ],
)
async def test_transport_exception_is_transient(monkeypatch, boom):
    rows = [_usage_row(attempt_count=0)]

    def handler(request: httpx.Request) -> httpx.Response:
        return boom(request)

    summary, updates = await _drain(monkeypatch, rows, handler)

    assert summary.retried == 1
    assert updates[0]["status"] == "pending"
    assert updates[0]["attempt_count"] == 1
    # last_error is a short, non-sensitive exception class name (never the body/secret).
    assert updates[0]["err"] in {"ConnectError", "OSError"}


# --------------------------------------------------------------------------- (e) bounded retry
async def test_transient_at_max_attempts_marks_failed(monkeypatch):
    # attempt_count already at max_attempts-1; one more transient failure exhausts the bound.
    rows = [_usage_row(attempt_count=4)]

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"status": "retry"})

    summary, updates = await _drain(monkeypatch, rows, handler, max_attempts=5)

    assert summary.failed == 1
    assert summary.retried == 0
    assert updates[0]["status"] == "failed"
    # Bounded: attempt reaches max_attempts (5) and the row is terminally failed, not retried.
    assert updates[0]["attempt_count"] == 5


# --------------------------------------------------------------------------- (f) join miss
async def test_join_miss_payload_none_is_skipped(monkeypatch):
    # A forward_outbox row with no matching ingest_events row -> payload/event_type NULL.
    row = _usage_row()
    row["payload"] = None
    row["event_type"] = None
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    summary, updates = await _drain(monkeypatch, [row], handler)

    assert summary.skipped == 1
    assert updates[0]["status"] == "skipped"
    assert calls == []  # terminal skip issues NO HTTP request


# --------------------------------------------------------------------------- (g) non-usage type
async def test_non_usage_event_type_is_skipped(monkeypatch):
    row = _usage_row(event_type="policy_decision_deny")
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200)

    summary, updates = await _drain(monkeypatch, [row], handler)

    assert summary.skipped == 1
    assert updates[0]["status"] == "skipped"
    assert calls == []  # only 'usage' events are forwarded; others never hit the wire


# --------------------------------------------------------------------------- sign + POST path
async def test_signs_body_and_posts_canonical_payload(monkeypatch):
    payload = {"event_type": "usage", "event_id": str(uuid.uuid4()), "cost_estimate_cents": 4242}
    rows = [_usage_row(attempt_count=0, payload=payload)]
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.content
        captured["sig"] = request.headers.get(signer.SIGNATURE_HEADER)
        captured["ts"] = request.headers.get(signer.TIMESTAMP_HEADER)
        captured["attempt"] = request.headers.get(signer.ATTEMPT_HEADER)
        captured["ctype"] = request.headers.get("Content-Type")
        return httpx.Response(200, json={"status": "accepted"})

    summary, _ = await _drain(monkeypatch, rows, handler)

    assert summary.forwarded == 1
    # The body is the canonical compact JSON of the payload (the exact bytes that were signed).
    expected_body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert captured["body"] == expected_body
    assert captured["ctype"] == "application/json"
    assert captured["attempt"] == "1"  # first delivery attempt
    # Recompute the HMAC over "{ts}.{body}" with the shared secret and match the header.
    ts = str(captured["ts"])
    expected = hmac.new(
        _SECRET.encode("utf-8"), ts.encode("ascii") + b"." + expected_body, hashlib.sha256
    ).hexdigest()
    assert captured["sig"] == f"sha256={expected}"
