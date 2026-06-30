"""Drainer error-path unit tests (no DB) — the defensive branches (vector 11).

Exercises the missing-key, snapshot-read-failure (transient + non-transient classify), and
per-delivery (sign-fail / transient-retry / retries-exhausted / permanent / distributed)
branches with mocks, so the fail posture is proven without a live database.
"""

from __future__ import annotations

import contextlib
from datetime import datetime, timezone

from delta.budget_engine import drainer
from delta.budget_engine.config import EngineSettings
from delta.budget_engine.outbox import OutboxRow
from delta.budget_engine.publisher import (
    Distributed,
    PermanentPublishError,
    TransientPublishError,
)
from delta.policy.sign import PolicySigningKeyError

_NOW = datetime(2026, 7, 1, tzinfo=timezone.utc)
_S = EngineSettings(
    enabled=True,
    distribution_url="http://x",
    service_token="t",
    max_publish_attempts=3,
    backoff_base_seconds=0.0,
)


def _row(attempts: int = 0) -> OutboxRow:
    return OutboxRow(
        outbox_id="o1",
        tenant_id="t1",
        policy_id="p1",
        policy_version=1,
        transition="enforce",
        policy_payload={"policy_type": "budget_limit"},
        attempts=attempts,
    )


def _session_factory(exc: Exception):
    @contextlib.asynccontextmanager
    async def _raising(_tenant_id):
        raise exc
        yield  # pragma: no cover - unreachable

    return _raising


async def test_missing_key_returns_without_opening_a_session(monkeypatch):
    def _no_key():
        raise PolicySigningKeyError("no key")

    def _explode(_tid):
        raise AssertionError("must not open a session without a signing key")

    monkeypatch.setattr(drainer, "load_signing_key", _no_key)
    monkeypatch.setattr(drainer, "get_tenant_session", _explode)
    await drainer.drain_tenant("t1", _S, _NOW)  # returns cleanly, nothing published


async def test_snapshot_read_transient_logged_warning(monkeypatch, caplog):
    monkeypatch.setattr(drainer, "load_signing_key", lambda: object())
    monkeypatch.setattr(
        drainer, "get_tenant_session", _session_factory(ConnectionRefusedError("db down"))
    )
    with caplog.at_level("WARNING"):
        await drainer.drain_tenant("t1", _S, _NOW)
    assert any("transiently unavailable" in r.getMessage() for r in caplog.records)


async def test_snapshot_read_nontransient_escalated_error(monkeypatch, caplog):
    monkeypatch.setattr(drainer, "load_signing_key", lambda: object())
    monkeypatch.setattr(drainer, "get_tenant_session", _session_factory(ValueError("schema bug")))
    with caplog.at_level("ERROR"):
        await drainer.drain_tenant("t1", _S, _NOW)
    assert any("non-transient" in r.getMessage() for r in caplog.records)


async def test_deliver_one_sign_failure_dead_letters(monkeypatch):
    captured: dict = {}

    async def _mark_failed(session, *, outbox_id, error):
        captured["error"] = error

    def _bad_sign(_payload, _key):
        raise ValueError("bad payload")

    monkeypatch.setattr(drainer, "mark_failed", _mark_failed)
    monkeypatch.setattr(drainer, "sign_policy_record", _bad_sign)
    await drainer._deliver_one(None, _row(), object(), _S, _NOW)
    assert "sign failed" in captured["error"]


async def test_deliver_one_transient_marks_retry(monkeypatch):
    captured: dict = {}

    async def _mark_retry(session, *, outbox_id, error, next_attempt_at):
        captured["retry"] = error

    async def _pub(_signed, _settings):
        raise TransientPublishError("o004 down")

    monkeypatch.setattr(drainer, "mark_retry", _mark_retry)
    monkeypatch.setattr(drainer, "sign_policy_record", lambda p, k: {"signed": True})
    monkeypatch.setattr(drainer, "publish_signed_policy", _pub)
    await drainer._deliver_one(None, _row(attempts=0), object(), _S, _NOW)
    assert "o004 down" in captured["retry"]


async def test_deliver_one_transient_exhausted_dead_letters(monkeypatch):
    captured: dict = {}

    async def _mark_failed(session, *, outbox_id, error):
        captured["failed"] = error

    async def _pub(_signed, _settings):
        raise TransientPublishError("o004 down")

    monkeypatch.setattr(drainer, "mark_failed", _mark_failed)
    monkeypatch.setattr(drainer, "sign_policy_record", lambda p, k: {"signed": True})
    monkeypatch.setattr(drainer, "publish_signed_policy", _pub)
    # attempts=2 -> attempts+1=3 >= max_publish_attempts -> dead-letter.
    await drainer._deliver_one(None, _row(attempts=2), object(), _S, _NOW)
    assert "retries exhausted" in captured["failed"]


async def test_deliver_one_permanent_dead_letters(monkeypatch):
    captured: dict = {}

    async def _mark_failed(session, *, outbox_id, error):
        captured["failed"] = error

    async def _pub(_signed, _settings):
        raise PermanentPublishError("rejected")

    monkeypatch.setattr(drainer, "mark_failed", _mark_failed)
    monkeypatch.setattr(drainer, "sign_policy_record", lambda p, k: {"signed": True})
    monkeypatch.setattr(drainer, "publish_signed_policy", _pub)
    await drainer._deliver_one(None, _row(), object(), _S, _NOW)
    assert "rejected" in captured["failed"]


async def test_deliver_one_distributed(monkeypatch):
    captured: dict = {}

    async def _mark_distributed(session, *, outbox_id, distribution_id, now):
        captured["dist"] = distribution_id

    async def _pub(_signed, _settings):
        return Distributed(distribution_id="d1")

    monkeypatch.setattr(drainer, "mark_distributed", _mark_distributed)
    monkeypatch.setattr(drainer, "sign_policy_record", lambda p, k: {"signed": True})
    monkeypatch.setattr(drainer, "publish_signed_policy", _pub)
    await drainer._deliver_one(None, _row(), object(), _S, _NOW)
    assert captured["dist"] == "d1"
