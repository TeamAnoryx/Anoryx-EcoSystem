"""Kill-switch drainer error-path unit tests (no DB) — mirrors
``tests/budget_engine/test_drainer_unit.py`` (vector 4).
"""

from __future__ import annotations

import contextlib
from datetime import datetime, timezone

from delta.budget_engine.publisher import Distributed, PermanentPublishError, TransientPublishError
from delta.kill_switch import drainer
from delta.kill_switch.config import KillSwitchSettings
from delta.kill_switch.outbox import KillOutboxRow
from delta.policy.sign import PolicySigningKeyError

_NOW = datetime(2026, 7, 7, tzinfo=timezone.utc)
_S = KillSwitchSettings(
    enabled=True,
    distribution_url="http://x",
    service_token="t",
    max_publish_attempts=3,
    backoff_base_seconds=0.0,
)


def _row(attempts: int = 0) -> KillOutboxRow:
    return KillOutboxRow(
        outbox_id="o1",
        tenant_id="t1",
        policy_id="p1",
        policy_version=1,
        transition="kill",
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
    await drainer.drain_tenant("t1", _S, _NOW)


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


async def test_claim_none_skips_row(monkeypatch):
    """A row already taken by a concurrent drainer (claim_one -> None) is skipped, not
    delivered — no delivery attempt, no crash."""

    @contextlib.asynccontextmanager
    async def _fake_session(_tenant_id):
        yield object()

    async def _due(_session, *, now):
        return ["o1"]

    async def _claim(_session, *, outbox_id, now):
        return None

    async def _explode_deliver(*a, **k):
        raise AssertionError("must not deliver a claim that returned None")

    monkeypatch.setattr(drainer, "load_signing_key", lambda: object())
    monkeypatch.setattr(drainer, "get_tenant_session", _fake_session)
    monkeypatch.setattr(drainer, "due_outbox_ids", _due)
    monkeypatch.setattr(drainer, "claim_one", _claim)
    monkeypatch.setattr(drainer, "_deliver_one", _explode_deliver)
    await drainer.drain_tenant("t1", _S, _NOW)  # completes cleanly, nothing delivered


class _FakeSession:
    async def commit(self) -> None:
        pass


async def test_per_row_exception_is_classified_and_draining_continues(monkeypatch, caplog):
    @contextlib.asynccontextmanager
    async def _fake_session(_tenant_id):
        yield _FakeSession()

    async def _due(_session, *, now):
        return ["o1", "o2"]

    async def _claim(_session, *, outbox_id, now):
        if outbox_id == "o1":
            raise ConnectionRefusedError("db blip")
        return KillOutboxRow(**{**_row().__dict__, "outbox_id": outbox_id})

    delivered: list[str] = []

    async def _deliver(_session, row, _key, _settings, _now):
        delivered.append(row.outbox_id)

    monkeypatch.setattr(drainer, "load_signing_key", lambda: object())
    monkeypatch.setattr(drainer, "get_tenant_session", _fake_session)
    monkeypatch.setattr(drainer, "due_outbox_ids", _due)
    monkeypatch.setattr(drainer, "claim_one", _claim)
    monkeypatch.setattr(drainer, "_deliver_one", _deliver)
    with caplog.at_level("WARNING"):
        await drainer.drain_tenant("t1", _S, _NOW)
    assert delivered == ["o2"]  # o1's failure is logged, o2 still drains


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


async def test_deliver_one_distributed_clear_transition_logged(monkeypatch, caplog):
    async def _mark_distributed(session, *, outbox_id, distribution_id, now):
        pass

    async def _pub(_signed, _settings):
        return Distributed(distribution_id="d1")

    monkeypatch.setattr(drainer, "mark_distributed", _mark_distributed)
    monkeypatch.setattr(drainer, "sign_policy_record", lambda p, k: {"signed": True})
    monkeypatch.setattr(drainer, "publish_signed_policy", _pub)
    clear_row = _row()
    clear_row = KillOutboxRow(**{**clear_row.__dict__, "transition": "clear"})
    with caplog.at_level("INFO"):
        await drainer._deliver_one(None, clear_row, object(), _S, _NOW)
    assert any("CLEARED" in r.getMessage() for r in caplog.records)
