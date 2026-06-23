"""Unit tests for data_lock.config fail-closed branches (F-017, no DB).

Exercises the loader's error posture without a database by stubbing
get_tenant_session + PolicyRepository: every failure that leaves the ruleset
unknowable must RAISE DataLockConfigError (→ detector fail-closed block), while a
successful empty load is a cheap not-armed pass.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import pytest

from data_lock import config as cfg
from data_lock.config import DataLockConfigError, load_data_lock_config

pytestmark = pytest.mark.asyncio


class _Row:
    def __init__(self, payload: str) -> None:
        self.policy_payload = payload


def _stub(monkeypatch, *, policies=None, session_raises=False, repo_raises=False):
    @asynccontextmanager
    async def _fake_session(tenant_id):  # noqa: ANN001
        if session_raises:
            raise RuntimeError("db down")
        yield object()

    monkeypatch.setattr(cfg, "get_tenant_session", _fake_session)

    class _FakeRepo:
        def __init__(self, _session) -> None:  # noqa: ANN001
            pass

        async def get_active_policies_for_scope(self, tenant_id, policy_type):  # noqa: ANN001
            if repo_raises:
                raise RuntimeError("query failed")
            return policies or []

    monkeypatch.setattr(cfg, "PolicyRepository", _FakeRepo)


async def test_empty_tenant_id_fails_closed(monkeypatch) -> None:
    _stub(monkeypatch, policies=[])
    with pytest.raises(DataLockConfigError):
        await load_data_lock_config("")


async def test_session_error_fails_closed(monkeypatch) -> None:
    _stub(monkeypatch, session_raises=True)
    with pytest.raises(DataLockConfigError):
        await load_data_lock_config("t1")


async def test_query_error_fails_closed(monkeypatch) -> None:
    _stub(monkeypatch, repo_raises=True)
    with pytest.raises(DataLockConfigError):
        await load_data_lock_config("t1")


async def test_no_policy_not_armed(monkeypatch) -> None:
    _stub(monkeypatch, policies=[])
    conf = await load_data_lock_config("t1")
    assert conf.armed is False
    assert conf.rules == ()


async def test_multiple_active_policies_fails_closed(monkeypatch) -> None:
    _stub(monkeypatch, policies=[_Row("{}"), _Row("{}")])
    with pytest.raises(DataLockConfigError):
        await load_data_lock_config("t1")


async def test_unparseable_payload_fails_closed(monkeypatch) -> None:
    _stub(monkeypatch, policies=[_Row("{not json")])
    with pytest.raises(DataLockConfigError):
        await load_data_lock_config("t1")


async def test_malformed_rule_fails_closed(monkeypatch) -> None:
    _stub(monkeypatch, policies=[_Row('{"enabled": true, "rules": [{"field_path": "a..b"}]}')])
    with pytest.raises(DataLockConfigError):
        await load_data_lock_config("t1")


async def test_disabled_policy_not_armed(monkeypatch) -> None:
    _stub(monkeypatch, policies=[_Row('{"enabled": false}')])
    conf = await load_data_lock_config("t1")
    assert conf.armed is False


async def test_enabled_policy_armed_with_rules(monkeypatch) -> None:
    payload = (
        '{"enabled": true, "rules": ['
        '{"field_path": "result.ssn", "condition": {"type": "time", '
        '"unlock_at": "2099-01-01T00:00:00Z"}}]}'
    )
    _stub(monkeypatch, policies=[_Row(payload)])
    conf = await load_data_lock_config("t1")
    assert conf.armed is True
    assert len(conf.rules) == 1
