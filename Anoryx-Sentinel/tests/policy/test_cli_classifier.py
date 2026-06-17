"""sentinel-cli classifier set/get/unset (F-007, ADR-0010 §11).

The privileged session + repo are mocked, so these are fast unit tests with no DB
writes. They verify command dispatch, the SQL/params for set/unset, the resolved
output for get, and argparse validation of --model / --audit-mode.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest

from orchestration.judge.config import ClassifierConfig
from policy.cli import main

HAIKU = "anthropic:claude-haiku-4-5"


def _fake_privileged():
    """Return (cm, captured) where captured['session'].execute is an AsyncMock."""
    captured: dict = {}

    @asynccontextmanager
    async def _cm(*_a, **_k):
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        session.execute = AsyncMock()
        captured["session"] = session
        yield session

    return _cm, captured


def test_classifier_set_upserts(monkeypatch, capsys):
    cm, captured = _fake_privileged()
    monkeypatch.setattr("persistence.database.get_privileged_session", cm)
    rc = main(
        ["classifier", "set", "--tenant", "t-1", "--model", HAIKU, "--audit-mode", "redacted"]
    )
    assert rc == 0
    sql, params = captured["session"].execute.call_args.args
    text = str(sql)
    assert "INSERT INTO tenant_routing_policy" in text and "ON CONFLICT" in text
    assert params["model"] == HAIKU and params["mode"] == "redacted" and params["t"] == "t-1"
    assert "classifier set for tenant t-1" in capsys.readouterr().out


def test_classifier_unset_nulls_model(monkeypatch, capsys):
    cm, captured = _fake_privileged()
    monkeypatch.setattr("persistence.database.get_privileged_session", cm)
    rc = main(["classifier", "unset", "--tenant", "t-9"])
    assert rc == 0
    sql, params = captured["session"].execute.call_args.args
    assert "classifier_model_id = NULL" in str(sql) and params["t"] == "t-9"
    assert "unset for tenant t-9" in capsys.readouterr().out


def test_classifier_get_shows_resolved(monkeypatch, capsys):
    cm, _ = _fake_privileged()
    monkeypatch.setattr("persistence.database.get_privileged_session", cm)
    monkeypatch.setattr(
        "persistence.repositories.tenant_routing_policy_repository."
        "TenantRoutingPolicyRepository.resolve_classifier_config",
        AsyncMock(return_value=ClassifierConfig(model_id=HAIKU, audit_mode="full")),
    )
    rc = main(["classifier", "get", "--tenant", "t-2"])
    assert rc == 0
    out = capsys.readouterr().out
    assert f"model={HAIKU}" in out and "audit_mode=full" in out


def test_classifier_get_unconfigured(monkeypatch, capsys):
    cm, _ = _fake_privileged()
    monkeypatch.setattr("persistence.database.get_privileged_session", cm)
    monkeypatch.setattr(
        "persistence.repositories.tenant_routing_policy_repository."
        "TenantRoutingPolicyRepository.resolve_classifier_config",
        AsyncMock(return_value=ClassifierConfig(model_id=None, audit_mode="full")),
    )
    rc = main(["classifier", "get", "--tenant", "t-3"])
    assert rc == 0
    assert "(unconfigured)" in capsys.readouterr().out


def test_classifier_set_rejects_unknown_preset():
    # argparse choices reject an out-of-allow-list preset before any DB call.
    with pytest.raises(SystemExit):
        main(["classifier", "set", "--tenant", "t", "--model", "anthropic:claude-3-opus"])


def test_classifier_set_rejects_bad_audit_mode():
    with pytest.raises(SystemExit):
        main(["classifier", "set", "--tenant", "t", "--model", HAIKU, "--audit-mode", "loud"])
