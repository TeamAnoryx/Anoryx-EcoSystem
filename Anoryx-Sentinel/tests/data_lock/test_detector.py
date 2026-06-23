"""Unit tests for DataLockDetector (F-017 vectors 1, 2, 4, 7, 8).

The per-tenant CONFIG LOAD is stubbed here so the enforcement logic can be tested
without a DB.  The NON-STUBBED counterparts that prove the real persist/load/hook
path live in test_crit2_policy_persist.py (vectors 5, 6) and
test_e2e_nonstubbed.py (vector 12) — both DB-gated.  (Stub-audit, ADR-0020 §STEP10.)
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from data_lock import detector as detector_mod
from data_lock.config import DataLockConfig, DataLockConfigError
from data_lock.detector import DataLockDetector
from data_lock.rules import parse_rules
from data_lock.selector import WITHHELD_PLACEHOLDER

pytestmark = pytest.mark.asyncio


class _FakeTenantContext:
    def __init__(self, team_id="team-a", project_id="proj-a", agent_id="agent-a"):
        self.tenant_id = "tenant-a"
        self.team_id = team_id
        self.project_id = project_id
        self.agent_id = agent_id


class _FakeContext:
    """Minimal HookContext stand-in: identity + a recording emit()."""

    def __init__(self, **ids):
        self.tenant_context = _FakeTenantContext(**ids)
        self.request_id = "req-1"
        self.events: list[dict] = []

    async def emit(self, event, *, detector_slug):  # noqa: ANN001
        self.events.append(event)
        return True


def _config(payload: dict) -> DataLockConfig:
    armed, rules = parse_rules(payload)
    return DataLockConfig(armed=armed, rules=tuple(rules))


def _envelope(content_obj) -> str:
    """One-choice chat-completion envelope whose assistant content is JSON."""
    return json.dumps(
        {
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": json.dumps(content_obj)}}
            ]
        }
    )


def _stub_config(monkeypatch, config_or_exc) -> None:
    async def _fake(tenant_id):  # noqa: ANN001
        if isinstance(config_or_exc, Exception):
            raise config_or_exc
        return config_or_exc

    monkeypatch.setattr(detector_mod, "load_data_lock_config", _fake)


_FUTURE = (datetime.now(timezone.utc) + timedelta(days=3650)).isoformat()
_PAST = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()


# --- vector 1: fail-closed on error ---------------------------------------


async def test_config_load_error_blocks_whole_response(monkeypatch) -> None:
    """Vector 1: a load error → action=block (fail-closed), data_lock_error audited."""
    _stub_config(monkeypatch, DataLockConfigError("boom"))
    ctx = _FakeContext()
    result = await DataLockDetector().inspect(_envelope({"result": {"ssn": "x"}}), ctx)
    assert result.action == "block"
    assert any(e["event_type"] == "data_lock_error" for e in ctx.events)
    assert ctx.events[0]["action_taken"] == "blocked"


async def test_envelope_unparseable_blocks(monkeypatch) -> None:
    _stub_config(
        monkeypatch,
        _config(
            {
                "enabled": True,
                "rules": [{"field_path": "a", "condition": {"type": "time", "unlock_at": _FUTURE}}],
            }
        ),
    )
    ctx = _FakeContext()
    result = await DataLockDetector().inspect("not json", ctx)
    assert result.action == "block"


# --- not armed -------------------------------------------------------------


async def test_not_armed_passes(monkeypatch) -> None:
    _stub_config(monkeypatch, DataLockConfig(armed=False))
    ctx = _FakeContext()
    result = await DataLockDetector().inspect(_envelope({"result": {"ssn": "x"}}), ctx)
    assert result.action == "pass"
    assert ctx.events == []


# --- vector 7: time condition (withheld before, released after) ------------


async def test_time_future_withholds(monkeypatch) -> None:
    _stub_config(
        monkeypatch,
        _config(
            {
                "enabled": True,
                "rules": [
                    {
                        "field_path": "result.ssn",
                        "condition": {"type": "time", "unlock_at": _FUTURE},
                    }
                ],
            }
        ),
    )
    ctx = _FakeContext()
    result = await DataLockDetector().inspect(
        _envelope({"result": {"ssn": "123", "name": "Ada"}}), ctx
    )
    assert result.action == "mask"
    content = json.loads(json.loads(result.modified_payload)["choices"][0]["message"]["content"])
    assert content["result"]["ssn"] == WITHHELD_PLACEHOLDER
    assert content["result"]["name"] == "Ada"  # vector 8
    assert any(e["event_type"] == "field_locked" for e in ctx.events)


async def test_time_past_releases(monkeypatch) -> None:
    _stub_config(
        monkeypatch,
        _config(
            {
                "enabled": True,
                "rules": [
                    {"field_path": "result.ssn", "condition": {"type": "time", "unlock_at": _PAST}}
                ],
            }
        ),
    )
    ctx = _FakeContext()
    result = await DataLockDetector().inspect(_envelope({"result": {"ssn": "123"}}), ctx)
    assert result.action == "pass"
    assert any(e["event_type"] == "field_unlocked" for e in ctx.events)


# --- vector 2: permission non-forgeability --------------------------------


async def test_permission_no_match_withholds(monkeypatch) -> None:
    _stub_config(
        monkeypatch,
        _config(
            {
                "enabled": True,
                "rules": [
                    {
                        "field_path": "result.salary",
                        "condition": {
                            "type": "permission",
                            "allow": {"project_id": ["proj-FINANCE"]},
                        },
                    }
                ],
            }
        ),
    )
    ctx = _FakeContext(project_id="proj-a")  # not finance
    result = await DataLockDetector().inspect(_envelope({"result": {"salary": 100}}), ctx)
    assert result.action == "mask"
    assert any(e["event_type"] == "lock_condition_denied" for e in ctx.events)


async def test_permission_match_releases(monkeypatch) -> None:
    _stub_config(
        monkeypatch,
        _config(
            {
                "enabled": True,
                "rules": [
                    {
                        "field_path": "result.salary",
                        "condition": {"type": "permission", "allow": {"project_id": ["proj-a"]}},
                    }
                ],
            }
        ),
    )
    ctx = _FakeContext(project_id="proj-a")
    result = await DataLockDetector().inspect(_envelope({"result": {"salary": 100}}), ctx)
    assert result.action == "pass"


async def test_caller_cannot_forge_permission_via_body(monkeypatch) -> None:
    """Vector 2: a forged claim embedded in the RESPONSE body does not unlock —
    the detector matches only the server-resolved ctx identity."""
    _stub_config(
        monkeypatch,
        _config(
            {
                "enabled": True,
                "rules": [
                    {
                        "field_path": "result.salary",
                        "condition": {
                            "type": "permission",
                            "allow": {"project_id": ["proj-FINANCE"]},
                        },
                    }
                ],
            }
        ),
    )
    ctx = _FakeContext(project_id="proj-a")
    # The model output even contains a fake 'project_id: proj-FINANCE' claim.
    body = _envelope({"result": {"salary": 100}, "project_id": "proj-FINANCE", "role": "admin"})
    result = await DataLockDetector().inspect(body, ctx)
    assert result.action == "mask"  # still withheld — the body claim is ignored
    content = json.loads(json.loads(result.modified_payload)["choices"][0]["message"]["content"])
    assert content["result"]["salary"] == WITHHELD_PLACEHOLDER


# --- vector 4: multi-field, no partial leak --------------------------------


async def test_multifield_all_withheld(monkeypatch) -> None:
    _stub_config(
        monkeypatch,
        _config(
            {
                "enabled": True,
                "rules": [
                    {"field_path": "a.x", "condition": {"type": "time", "unlock_at": _FUTURE}},
                    {"field_path": "b.y", "condition": {"type": "time", "unlock_at": _FUTURE}},
                ],
            }
        ),
    )
    ctx = _FakeContext()
    result = await DataLockDetector().inspect(
        _envelope({"a": {"x": 1}, "b": {"y": 2}, "c": 3}), ctx
    )
    assert result.action == "mask"
    content = json.loads(json.loads(result.modified_payload)["choices"][0]["message"]["content"])
    assert content["a"]["x"] == WITHHELD_PLACEHOLDER
    assert content["b"]["y"] == WITHHELD_PLACEHOLDER
    assert content["c"] == 3  # vector 8


async def test_released_rules_never_block_on_budget(monkeypatch) -> None:
    """H-1: a fully-RELEASED response must not 403 even if release-probing would
    exhaust the traversal budget. Only unmet (withholding) rules may fail closed."""
    from data_lock import selector

    monkeypatch.setattr(selector, "MAX_TRAVERSAL_NODES", 3)
    # All rules are permission-matched (released) for this caller.
    rules = [
        {
            "field_path": f"result.f{i}",
            "condition": {"type": "permission", "allow": {"project_id": ["proj-a"]}},
        }
        for i in range(10)
    ]
    _stub_config(monkeypatch, _config({"enabled": True, "rules": rules}))
    ctx = _FakeContext(project_id="proj-a")
    obj = {"result": {f"f{i}": i for i in range(10)}}
    result = await DataLockDetector().inspect(_envelope(obj), ctx)
    assert result.action == "pass"  # released — never blocked by probe budget


async def test_prose_content_out_of_scope_passes(monkeypatch) -> None:
    """Non-JSON assistant content has no fields to match → pass (Fork 2 scope)."""
    _stub_config(
        monkeypatch,
        _config(
            {
                "enabled": True,
                "rules": [
                    {
                        "field_path": "result.ssn",
                        "condition": {"type": "time", "unlock_at": _FUTURE},
                    }
                ],
            }
        ),
    )
    ctx = _FakeContext()
    envelope = json.dumps(
        {"choices": [{"message": {"role": "assistant", "content": "here is the ssn: 123"}}]}
    )
    result = await DataLockDetector().inspect(envelope, ctx)
    assert result.action == "pass"


# --- streaming pre-flight (ADR-0020 §5) -----------------------------------


async def test_stream_preflight_armed_blocks(monkeypatch) -> None:
    _stub_config(
        monkeypatch,
        _config(
            {
                "enabled": True,
                "rules": [{"field_path": "a", "condition": {"type": "time", "unlock_at": _FUTURE}}],
            }
        ),
    )
    ctx = _FakeContext()
    result = await DataLockDetector().evaluate_stream_preflight(ctx)
    assert result.action == "block"
    # Whole-request block uses data_lock_error (FieldLockedEvent requires a
    # pattern_name; a streamed block has no single field path).
    assert any(e["event_type"] == "data_lock_error" for e in ctx.events)


async def test_stream_preflight_not_armed_passes(monkeypatch) -> None:
    _stub_config(monkeypatch, DataLockConfig(armed=False))
    ctx = _FakeContext()
    result = await DataLockDetector().evaluate_stream_preflight(ctx)
    assert result.action == "pass"


async def test_stream_preflight_load_error_blocks(monkeypatch) -> None:
    _stub_config(monkeypatch, DataLockConfigError("boom"))
    ctx = _FakeContext()
    result = await DataLockDetector().evaluate_stream_preflight(ctx)
    assert result.action == "block"
