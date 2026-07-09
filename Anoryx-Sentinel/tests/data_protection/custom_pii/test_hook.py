"""Unit tests for CustomPiiHook (F-028) — fake loader, no DB / Presidio / spacy."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from data_protection.custom_pii.config import CustomPiiSettings
from data_protection.custom_pii.engine import CompiledPattern, compile_pattern
from data_protection.custom_pii.hook import CustomPiiHook, _reset_loader_for_testing


@dataclass
class _FakeTenantContext:
    tenant_id: str
    team_id: str | None = None
    project_id: str | None = None


@dataclass
class _FakeHookContext:
    tenant_context: _FakeTenantContext


class _FakeLoader:
    """Stand-in for CustomPiiPatternLoader — returns fixed compiled patterns,
    or raises to exercise the fail-safe-block path."""

    def __init__(self, patterns: list[CompiledPattern] | None = None, raises: bool = False):
        self._patterns = patterns or []
        self._raises = raises

    async def load(self, tenant_id: str) -> list[CompiledPattern]:
        if self._raises:
            raise RuntimeError("pattern store unreachable")
        return self._patterns


def _settings(**overrides) -> CustomPiiSettings:
    return CustomPiiSettings(**overrides)


def _ctx(tenant_id="tenant-a") -> _FakeHookContext:
    return _FakeHookContext(tenant_context=_FakeTenantContext(tenant_id=tenant_id))


def _compiled(name, pattern, score=0.85, action=None):
    return compile_pattern(name, pattern, score=score, action=action)


@pytest.fixture(autouse=True)
def _reset():
    yield
    _reset_loader_for_testing(None)


@pytest.mark.asyncio
async def test_empty_content_passes():
    _reset_loader_for_testing(_FakeLoader([_compiled("EMP", r"EMP-\d{6}")]))
    hook = CustomPiiHook(settings=_settings())
    result = await hook.inspect("", _ctx())
    assert result.action == "pass"


@pytest.mark.asyncio
async def test_no_patterns_passes():
    _reset_loader_for_testing(_FakeLoader([]))
    hook = CustomPiiHook(settings=_settings())
    result = await hook.inspect("EMP-123456", _ctx())
    assert result.action == "pass"


@pytest.mark.asyncio
async def test_match_masks_by_default():
    _reset_loader_for_testing(_FakeLoader([_compiled("EMPLOYEE_ID", r"EMP-\d{6}")]))
    hook = CustomPiiHook(settings=_settings(custom_pii_action="mask"))
    result = await hook.inspect("my id is EMP-123456 ok", _ctx())
    assert result.action == "mask"
    assert "EMP-123456" not in result.modified_payload
    assert "[REDACTED:EMPLOYEE_ID]" in result.modified_payload
    assert result.event["event_type"] == "pii_blocked"
    assert result.event["pattern_name"] == "employee_id"
    assert result.event["action_taken"] == "masked"


@pytest.mark.asyncio
async def test_no_match_passes():
    _reset_loader_for_testing(_FakeLoader([_compiled("EMPLOYEE_ID", r"EMP-\d{6}")]))
    hook = CustomPiiHook(settings=_settings())
    result = await hook.inspect("nothing sensitive here", _ctx())
    assert result.action == "pass"


@pytest.mark.asyncio
async def test_global_block_action_blocks():
    _reset_loader_for_testing(_FakeLoader([_compiled("EMPLOYEE_ID", r"EMP-\d{6}")]))
    hook = CustomPiiHook(settings=_settings(custom_pii_action="block"))
    result = await hook.inspect("EMP-123456", _ctx())
    assert result.action == "block"
    assert result.modified_payload is None
    assert result.event["action_taken"] == "blocked"


@pytest.mark.asyncio
async def test_per_pattern_block_override_wins_over_mask_default():
    # Default is mask, but a matched pattern says block -> request blocks (strict).
    patterns = [
        _compiled("SAFE", r"SAFE-\d{3}", score=0.95, action=None),
        _compiled("SECRET", r"SECRET-\d{3}", score=0.5, action="block"),
    ]
    _reset_loader_for_testing(_FakeLoader(patterns))
    hook = CustomPiiHook(settings=_settings(custom_pii_action="mask"))
    result = await hook.inspect("SAFE-111 and SECRET-222", _ctx())
    assert result.action == "block"


@pytest.mark.asyncio
async def test_loader_failure_is_fail_safe_block_raises():
    _reset_loader_for_testing(_FakeLoader(raises=True))
    hook = CustomPiiHook(settings=_settings())
    with pytest.raises(RuntimeError):
        await hook.inspect("EMP-123456", _ctx())


@pytest.mark.asyncio
async def test_severity_from_score():
    _reset_loader_for_testing(_FakeLoader([_compiled("HIGH", r"H-\d", score=0.95)]))
    hook = CustomPiiHook(settings=_settings(custom_pii_action="mask"))
    result = await hook.inspect("H-1", _ctx())
    assert result.event["severity"] == "critical"
