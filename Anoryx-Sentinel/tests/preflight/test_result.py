"""Unit tests for F-031 CheckResult aggregation logic."""

from __future__ import annotations

from preflight.result import (
    STATUS_FAIL,
    STATUS_PASS,
    STATUS_SKIP,
    STATUS_WARN,
    CheckResult,
    gate_passed,
    worst_status,
)


def _r(status):
    return CheckResult(name="x", status=status, detail="d")


def test_worst_status_empty_is_pass():
    assert worst_status([]) == STATUS_PASS


def test_worst_status_picks_highest_severity():
    assert worst_status([_r(STATUS_PASS), _r(STATUS_WARN), _r(STATUS_SKIP)]) == STATUS_WARN
    assert worst_status([_r(STATUS_WARN), _r(STATUS_FAIL)]) == STATUS_FAIL


def test_skip_and_pass_are_non_blocking():
    assert gate_passed([_r(STATUS_PASS), _r(STATUS_SKIP), _r(STATUS_WARN)]) is True


def test_any_fail_blocks_the_gate():
    assert gate_passed([_r(STATUS_PASS), _r(STATUS_FAIL)]) is False


def test_is_blocking_only_for_fail():
    assert _r(STATUS_FAIL).is_blocking is True
    for s in (STATUS_PASS, STATUS_WARN, STATUS_SKIP):
        assert _r(s).is_blocking is False
