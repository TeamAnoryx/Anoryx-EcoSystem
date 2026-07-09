"""Unit tests for the F-028 ReDoS-safe regex matching engine (no DB/Presidio)."""

from __future__ import annotations

from data_protection.custom_pii.engine import compile_pattern, scan


def _p(name, pattern, score=0.85, action=None):
    return compile_pattern(name, pattern, score=score, action=action)


def test_single_pattern_matches():
    spans, timed_out = scan(
        "id EMP-123456 here", [_p("EMPLOYEE_ID", r"EMP-\d{6}")], timeout_seconds=1.0
    )
    assert timed_out == []
    assert len(spans) == 1
    assert spans[0].name == "EMPLOYEE_ID"
    assert spans[0].start == 3 and spans[0].end == 13


def test_multiple_matches_of_one_pattern():
    spans, _ = scan(
        "EMP-111111 and EMP-222222", [_p("EMPLOYEE_ID", r"EMP-\d{6}")], timeout_seconds=1.0
    )
    assert len(spans) == 2


def test_multiple_patterns():
    spans, _ = scan(
        "EMP-123456 acct#9999",
        [_p("EMPLOYEE_ID", r"EMP-\d{6}"), _p("ACCOUNT", r"acct#\d{4}")],
        timeout_seconds=1.0,
    )
    names = {s.name for s in spans}
    assert names == {"EMPLOYEE_ID", "ACCOUNT"}


def test_no_match_returns_empty():
    spans, timed_out = scan("nothing here", [_p("EMPLOYEE_ID", r"EMP-\d{6}")], timeout_seconds=1.0)
    assert spans == []
    assert timed_out == []


def test_zero_width_matches_ignored():
    # `a*` can match empty at every position — those must NOT become spans.
    spans, _ = scan("bbb", [_p("MAYBE_A", r"a*")], timeout_seconds=1.0)
    assert spans == []


def test_catastrophic_pattern_times_out_and_is_isolated():
    # A deliberately catastrophic pattern on a long input times out — but the
    # co-registered normal pattern still produces its match (isolation).
    long_input = "a" * 4000 + "X   EMP-123456"
    spans, timed_out = scan(
        long_input,
        [_p("BOOM", r"(a+)+$"), _p("EMPLOYEE_ID", r"EMP-\d{6}")],
        timeout_seconds=0.1,
    )
    assert "BOOM" in timed_out
    assert any(s.name == "EMPLOYEE_ID" for s in spans)
