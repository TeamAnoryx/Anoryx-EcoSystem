"""Unit tests for data_lock.selector (F-017 vectors 4, 8, 11).

Bounded dotted-path parse + immutable withholding.
"""

from __future__ import annotations

import pytest

from data_lock import selector
from data_lock.selector import (
    ARRAY_WILDCARD,
    WITHHELD_PLACEHOLDER,
    SelectorBudgetError,
    SelectorError,
    apply_withhold,
    parse_path,
)

# --- parse_path ------------------------------------------------------------


def test_parse_simple_path() -> None:
    assert parse_path("a.b.c") == ("a", "b", "c")


def test_parse_array_wildcard() -> None:
    assert parse_path("a.b[].c") == ("a", "b", ARRAY_WILDCARD, "c")


@pytest.mark.parametrize(
    "bad",
    ["", "   ", "a..b", "a.", ".a", "a.b c", "a.$x", "a.b[", "a.b]["],
)
def test_parse_rejects_malformed(bad) -> None:
    with pytest.raises(SelectorError):
        parse_path(bad)


def test_parse_rejects_too_many_segments() -> None:
    deep = ".".join(["k"] * (selector.MAX_PATH_SEGMENTS + 1))
    with pytest.raises(SelectorError):
        parse_path(deep)


# --- apply_withhold --------------------------------------------------------


def test_withhold_nested_leaf() -> None:
    obj = {"result": {"ssn": "123-45-6789", "name": "Ada"}}
    new, count = apply_withhold(obj, [parse_path("result.ssn")])
    assert count == 1
    assert new["result"]["ssn"] == WITHHELD_PLACEHOLDER
    assert new["result"]["name"] == "Ada"  # vector 8: unmatched untouched


def test_withhold_is_immutable() -> None:
    obj = {"result": {"ssn": "123-45-6789"}}
    new, _ = apply_withhold(obj, [parse_path("result.ssn")])
    assert obj["result"]["ssn"] == "123-45-6789"  # original unchanged
    assert new is not obj


def test_withhold_array_wildcard_locks_every_element() -> None:
    obj = {"rows": [{"v": 1, "keep": "a"}, {"v": 2, "keep": "b"}]}
    new, count = apply_withhold(obj, [parse_path("rows[].v")])
    assert count == 2
    assert [r["v"] for r in new["rows"]] == [WITHHELD_PLACEHOLDER, WITHHELD_PLACEHOLDER]
    assert [r["keep"] for r in new["rows"]] == ["a", "b"]  # vector 8


def test_withhold_absent_path_is_noop() -> None:
    obj = {"result": {"name": "Ada"}}
    new, count = apply_withhold(obj, [parse_path("result.ssn")])
    assert count == 0
    assert new == obj  # nothing matched → unchanged


def test_withhold_multifield_all_or_none(monkeypatch) -> None:
    """Vector 4: a multi-field payload withholds EVERY matching field."""
    obj = {"a": {"x": 1}, "b": {"y": 2}, "c": 3}
    paths = [parse_path("a.x"), parse_path("b.y")]
    new, count = apply_withhold(obj, paths)
    assert count == 2
    assert new["a"]["x"] == WITHHELD_PLACEHOLDER
    assert new["b"]["y"] == WITHHELD_PLACEHOLDER
    assert new["c"] == 3


def test_traversal_budget_enforced(monkeypatch) -> None:
    """Vector 11: a payload that would exceed the node budget raises (fail-closed)."""
    monkeypatch.setattr(selector, "MAX_TRAVERSAL_NODES", 5)
    big = {"rows": [{"v": i} for i in range(50)]}
    with pytest.raises(SelectorBudgetError):
        apply_withhold(big, [parse_path("rows[].v")])
