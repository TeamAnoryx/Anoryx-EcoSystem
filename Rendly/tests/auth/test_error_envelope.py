"""R-003 error-envelope conformance — the REAL 1:1 code→message pairing (R-001 audit LOW-6).

R-001's audit flagged that its own test only checked cardinality (len(codes) == len(messages)),
not that each code maps to the RIGHT message. R-003 implements the mapping (rendly.auth.errors),
so this is the binding test: ``MESSAGES`` must reproduce every code→message pairing the LOCKED
contract documents in its response examples, and must cover exactly the contract's two enums.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from rendly.auth.errors import MESSAGES, STATUS, ErrorCode

_OPENAPI = Path(__file__).parents[2] / "contracts" / "openapi.yaml"


def _spec() -> dict:
    return yaml.safe_load(_OPENAPI.read_text(encoding="utf-8"))


def _documented_pairings(spec: dict) -> list[tuple[str, str]]:
    """Every (error_code, message) pair appearing in a response example in the contract."""
    pairs: list[tuple[str, str]] = []
    for response in spec["components"]["responses"].values():
        json_body = response.get("content", {}).get("application/json", {})
        if "example" in json_body:
            ex = json_body["example"]
            pairs.append((ex["error_code"], ex["message"]))
        for example in json_body.get("examples", {}).values():
            ex = example["value"]
            pairs.append((ex["error_code"], ex["message"]))
    return pairs


def test_messages_cover_exactly_the_contract_error_code_enum() -> None:
    enum = set(_spec()["components"]["schemas"]["Error"]["properties"]["error_code"]["enum"])
    assert {code.value for code in MESSAGES} == enum


def test_messages_are_exactly_the_contract_message_enum() -> None:
    enum = set(_spec()["components"]["schemas"]["Error"]["properties"]["message"]["enum"])
    assert set(MESSAGES.values()) == enum


def test_each_documented_example_pairs_code_to_the_right_message() -> None:
    spec = _spec()
    pairings = _documented_pairings(spec)
    assert pairings, "no documented error examples found in the contract"
    for code, message in pairings:
        assert MESSAGES[ErrorCode(code)] == message, f"{code} must map to its documented message"


def test_every_code_has_a_status() -> None:
    assert set(STATUS) == set(MESSAGES)
    assert all(100 <= status <= 599 for status in STATUS.values())
