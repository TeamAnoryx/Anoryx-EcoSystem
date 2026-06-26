"""Money integrity — vectors 1 (float smuggling) and 3 (negative/overflow)."""

from __future__ import annotations

import math

import pytest
from pydantic import ValidationError

from delta.money import MAX_MONEY_MINOR_UNITS, Money


def test_integer_cents_accepted():
    m = Money(minor_units=12345, currency="USD")
    assert m.minor_units == 12345
    assert m.currency == "USD"


@pytest.mark.parametrize("bad", [1.0, 1.5, 0.1, float("nan"), float("inf"), -math.inf])
def test_float_minor_units_rejected(bad):
    # Vector 1: no monetary field may hold a float, not even an integral one like 1.0.
    with pytest.raises(ValidationError):
        Money(minor_units=bad)


def test_bool_minor_units_rejected():
    # bool is an int subclass; reject it explicitly so True != 1 cent.
    with pytest.raises(ValidationError):
        Money(minor_units=True)


@pytest.mark.parametrize("bad", ["100", "5", None, [1]])
def test_non_integer_minor_units_rejected(bad):
    with pytest.raises(ValidationError):
        Money(minor_units=bad)


def test_negative_rejected():
    # Vector 3: negative amount.
    with pytest.raises(ValidationError):
        Money(minor_units=-1)


def test_overflow_rejected():
    # Vector 3: above the wire maximum.
    with pytest.raises(ValidationError):
        Money(minor_units=MAX_MONEY_MINOR_UNITS + 1)


def test_max_boundary_accepted():
    assert Money(minor_units=MAX_MONEY_MINOR_UNITS).minor_units == MAX_MONEY_MINOR_UNITS


@pytest.mark.parametrize("bad_currency", ["usd", "US", "USDD", "12$", ""])
def test_currency_pattern_enforced(bad_currency):
    with pytest.raises(ValidationError):
        Money(minor_units=1, currency=bad_currency)


def test_frozen():
    m = Money(minor_units=1)
    with pytest.raises(ValidationError):
        m.minor_units = 2  # type: ignore[misc]


def test_extra_forbidden():
    with pytest.raises(ValidationError):
        Money(minor_units=1, currency="USD", note="smuggled")  # type: ignore[call-arg]


# --- from_wire_cents: the one sanctioned float entry, quantized half-even -------
@pytest.mark.parametrize(
    "wire,expected",
    [
        (100, 100),
        (100.4, 100),
        (100.5, 100),  # half-even rounds to even
        (101.5, 102),  # half-even rounds to even
        (99.6, 100),
        (0.0, 0),
    ],
)
def test_from_wire_cents_quantizes_half_even(wire, expected):
    assert Money.from_wire_cents(wire).minor_units == expected


def test_from_wire_cents_rejects_non_finite():
    for bad in (float("nan"), float("inf")):
        with pytest.raises(ValueError):
            Money.from_wire_cents(bad)


def test_from_wire_cents_rejects_bool():
    with pytest.raises(ValueError):
        Money.from_wire_cents(True)


def test_from_wire_cents_rejects_overflow_magnitude():
    # A huge finite float overflows the Decimal context; must surface a clean
    # ValueError, not a raw decimal.InvalidOperation (L-3).
    with pytest.raises(ValueError):
        Money.from_wire_cents(1e30)


def test_money_json_roundtrip():
    m = Money(minor_units=4242, currency="EUR")
    restored = Money.model_validate_json(m.model_dump_json())
    assert restored == m
