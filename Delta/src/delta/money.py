"""Money value type + the numeric integrity primitives (Fork 2).

Money is held as **integer minor units (cents)** — never a float. Floats are
forbidden in every monetary field across Delta: an estimate denominated in cents
on the wire is quantized to integer cents at ingest (the one sanctioned place a
float is touched, in :meth:`Money.from_wire_cents`) and exact integer arithmetic
is used everywhere thereafter, so the double-entry balance check is exact.

Wire maxima mirror the Sentinel contracts so a Delta value can never exceed what
the contract can carry:

- ``MAX_BUDGET_*``  — ``policy.schema.json`` BudgetLimitPolicy (1e12 tokens, 1e11 cents)
- ``MAX_USAGE_*``   — ``events.schema.json`` UsageEvent (1e7 tokens, 1e8 cents)
"""

from __future__ import annotations

from datetime import datetime
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

# --- wire maxima (overflow guards; vector 3) ------------------------------------
MAX_BUDGET_TOKENS = 1_000_000_000_000  # 1e12  policy.schema.json max_tokens_per_period
MAX_BUDGET_COST_CENTS = 100_000_000_000  # 1e11  policy.schema.json max_cost_cents_per_period
MAX_USAGE_TOKENS = 10_000_000  # 1e7   events.schema.json tokens_in/tokens_out
MAX_USAGE_COST_CENTS = 100_000_000  # 1e8   events.schema.json cost_estimate_cents

# A single ledger amount is capped at the largest monetary value any wire contract
# carries; anything above it is rejected as overflow.
MAX_MONEY_MINOR_UNITS = MAX_BUDGET_COST_CENTS

DEFAULT_CURRENCY = "USD"
_CURRENCY_PATTERN = r"^[A-Z]{3}$"  # ISO-4217 alpha-3 (Fork 4: single currency, tagged)

# ISO-4217 currency code (uppercase alpha-3). No FX in D-001.
Currency = Annotated[str, StringConstraints(pattern=_CURRENCY_PATTERN)]


def reject_non_integer(value: object, field_name: str) -> int:
    """Return ``value`` iff it is a real ``int``; otherwise raise (vector 1).

    ``bool`` is an ``int`` subclass and a ``float`` can losslessly hold small
    integers, so both are rejected explicitly — no monetary or token field may be
    fed a float (incl. ``NaN``/``Inf``) or a bool. Strings/other types are rejected
    too: we never coerce money.
    """
    if isinstance(value, bool):
        raise ValueError(f"{field_name} must be an integer, not bool")
    if isinstance(value, float):
        raise ValueError(f"{field_name} must be integer minor units; floats are forbidden")
    if not isinstance(value, int):
        raise ValueError(f"{field_name} must be an integer")
    return value


def bounded_count(value: object, field_name: str, maximum: int) -> int:
    """Validate a non-negative integer count within ``[0, maximum]`` (vectors 1, 3)."""
    value = reject_non_integer(value, field_name)
    if value < 0:
        raise ValueError(f"{field_name} must be non-negative")
    if value > maximum:
        raise ValueError(f"{field_name} exceeds wire maximum {maximum}")
    return value


def require_aware_utc(value: datetime, field_name: str) -> datetime:
    """Require a timezone-AWARE datetime (the wire convention is RFC 3339 UTC).

    Only rejects an ambiguous NAIVE value (no offset at all, which could silently be
    misread as local time); any aware offset is accepted as-is and is an unambiguous
    instant regardless of which offset it carries — this does not additionally require
    the offset itself to be zero/UTC.
    """
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError(f"{field_name} must be timezone-aware (UTC)")
    return value


class Money(BaseModel):
    """An exact monetary amount: integer ``minor_units`` (cents) + ISO-4217 currency."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    minor_units: int
    currency: Currency = DEFAULT_CURRENCY

    @field_validator("minor_units", mode="before")
    @classmethod
    def _no_float_bounded(cls, value: object) -> int:
        return bounded_count(value, "minor_units", MAX_MONEY_MINOR_UNITS)

    @classmethod
    def from_wire_cents(cls, value: int | float, currency: str = DEFAULT_CURRENCY) -> "Money":
        """Quantize a wire cost estimate (a JSON ``number``) to exact integer cents.

        This is the ONLY place Delta accepts a float: the wire
        ``cost_estimate_cents`` is a ``number`` (sub-cent fractions possible) and an
        estimate, not a bill. We round half-even to integer cents via ``Decimal``
        (``str(value)`` avoids binary-float artefacts) and never retain the float.
        ``NaN``/``Inf`` raise here.
        """
        if isinstance(value, bool):
            raise ValueError("wire cost estimate must be numeric, not bool")
        dec = Decimal(str(value))
        if not dec.is_finite():
            raise ValueError("wire cost estimate must be finite")
        try:
            quantized = int(dec.quantize(Decimal("1"), rounding=ROUND_HALF_EVEN))
        except InvalidOperation as exc:
            # A huge finite float overflows the default Decimal context; surface a
            # clean ValueError (not a raw ArithmeticError) on this one float path.
            raise ValueError("wire cost estimate magnitude is out of range") from exc
        return cls(minor_units=quantized, currency=currency)
