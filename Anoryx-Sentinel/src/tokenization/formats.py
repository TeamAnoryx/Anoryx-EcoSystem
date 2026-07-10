"""Format-preserving surrogate token generation (F-033, ADR-0039).

Given a PII value and a declared token TYPE, produce a random surrogate TOKEN
that preserves the value's FORMAT so downstream systems that validate structure
still accept it — WITHOUT the token revealing anything about the original.

Supported token types:
  - "card"    : a 16-digit number that passes the Luhn check (payment-form
                validators accept it). NOT a real issued card.
  - "ssn"     : NNN-NN-NNNN digit shape.
  - "digits"  : a same-length random digit string (matches the input's length).
  - "generic" : a "tok_" + 24 hex-char opaque token (no format to preserve).

Randomness is os.urandom-backed (SystemRandom). Surrogates are RANDOM, so two
tokenizations of the same value yield DIFFERENT tokens (no equality leakage
through the surface token — referential-integrity / deterministic tokenization
is a separate, documented option, see ADR-0039). Uniqueness across a tenant's
vault is enforced by the caller (retry on the vault's unique constraint).
"""

from __future__ import annotations

import secrets

from tokenization.exceptions import UnsupportedFormatError

_SYS_RANDOM = secrets.SystemRandom()

TOKEN_TYPES = ("card", "ssn", "digits", "generic")


def _random_digits(n: int) -> str:
    return "".join(str(_SYS_RANDOM.randint(0, 9)) for _ in range(n))


def _luhn_check_digit(digits_without_check: str) -> str:
    """Return the Luhn check digit for a numeric string (no check digit yet)."""
    total = 0
    # The check digit will be appended, so positions alternate starting doubled
    # from the rightmost of the existing digits.
    for i, ch in enumerate(reversed(digits_without_check)):
        d = int(ch)
        if i % 2 == 0:  # these become the "doubled" positions once check appended
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return str((10 - (total % 10)) % 10)


def _generate_card() -> str:
    body = _random_digits(15)
    return body + _luhn_check_digit(body)


def _generate_ssn() -> str:
    return f"{_random_digits(3)}-{_random_digits(2)}-{_random_digits(4)}"


def _validate_and_length_digits(value: str) -> int:
    stripped = value.replace(" ", "").replace("-", "")
    if not stripped.isdigit():
        raise UnsupportedFormatError("token_type='digits' requires a digit string")
    return len(stripped)


def generate_surrogate(token_type: str, original: str) -> str:
    """Return a random format-preserving surrogate token for `original`.

    Validates that `original` is compatible with `token_type` where the format
    is intrinsic (card/ssn), and derives length from `original` for "digits".
    """
    # noqa on these branches: ruff S105 false-positives on `token_type == "..."`
    # because the variable name contains "token" — this is a type dispatch, not a
    # credential comparison.
    if token_type == "card":  # noqa: S105
        stripped = original.replace(" ", "").replace("-", "")
        if not (stripped.isdigit() and len(stripped) == 16):
            raise UnsupportedFormatError("token_type='card' requires a 16-digit value")
        return _generate_card()
    if token_type == "ssn":  # noqa: S105
        stripped = original.replace("-", "")
        if not (stripped.isdigit() and len(stripped) == 9):
            raise UnsupportedFormatError("token_type='ssn' requires a 9-digit value")
        return _generate_ssn()
    if token_type == "digits":  # noqa: S105
        n = _validate_and_length_digits(original)
        return _random_digits(n)
    if token_type == "generic":  # noqa: S105
        return "tok_" + secrets.token_hex(12)
    raise UnsupportedFormatError(
        f"unknown token_type {token_type!r} (expected one of {TOKEN_TYPES})"
    )


def luhn_valid(number: str) -> bool:
    """True if a numeric string passes the Luhn check (used in tests)."""
    digits = [int(c) for c in number if c.isdigit()]
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0
