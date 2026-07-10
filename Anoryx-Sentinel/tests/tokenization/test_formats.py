"""Unit tests for F-033 format-preserving surrogate generation (no DB/crypto)."""

from __future__ import annotations

import pytest

from tokenization.exceptions import UnsupportedFormatError
from tokenization.formats import generate_surrogate, luhn_valid


def test_card_token_is_16_digits_and_luhn_valid():
    tok = generate_surrogate("card", "4111111111111111")
    assert len(tok) == 16 and tok.isdigit()
    assert luhn_valid(tok)


def test_card_rejects_non_16_digit():
    with pytest.raises(UnsupportedFormatError):
        generate_surrogate("card", "12345")


def test_ssn_token_shape_preserved():
    tok = generate_surrogate("ssn", "123-45-6789")
    assert len(tok) == 11
    parts = tok.split("-")
    assert [len(p) for p in parts] == [3, 2, 4]
    assert all(p.isdigit() for p in parts)


def test_ssn_accepts_undashed_9_digits():
    tok = generate_surrogate("ssn", "123456789")
    assert tok.count("-") == 2


def test_ssn_rejects_wrong_length():
    with pytest.raises(UnsupportedFormatError):
        generate_surrogate("ssn", "12345")


def test_digits_preserves_length():
    tok = generate_surrogate("digits", "0001112223")
    assert len(tok) == 10 and tok.isdigit()


def test_digits_rejects_non_digits():
    with pytest.raises(UnsupportedFormatError):
        generate_surrogate("digits", "abc")


def test_generic_token_prefix():
    tok = generate_surrogate("generic", "anything at all")
    assert tok.startswith("tok_")


def test_unknown_type_rejected():
    with pytest.raises(UnsupportedFormatError):
        generate_surrogate("passport", "X1234567")


def test_surrogates_are_random_not_the_original():
    # random surrogate: two tokenizations differ and neither equals the input
    t1 = generate_surrogate("card", "4111111111111111")
    t2 = generate_surrogate("card", "4111111111111111")
    assert t1 != t2
    assert t1 != "4111111111111111"
