"""Unit tests for the F-028 pattern validator (registration-time regex safety)."""

from __future__ import annotations

import pytest

from data_protection.custom_pii.exceptions import InvalidPattern, InvalidPatternName
from data_protection.custom_pii.validator import normalize_name, validate_pattern


class TestNormalizeName:
    def test_uppercases_and_accepts(self):
        assert normalize_name("employee_id") == "EMPLOYEE_ID"

    def test_hyphen_and_space_become_underscore(self):
        assert normalize_name("emp-id number") == "EMP_ID_NUMBER"

    def test_rejects_leading_digit(self):
        with pytest.raises(InvalidPatternName):
            normalize_name("1account")

    def test_rejects_empty(self):
        with pytest.raises(InvalidPatternName):
            normalize_name("")

    def test_rejects_too_long(self):
        with pytest.raises(InvalidPatternName):
            normalize_name("A" * 65)


class TestValidatePattern:
    def test_accepts_simple_pattern(self):
        validate_pattern(r"EMP-\d{6}", max_length=512)  # no raise

    def test_rejects_empty(self):
        with pytest.raises(InvalidPattern):
            validate_pattern("", max_length=512)

    def test_rejects_over_max_length(self):
        with pytest.raises(InvalidPattern):
            validate_pattern("a" * 513, max_length=512)

    def test_rejects_uncompilable(self):
        with pytest.raises(InvalidPattern):
            validate_pattern(r"EMP-(\d{6}", max_length=512)  # unbalanced paren

    def test_rejects_nested_quantifier_redos_shape(self):
        with pytest.raises(InvalidPattern):
            validate_pattern(r"(a+)+$", max_length=512)

    def test_rejects_star_of_star(self):
        with pytest.raises(InvalidPattern):
            validate_pattern(r"(a*)*", max_length=512)
