"""Unit tests for CustomPiiSettings validation (F-028)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from data_protection.custom_pii.config import CustomPiiSettings


def test_defaults():
    s = CustomPiiSettings()
    assert s.custom_pii_enabled is True
    assert s.custom_pii_action == "mask"
    assert s.custom_pii_max_patterns_per_tenant == 50


def test_rejects_bad_action():
    with pytest.raises(ValidationError):
        CustomPiiSettings(custom_pii_action="drop")


def test_rejects_non_positive_ttl():
    with pytest.raises(ValidationError):
        CustomPiiSettings(custom_pii_cache_ttl_seconds=0)


def test_rejects_non_positive_max_patterns():
    with pytest.raises(ValidationError):
        CustomPiiSettings(custom_pii_max_patterns_per_tenant=0)


def test_rejects_non_positive_timeout():
    with pytest.raises(ValidationError):
        CustomPiiSettings(custom_pii_match_timeout_seconds=0)
