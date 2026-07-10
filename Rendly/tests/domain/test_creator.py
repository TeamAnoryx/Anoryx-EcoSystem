"""R-026: the creator-economy revenue-share allocation seam (creator.py)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from rendly.creator import (
    MAX_ALLOCATABLE_MINOR_UNITS,
    CreatorEarningsAllocation,
    allocate_creator_earnings,
)
from rendly.enums import OrgRole
from rendly.premium import PremiumTier, bind_premium_entitlement
from rendly.profile import Profile

_NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_USER = "11111111-1111-4111-8111-111111111111"
_OTHER = "99999999-9999-4999-8999-999999999999"


def _profile(user_id: str = _USER, tenant_id: str = _TENANT) -> Profile:
    return Profile(user_id=user_id, tenant_id=tenant_id, org_role=OrgRole.MEMBER)


def _premium_entitlement(*, expires_at=None):
    return bind_premium_entitlement(
        _profile(), tier=PremiumTier.PREMIUM, granted_at=_NOW, expires_at=expires_at
    )


def _free_entitlement():
    return bind_premium_entitlement(_profile(), tier=PremiumTier.FREE, granted_at=_NOW)


# --- base (no/expired/free entitlement) split -------------------------------------------------


def test_allocates_base_split_without_entitlement():
    allocation = allocate_creator_earnings(_profile(), None, 10_000, now=_NOW)
    assert allocation.creator_share_minor_units == 7_000
    assert allocation.platform_share_minor_units == 3_000
    assert allocation.tier_applied is PremiumTier.FREE


def test_allocates_base_split_with_free_tier_entitlement():
    allocation = allocate_creator_earnings(_profile(), _free_entitlement(), 10_000, now=_NOW)
    assert allocation.creator_share_minor_units == 7_000
    assert allocation.tier_applied is PremiumTier.FREE


def test_allocates_base_split_after_premium_expiry():
    premium = _premium_entitlement(expires_at=_NOW + timedelta(days=30))
    after_expiry = _NOW + timedelta(days=31)
    allocation = allocate_creator_earnings(_profile(), premium, 10_000, now=after_expiry)
    assert allocation.creator_share_minor_units == 7_000
    assert allocation.tier_applied is PremiumTier.FREE


# --- boosted (active premium) split ------------------------------------------------------------


def test_allocates_boosted_split_with_active_premium():
    allocation = allocate_creator_earnings(_profile(), _premium_entitlement(), 10_000, now=_NOW)
    assert allocation.creator_share_minor_units == 8_500
    assert allocation.platform_share_minor_units == 1_500
    assert allocation.tier_applied is PremiumTier.PREMIUM


def test_allocates_boosted_split_just_before_expiry():
    expires_at = _NOW + timedelta(days=30)
    premium = _premium_entitlement(expires_at=expires_at)
    just_before = expires_at - timedelta(seconds=1)
    allocation = allocate_creator_earnings(_profile(), premium, 10_000, now=just_before)
    assert allocation.tier_applied is PremiumTier.PREMIUM


def test_allocates_base_split_exactly_at_expiry():
    expires_at = _NOW + timedelta(days=30)
    premium = _premium_entitlement(expires_at=expires_at)
    allocation = allocate_creator_earnings(_profile(), premium, 10_000, now=expires_at)
    assert allocation.tier_applied is PremiumTier.FREE


# --- shares always sum exactly to the total, remainder favors the platform --------------------


@pytest.mark.parametrize("total", [0, 1, 3, 7, 9_999, 10_000, 10_001, 123_456_789])
def test_shares_always_sum_to_total_free(total):
    allocation = allocate_creator_earnings(_profile(), None, total, now=_NOW)
    assert allocation.creator_share_minor_units + allocation.platform_share_minor_units == total


@pytest.mark.parametrize("total", [0, 1, 3, 7, 9_999, 10_000, 10_001, 123_456_789])
def test_shares_always_sum_to_total_premium(total):
    allocation = allocate_creator_earnings(_profile(), _premium_entitlement(), total, now=_NOW)
    assert allocation.creator_share_minor_units + allocation.platform_share_minor_units == total


def test_remainder_lands_on_platform_not_creator():
    # 1 minor unit at 70% floors to 0 for the creator; the whole unit must still
    # be accounted for, and it must land on the platform side (never invented,
    # never lost, never rounded up in the creator's favor).
    allocation = allocate_creator_earnings(_profile(), None, 1, now=_NOW)
    assert allocation.creator_share_minor_units == 0
    assert allocation.platform_share_minor_units == 1


def test_zero_total_allocates_zero_to_both():
    allocation = allocate_creator_earnings(_profile(), None, 0, now=_NOW)
    assert allocation.creator_share_minor_units == 0
    assert allocation.platform_share_minor_units == 0


# --- input validation ---------------------------------------------------------------------------


def test_rejects_negative_total():
    with pytest.raises(ValueError, match="non-negative"):
        allocate_creator_earnings(_profile(), None, -1, now=_NOW)


def test_rejects_total_above_ceiling():
    with pytest.raises(ValueError, match="must not exceed"):
        allocate_creator_earnings(_profile(), None, MAX_ALLOCATABLE_MINOR_UNITS + 1, now=_NOW)


def test_accepts_total_at_ceiling():
    allocation = allocate_creator_earnings(_profile(), None, MAX_ALLOCATABLE_MINOR_UNITS, now=_NOW)
    assert (
        allocation.creator_share_minor_units + allocation.platform_share_minor_units
        == MAX_ALLOCATABLE_MINOR_UNITS
    )


def test_rejects_entitlement_for_a_different_user():
    premium = _premium_entitlement()
    with pytest.raises(ValueError, match="do not describe the same user"):
        allocate_creator_earnings(_profile(_OTHER), premium, 10_000, now=_NOW)


# --- CreatorEarningsAllocation structural invariants --------------------------------------------


def test_allocation_rejects_shares_that_do_not_sum_to_total():
    with pytest.raises(ValidationError, match="must equal total_minor_units"):
        CreatorEarningsAllocation(
            user_id=_USER,
            tenant_id=_TENANT,
            total_minor_units=100,
            creator_share_minor_units=60,
            platform_share_minor_units=30,
            tier_applied=PremiumTier.FREE,
        )


def test_allocation_rejects_negative_share():
    with pytest.raises(ValidationError, match="non-negative"):
        CreatorEarningsAllocation(
            user_id=_USER,
            tenant_id=_TENANT,
            total_minor_units=100,
            creator_share_minor_units=-10,
            platform_share_minor_units=110,
            tier_applied=PremiumTier.FREE,
        )


def test_allocation_is_frozen():
    allocation = allocate_creator_earnings(_profile(), None, 10_000, now=_NOW)
    with pytest.raises(ValidationError):
        allocation.creator_share_minor_units = 9_999
