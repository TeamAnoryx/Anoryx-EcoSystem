"""R-025: the premium feature-entitlement seam (premium.py)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from rendly.discovery_feed import DEFAULT_FEED_LIMIT, MAX_FEED_LIMIT
from rendly.enums import OrgRole
from rendly.mentorship import DEFAULT_MATCH_LIMIT, MAX_SUGGESTIONS
from rendly.premium import (
    PremiumEntitlement,
    PremiumFeature,
    PremiumTier,
    bind_premium_entitlement,
    has_feature_access,
    resolve_discovery_feed_limit,
    resolve_mentorship_match_limit,
)
from rendly.profile import Profile

_NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_USER = "11111111-1111-4111-8111-111111111111"
_OTHER = "99999999-9999-4999-8999-999999999999"


def _profile(user_id: str = _USER, tenant_id: str = _TENANT) -> Profile:
    return Profile(user_id=user_id, tenant_id=tenant_id, org_role=OrgRole.MEMBER)


def _premium_entitlement(*, expires_at=None) -> PremiumEntitlement:
    return bind_premium_entitlement(
        _profile(), tier=PremiumTier.PREMIUM, granted_at=_NOW, expires_at=expires_at
    )


# --- PremiumEntitlement structural invariants -----------------------------------------------


def test_entitlement_rejects_naive_granted_at():
    with pytest.raises(ValidationError, match="granted_at"):
        PremiumEntitlement(
            user_id=_USER,
            tenant_id=_TENANT,
            tier=PremiumTier.PREMIUM,
            granted_at=datetime(2026, 7, 10, 12, 0, 0),
        )


def test_entitlement_rejects_naive_expires_at():
    with pytest.raises(ValidationError, match="expires_at"):
        PremiumEntitlement(
            user_id=_USER,
            tenant_id=_TENANT,
            tier=PremiumTier.PREMIUM,
            granted_at=_NOW,
            expires_at=datetime(2026, 8, 10, 12, 0, 0),
        )


def test_entitlement_rejects_expiry_at_or_before_grant():
    with pytest.raises(ValidationError, match="expires_at must be strictly after"):
        PremiumEntitlement(
            user_id=_USER,
            tenant_id=_TENANT,
            tier=PremiumTier.PREMIUM,
            granted_at=_NOW,
            expires_at=_NOW,
        )


def test_bind_premium_entitlement_derives_ids_from_profile():
    entitlement = bind_premium_entitlement(_profile(), tier=PremiumTier.PREMIUM, granted_at=_NOW)
    assert entitlement.user_id == _USER
    assert entitlement.tenant_id == _TENANT


# --- has_feature_access: fail-closed defaults -----------------------------------------------


def test_has_feature_access_denies_when_entitlement_is_none():
    assert (
        has_feature_access(_profile(), None, PremiumFeature.EXTENDED_DISCOVERY_FEED, now=_NOW)
        is False
    )


def test_has_feature_access_denies_free_tier():
    free = bind_premium_entitlement(_profile(), tier=PremiumTier.FREE, granted_at=_NOW)
    assert (
        has_feature_access(_profile(), free, PremiumFeature.EXTENDED_DISCOVERY_FEED, now=_NOW)
        is False
    )


def test_has_feature_access_grants_active_premium():
    premium = _premium_entitlement()
    assert (
        has_feature_access(_profile(), premium, PremiumFeature.EXTENDED_DISCOVERY_FEED, now=_NOW)
        is True
    )


def test_has_feature_access_grants_both_closed_features_for_premium():
    premium = _premium_entitlement()
    for feature in PremiumFeature:
        assert has_feature_access(_profile(), premium, feature, now=_NOW) is True


# --- has_feature_access: expiry ---------------------------------------------------------------


def test_has_feature_access_denies_after_expiry():
    premium = _premium_entitlement(expires_at=_NOW + timedelta(days=30))
    after_expiry = _NOW + timedelta(days=31)
    assert (
        has_feature_access(
            _profile(), premium, PremiumFeature.EXTENDED_DISCOVERY_FEED, now=after_expiry
        )
        is False
    )


def test_has_feature_access_denies_exactly_at_expiry():
    expires_at = _NOW + timedelta(days=30)
    premium = _premium_entitlement(expires_at=expires_at)
    assert (
        has_feature_access(
            _profile(), premium, PremiumFeature.EXTENDED_DISCOVERY_FEED, now=expires_at
        )
        is False
    )


def test_has_feature_access_grants_just_before_expiry():
    expires_at = _NOW + timedelta(days=30)
    premium = _premium_entitlement(expires_at=expires_at)
    just_before = expires_at - timedelta(seconds=1)
    assert (
        has_feature_access(
            _profile(), premium, PremiumFeature.EXTENDED_DISCOVERY_FEED, now=just_before
        )
        is True
    )


def test_has_feature_access_grants_with_no_expiry():
    premium = _premium_entitlement(expires_at=None)
    far_future = _NOW + timedelta(days=3650)
    assert (
        has_feature_access(
            _profile(), premium, PremiumFeature.EXTENDED_DISCOVERY_FEED, now=far_future
        )
        is True
    )


# --- has_feature_access: cross-checking -------------------------------------------------------


def test_has_feature_access_rejects_entitlement_for_a_different_user():
    premium = _premium_entitlement()
    with pytest.raises(ValueError, match="do not describe the same user"):
        has_feature_access(
            _profile(_OTHER), premium, PremiumFeature.EXTENDED_DISCOVERY_FEED, now=_NOW
        )


def test_has_feature_access_rejects_entitlement_for_a_different_tenant():
    premium = _premium_entitlement()
    with pytest.raises(ValueError, match="do not describe the same user"):
        has_feature_access(
            _profile(_USER, "22222222-2222-4222-8222-222222222222"),
            premium,
            PremiumFeature.EXTENDED_DISCOVERY_FEED,
            now=_NOW,
        )


# --- resolve_discovery_feed_limit / resolve_mentorship_match_limit ---------------------------


def test_resolve_discovery_feed_limit_is_default_without_entitlement():
    assert resolve_discovery_feed_limit(_profile(), None, now=_NOW) == DEFAULT_FEED_LIMIT


def test_resolve_discovery_feed_limit_is_max_with_active_premium():
    premium = _premium_entitlement()
    assert resolve_discovery_feed_limit(_profile(), premium, now=_NOW) == MAX_FEED_LIMIT


def test_resolve_discovery_feed_limit_falls_back_after_expiry():
    premium = _premium_entitlement(expires_at=_NOW + timedelta(days=1))
    after = _NOW + timedelta(days=2)
    assert resolve_discovery_feed_limit(_profile(), premium, now=after) == DEFAULT_FEED_LIMIT


def test_resolve_mentorship_match_limit_is_default_without_entitlement():
    assert resolve_mentorship_match_limit(_profile(), None, now=_NOW) == DEFAULT_MATCH_LIMIT


def test_resolve_mentorship_match_limit_is_max_with_active_premium():
    premium = _premium_entitlement()
    assert resolve_mentorship_match_limit(_profile(), premium, now=_NOW) == MAX_SUGGESTIONS


def test_resolve_limits_never_regress_below_default():
    # Sanity invariant: whatever the tier, the resolved limit is never below the
    # free-tier default and never above the max — no configuration can produce an
    # out-of-band value.
    for entitlement in (None, _premium_entitlement()):
        assert (
            DEFAULT_FEED_LIMIT
            <= resolve_discovery_feed_limit(_profile(), entitlement, now=_NOW)
            <= MAX_FEED_LIMIT
        )
        assert (
            DEFAULT_MATCH_LIMIT
            <= resolve_mentorship_match_limit(_profile(), entitlement, now=_NOW)
            <= MAX_SUGGESTIONS
        )


# --- closed feature set is fully covered ------------------------------------------------------


def test_every_premium_feature_has_a_minimum_tier_mapping():
    # Import the private mapping only to assert the closed-set invariant the module
    # docstring promises: every enum member is resolvable, none silently falls through.
    from rendly.premium import _FEATURE_MIN_TIER

    for feature in PremiumFeature:
        assert feature in _FEATURE_MIN_TIER
