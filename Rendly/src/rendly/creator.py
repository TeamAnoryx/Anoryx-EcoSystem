"""Creator — a deterministic, tier-gated revenue-share ALLOCATION seam for
Rendly's creator economy (R-026 = FORK A1/B1/C1).

HONESTY BOUNDARY (verbatim, non-removable): "Creator economy features" ships
here as a pure, closed-form percentage-split ALLOCATION over a caller-supplied,
already-computed total amount — expressed as an integer MINOR-UNIT count,
mirroring Delta's own "money is integer minor units, never floats" invariant
even though this domain sits entirely inside Rendly and never touches Delta's
ledger — into a creator share and a platform share, gated by the creator's
EXISTING R-025 ``PremiumEntitlement``/``PremiumTier`` (composes ``premium.py``
by adding ONE new closed ``PremiumFeature`` member,
``CREATOR_REVENUE_SHARE_BOOST``, plus its ``_FEATURE_MIN_TIER`` entry — an
addition ``premium.py``'s own docstring already invited: "a future feature
requiring a different minimum tier is a one-line addition here, not a
restructuring" — no other change to ``premium.py``, and neither of its two
existing R-025 features/compositions is touched).

This is a deliberate scope-down of R-026 (~10-16h, 🏦 POST-INVESTMENT, eleventh
and final task of Rendly's B2C professional-networking tier, "Depends on:
R-004/R-005 + the matching core") to a minimal seam, in the same spirit as
R-012/R-016 through R-025's own scoped deliveries (see ADR-0026).

NOT BUILT HERE: any real payment collection, payout, or transfer of funds (this
module never moves money — it only ever splits a caller-supplied integer total
into two caller-facing numbers); any content hosting/publishing surface (posts,
media, tipping UI); any follower/subscriber relationship or persistence; any
wiring to Delta's ledger/budget engine (real money movement remains a future,
separate, still-unshipped cross-product task, in the same spirit as R-025's own
X-005 deferral — Rendly's builder has no write access to Delta's ledger in any
case); any REST/wire surface or UI; and any dynamic/ops-configurable
split-percentage catalog (the two tiers' percentages are a small closed table,
expressed in basis points, never a runtime-editable config — mirrors
``premium.py``'s own Fork B rejection of an open feature catalog).
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, model_validator

from .identifiers import TenantId, UserId
from .premium import PremiumEntitlement, PremiumFeature, PremiumTier, has_feature_access
from .profile import Profile

# Basis-points scale (1 bp = 0.01%) — an integer percentage representation so no
# float ever enters a money-shaped calculation, mirroring Delta's own "money is
# integer minor units, never floats" discipline, extended here to percentages.
_BPS_SCALE = 10_000

# The closed, fixed revenue-share table. FREE creators keep the base share; an
# active CREATOR_REVENUE_SHARE_BOOST entitlement (PREMIUM tier, composed via
# `premium.has_feature_access`) raises the creator's share. Neither number is
# runtime-configurable (see module docstring; mirrors `premium.py`'s own
# rejection of an open/dynamic feature catalog).
_BASE_CREATOR_SHARE_BPS = 7_000  # 70% creator / 30% platform
_BOOSTED_CREATOR_SHARE_BPS = 8_500  # 85% creator / 15% platform

# Defense-in-depth sanity ceiling on a single allocation (mirrors
# `discovery_feed.MAX_ITEMS_PER_TYPE`'s own "bound the input, don't silently
# accept anything" discipline) — not a real-world revenue ceiling, just a guard
# against a caller passing a nonsensical/overflow-shaped value.
MAX_ALLOCATABLE_MINOR_UNITS = 10**15


class CreatorEarningsAllocation(BaseModel):
    """The result of splitting one caller-supplied total between a creator and
    the platform. Immutable.

    ``creator_share_minor_units + platform_share_minor_units`` always equals
    ``total_minor_units`` exactly (the integer-division remainder is assigned
    to the platform share — see :func:`allocate_creator_earnings`, ADR-0026
    Fork D) — this model can never represent a split that loses or invents a
    minor unit, enforced structurally, not just by the function that builds it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: UserId
    tenant_id: TenantId
    total_minor_units: int
    creator_share_minor_units: int
    platform_share_minor_units: int
    tier_applied: PremiumTier

    @model_validator(mode="after")
    def _shares_are_non_negative_and_sum_to_total(self) -> "CreatorEarningsAllocation":
        if self.creator_share_minor_units < 0 or self.platform_share_minor_units < 0:
            raise ValueError("shares must be non-negative")
        if (
            self.creator_share_minor_units + self.platform_share_minor_units
            != self.total_minor_units
        ):
            raise ValueError(
                "creator_share_minor_units + platform_share_minor_units "
                "must equal total_minor_units"
            )
        return self


def allocate_creator_earnings(
    profile: Profile,
    entitlement: PremiumEntitlement | None,
    total_minor_units: int,
    *,
    now: datetime,
) -> CreatorEarningsAllocation:
    """Split ``total_minor_units`` between ``profile`` (the creator) and the
    platform, using the closed two-tier basis-point table (see module
    docstring). ``total_minor_units`` is a caller-supplied integer already
    computed elsewhere — this function does not source, collect, or move any
    money; it is pure computation over its inputs.

    Raises ``ValueError`` if ``total_minor_units`` is negative or exceeds
    :data:`MAX_ALLOCATABLE_MINOR_UNITS`, or if ``entitlement`` (when supplied)
    does not belong to ``profile`` (delegated to
    :func:`rendly.premium.has_feature_access`).

    The creator's share is computed as ``total * share_bps // 10_000`` (floor
    division); the platform share is ``total - creator_share`` so the two
    ALWAYS sum to ``total_minor_units`` exactly — the integer-division
    remainder always lands on the platform side, never the creator's (ADR-0026
    Fork D: conservative-by-default, never round a creator UP beyond what the
    exact percentage implies).
    """
    if total_minor_units < 0:
        raise ValueError("total_minor_units must be non-negative")
    if total_minor_units > MAX_ALLOCATABLE_MINOR_UNITS:
        raise ValueError(f"total_minor_units must not exceed {MAX_ALLOCATABLE_MINOR_UNITS}")

    boosted = has_feature_access(
        profile, entitlement, PremiumFeature.CREATOR_REVENUE_SHARE_BOOST, now=now
    )
    tier_applied = PremiumTier.PREMIUM if boosted else PremiumTier.FREE
    share_bps = _BOOSTED_CREATOR_SHARE_BPS if boosted else _BASE_CREATOR_SHARE_BPS

    creator_share = (total_minor_units * share_bps) // _BPS_SCALE
    platform_share = total_minor_units - creator_share

    return CreatorEarningsAllocation(
        user_id=profile.user_id,
        tenant_id=profile.tenant_id,
        total_minor_units=total_minor_units,
        creator_share_minor_units=creator_share,
        platform_share_minor_units=platform_share,
        tier_applied=tier_applied,
    )
