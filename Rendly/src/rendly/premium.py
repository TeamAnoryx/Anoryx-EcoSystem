"""Premium — a deterministic, fail-closed feature-entitlement seam (R-025 =
FORK A1/B1/C1/D1).

HONESTY BOUNDARY (verbatim, non-removable): "Premium features + monetization (B2C,
via Delta)" ships here as a pure-domain, FAIL-CLOSED feature-GATE model only — no
payment collection, no subscription billing lifecycle (no checkout, no invoice, no
renewal/dunning), and NO wiring to Delta's ledger/budget engine. Real money movement
for a Rendly subscription is its own, separate, still-unshipped cross-product task
(``X-005`` "Rendly <-> Delta monetization wiring", 🏦, "Depends on: R-025, D-003") —
this task IS R-025, one of X-005's two named prerequisites, so building the OTHER
half of that wiring here would be undisclosed scope-widening into a task this run
was not dispatched to do (banked rule 13; also a cross-project write this builder is
not positioned to make — Delta's ledger lives in a different subproject folder).
What IS honestly buildable now, without inventing Delta wiring or a payment
processor integration, is the feature-GATE half: a closed two-tier model
(:class:`PremiumTier`), a revocable, optionally-expiring per-user entitlement record
(:class:`PremiumEntitlement`), and a deterministic access check
(:func:`has_feature_access`) plus two concrete compositions over already-shipped,
already-public limits (:func:`resolve_discovery_feed_limit` over R-024's
``discovery_feed.py``, :func:`resolve_mentorship_match_limit` over R-022's
``mentorship.py``) — this is a deliberate scope-down of R-025 (~10-16h, 🏦
POST-INVESTMENT, tenth task of Rendly's B2C professional-networking tier,
"Depends on: R-004/R-005 + the matching core") to a minimal seam, in the same
spirit as R-012/R-016/R-017/R-018/R-019/R-020/R-021/R-022/R-023/R-024's own scoped
deliveries (see ADR-0025).

NOT BUILT HERE: any payment processor integration (Stripe/etc.), any checkout/
subscription-lifecycle flow, any wiring to Delta's ledger/budget engine (the other
half of X-005, a still-unshipped cross-product task with its own dependencies), any
persistence for ``PremiumEntitlement`` (a caller supplies it each time, mirroring
every prior opt-in-style record in this codebase — ``IntentProfile``/``CareerGoal``/
``TechStackProficiency``/``PrivacySettings``), any REST/wire surface or UI, and any
OPEN/dynamic feature catalog (the feature set is a closed, fixed enum — see Fork B).

FAIL-CLOSED, by construction, not by policy (mirrors ``privacy.py``'s "absence means
deny" discipline, inverted from every OTHER opt-in record in this codebase where
absence means "not eligible to match"): a subject with no ``PremiumEntitlement`` at
all, or an entitlement whose ``expires_at`` has passed as of the caller-supplied
``now``, is always treated as :attr:`PremiumTier.FREE` — never inferred, never
defaulted to premium. There is no "trial" or "grace period" concept; an expired
entitlement is exactly as un-premium as no entitlement at all.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from .common import require_aware_utc
from .discovery_feed import DEFAULT_FEED_LIMIT as _DISCOVERY_FEED_DEFAULT_LIMIT
from .discovery_feed import MAX_FEED_LIMIT as _DISCOVERY_FEED_MAX_LIMIT
from .identifiers import TenantId, UserId
from .mentorship import DEFAULT_MATCH_LIMIT as _MENTORSHIP_DEFAULT_LIMIT
from .mentorship import MAX_SUGGESTIONS as _MENTORSHIP_MAX_LIMIT
from .profile import Profile


class PremiumTier(StrEnum):
    """A closed, ORDERED tier scale (mirrors ``mentorship.ProficiencyLevel``'s
    "order is an explicit mapping, not enum declaration order" discipline — see
    :data:`_TIER_RANK`). Two tiers only: there is no "trial"/"enterprise" tier here
    — a future tier is a new roadmap task, not a silent addition to this one."""

    FREE = "free"
    PREMIUM = "premium"


# The explicit ordering `PremiumTier` itself does not provide (StrEnum has none).
_TIER_RANK: dict[PremiumTier, int] = {
    PremiumTier.FREE: 0,
    PremiumTier.PREMIUM: 1,
}


class PremiumFeature(StrEnum):
    """The FIXED, NAMED set of premium-gated features this seam knows how to
    check. Closed by construction (mirrors ``privacy.PrivacyField``'s "a grant can
    never reference a field this module does not know how to redact" discipline)
    — a caller can never gate on a feature this module cannot resolve, and every
    member here MUST appear in :data:`_FEATURE_MIN_TIER` (enforced by test, not
    just convention)."""

    EXTENDED_DISCOVERY_FEED = "extended_discovery_feed"
    UNLIMITED_MENTORSHIP_MATCHES = "unlimited_mentorship_matches"


# The minimum tier required to use each feature. Every `PremiumFeature` member
# both currently require PREMIUM — there is no free-tier-gated feature yet — but
# the mapping is deliberately keyed PER FEATURE rather than a single hard-coded
# "every feature needs premium" check, so a future feature requiring a different
# minimum tier is a one-line addition here, not a restructuring.
_FEATURE_MIN_TIER: dict[PremiumFeature, PremiumTier] = {
    PremiumFeature.EXTENDED_DISCOVERY_FEED: PremiumTier.PREMIUM,
    PremiumFeature.UNLIMITED_MENTORSHIP_MATCHES: PremiumTier.PREMIUM,
}


class PremiumEntitlement(BaseModel):
    """A user's explicit, revocable, optionally-expiring premium-tier grant.
    Immutable.

    Direct construction with hand-supplied ids is a lower-level primitive (mirrors
    ``TechStackProficiency``'s own reservation) NOT validated against a real
    ``Profile``; :func:`bind_premium_entitlement` is the canonical path.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: UserId
    tenant_id: TenantId
    tier: PremiumTier
    granted_at: datetime
    expires_at: datetime | None = None

    @field_validator("granted_at")
    @classmethod
    def _granted_at_aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "granted_at")

    @field_validator("expires_at")
    @classmethod
    def _expires_at_aware(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return value
        return require_aware_utc(value, "expires_at")

    @model_validator(mode="after")
    def _expiry_after_grant(self) -> "PremiumEntitlement":
        if self.expires_at is not None and self.expires_at <= self.granted_at:
            raise ValueError("expires_at must be strictly after granted_at")
        return self


def bind_premium_entitlement(
    profile: Profile,
    *,
    tier: PremiumTier,
    granted_at: datetime,
    expires_at: datetime | None = None,
) -> PremiumEntitlement:
    """Build a ``PremiumEntitlement`` bound to a real ``Profile`` (the canonical
    path). ``user_id``/``tenant_id`` are read FROM the profile, mirroring
    :func:`rendly.mentorship.bind_tech_stack_proficiency`.
    """
    return PremiumEntitlement(
        user_id=profile.user_id,
        tenant_id=profile.tenant_id,
        tier=tier,
        granted_at=granted_at,
        expires_at=expires_at,
    )


def _require_bound(profile: Profile, entitlement: PremiumEntitlement) -> None:
    if profile.user_id != entitlement.user_id or profile.tenant_id != entitlement.tenant_id:
        raise ValueError("profile/entitlement pair do not describe the same user")


def _effective_tier(entitlement: PremiumEntitlement | None, *, now: datetime) -> PremiumTier:
    if entitlement is None:
        return PremiumTier.FREE
    if entitlement.expires_at is not None and now >= entitlement.expires_at:
        return PremiumTier.FREE
    return entitlement.tier


def has_feature_access(
    profile: Profile,
    entitlement: PremiumEntitlement | None,
    feature: PremiumFeature,
    *,
    now: datetime,
) -> bool:
    """Decide whether ``profile`` currently has access to ``feature``.

    Fail-closed (see module docstring): ``entitlement=None``, or an entitlement
    whose ``expires_at`` is at-or-before ``now``, resolves to
    :attr:`PremiumTier.FREE` — never an inferred premium grant. ``now`` is always
    caller-supplied (mirrors ``event.py``/``event_discovery.py``'s own discipline)
    so this function never reads the wall clock and is fully deterministic given
    its inputs.

    Raises ``ValueError`` (mirrors ``mentorship._require_bound``/
    ``privacy._check_owner``) if a supplied ``entitlement`` does not belong to
    ``profile``.
    """
    if entitlement is not None:
        _require_bound(profile, entitlement)
    tier = _effective_tier(entitlement, now=now)
    return _TIER_RANK[tier] >= _TIER_RANK[_FEATURE_MIN_TIER[feature]]


def resolve_discovery_feed_limit(
    profile: Profile,
    entitlement: PremiumEntitlement | None,
    *,
    now: datetime,
) -> int:
    """Resolve the ``limit`` a caller should pass to
    ``discovery_feed.compose_feed`` for ``profile``: R-024's
    :data:`~rendly.discovery_feed.MAX_FEED_LIMIT` if
    :attr:`PremiumFeature.EXTENDED_DISCOVERY_FEED` is active, else R-024's own
    :data:`~rendly.discovery_feed.DEFAULT_FEED_LIMIT`. Composes ``discovery_feed``'s
    ALREADY-PUBLIC constants — this function does not modify ``discovery_feed.py``.
    """
    if has_feature_access(profile, entitlement, PremiumFeature.EXTENDED_DISCOVERY_FEED, now=now):
        return _DISCOVERY_FEED_MAX_LIMIT
    return _DISCOVERY_FEED_DEFAULT_LIMIT


def resolve_mentorship_match_limit(
    profile: Profile,
    entitlement: PremiumEntitlement | None,
    *,
    now: datetime,
) -> int:
    """Resolve the ``limit`` a caller should pass to ``mentorship.rank_mentors``
    for ``profile``: R-022's :data:`~rendly.mentorship.MAX_SUGGESTIONS` if
    :attr:`PremiumFeature.UNLIMITED_MENTORSHIP_MATCHES` is active, else R-022's own
    :data:`~rendly.mentorship.DEFAULT_MATCH_LIMIT`. Composes ``mentorship``'s
    ALREADY-PUBLIC constants — this function does not modify ``mentorship.py``.
    """
    if has_feature_access(
        profile, entitlement, PremiumFeature.UNLIMITED_MENTORSHIP_MATCHES, now=now
    ):
        return _MENTORSHIP_MAX_LIMIT
    return _MENTORSHIP_DEFAULT_LIMIT
