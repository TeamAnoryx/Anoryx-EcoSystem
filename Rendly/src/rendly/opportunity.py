"""Opportunity — a deterministic skill-tag matching seam over R-016's existing
``IntentProfile.offering`` field (R-021 = FORK A1/B1/C1/D1).

HONESTY BOUNDARY (verbatim, non-removable): "Skill-based opportunity matching
(freelance + full-time)" ships here as a DETERMINISTIC, SET-INTERSECTION scorer
between a subject's already-shipped ``intent.IntentProfile.offering`` tags (R-016 —
"what I can offer", which a skill genuinely is) and a NEW ``Opportunity`` entity's
``required_skills`` tags — no ML, no resume parsing, no applicant-tracking
workflow, no generated match explanations. This is a deliberate scope-down of
R-021 (~10-16h, 🏦 POST-INVESTMENT, sixth task of Rendly's B2C professional-
networking tier) to a minimal seam, in the same spirit as R-012/R-016/R-017/
R-018/R-020's own scoped deliveries.

"(freelance + full-time)" ships as an INFORMATIONAL, closed ``OpportunityKind``
field only — it does not change matching behavior (no different weighting, no
eligibility rule per kind). A caller that wants freelance-only or full-time-only
results filters ``Opportunity.kind`` itself before or after calling this module's
functions; this module does not build that filtering UI/policy.

NOT BUILT HERE: a new opt-in type for "my skills" — deliberately REUSES R-016's
``IntentProfile.offering`` rather than inventing a parallel skill-tag concept (see
Fork A), because "what I can offer" already IS a skill declaration; persistence
for ``Opportunity`` (a caller supplies it each time, exactly as
``intent.IntentProfile``/``career.CareerGoal`` do); REST/wire surface; any
opportunity-posting workflow (approval, expiry, applicant tracking) — this module
only scores a caller-supplied ``Opportunity`` against a caller-supplied
``IntentProfile``, it does not decide who may post one or how long it stays live.

PRIVACY-CONTROLLED, by construction, not by policy (mirrors ``intent.py``): a user
who has never called ``intent.bind_intent_profile`` has no ``IntentProfile.offering``
and structurally cannot appear as a subject here — every function in this module
requires an explicit ``IntentProfile`` argument.

DELIBERATE DIVERGENCE FROM ``culture.py`` (R-012), consistent WITH ``intent.py``
(R-016)/``career.py`` (R-017): opportunity matching does NOT reject cross-tenant
pairs. Freelance/full-time hiring across companies is definitionally cross-tenant
— the same reasoning as R-016/R-017/R-020 applies unchanged.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

from .common import require_aware_utc
from .identifiers import OpportunityId, TenantId, UserId
from .intent import IntentProfile
from .profile import Profile

# A required-skill tag: short, non-empty, bounded (mirrors intent.py's IntentTag).
RequiredSkill = Annotated[str, StringConstraints(min_length=1, max_length=64)]

# Bounded field discipline (mirrors intent.py's MAX_TAGS): a single opportunity's
# skill list is capped so neither storage (once a follow-up task adds it) nor the
# O(n) intersection below is exposed to an unbounded input.
MAX_REQUIRED_SKILLS = 16

# Bounds the opportunity pool + the result set of a single ranking call (mirrors
# intent.py's/career.py's MAX_CANDIDATES/MAX_SUGGESTIONS at the same magnitudes).
MAX_OPPORTUNITIES = 500
MAX_MATCHES = 50
DEFAULT_MATCH_LIMIT = 10


class OpportunityKind(StrEnum):
    """The two engagement types R-021's task name names, informational only —
    see this module's HONESTY BOUNDARY docstring: this field does not change
    matching behavior."""

    FREELANCE = "freelance"
    FULL_TIME = "full_time"


class Opportunity(BaseModel):
    """A single-poster freelance/full-time role. Immutable.

    Direct construction with hand-supplied ids is a lower-level primitive
    (mirrors ``Event``'s own reservation) NOT validated against a real
    ``Profile``; :func:`bind_opportunity` is the canonical, validated path.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    opportunity_id: OpportunityId
    tenant_id: TenantId
    posted_by: UserId
    title: Annotated[str, StringConstraints(min_length=1, max_length=128)]
    kind: OpportunityKind
    required_skills: tuple[RequiredSkill, ...]
    posted_at: datetime

    @field_validator("posted_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "posted_at")

    @field_validator("required_skills")
    @classmethod
    def _bounded_and_deduped(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_REQUIRED_SKILLS:
            raise ValueError(f"required_skills must not exceed {MAX_REQUIRED_SKILLS} entries")
        if len(set(value)) != len(value):
            raise ValueError("required_skills must not contain duplicates")
        return value


def new_opportunity_id() -> str:
    """Mint a caller-side opportunity id (canonical dashed-hex UUID v4 — matches
    ``identifiers.py``'s wire-mirroring shape, mirrors :func:`rendly.event.new_event_id`)."""
    return str(uuid.uuid4())


def bind_opportunity(
    poster: Profile,
    *,
    title: str,
    kind: OpportunityKind,
    required_skills: Sequence[str],
    posted_at: datetime,
) -> Opportunity:
    """Build an ``Opportunity`` bound to a real ``Profile`` (the canonical path).

    ``posted_by``/``tenant_id`` are read FROM the poster's profile, mirroring
    :func:`rendly.event.bind_event` — an opportunity's identity is derived from
    a validated poster, never hand-supplied.
    """
    return Opportunity(
        opportunity_id=new_opportunity_id(),
        tenant_id=poster.tenant_id,
        posted_by=poster.user_id,
        title=title,
        kind=kind,
        required_skills=tuple(required_skills),
        posted_at=posted_at,
    )


class OpportunityMatch(BaseModel):
    """A single deterministic skill-based opportunity match. Immutable.

    ``matched_skills`` is the intersection of the subject's
    ``IntentProfile.offering`` tags and the opportunity's ``required_skills`` —
    reported (rather than just a bare score) so a future caller can show "why" a
    match was suggested without recomputing it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_user_id: UserId
    subject_tenant_id: TenantId
    opportunity_id: OpportunityId
    opportunity_tenant_id: TenantId
    matched_skills: tuple[str, ...]
    score: int


def suggest_opportunity_match(
    subject_profile: Profile,
    subject_intent: IntentProfile,
    opportunity: Opportunity,
) -> OpportunityMatch | None:
    """Score a single subject/opportunity pair, or ``None`` if no match applies.

    Complementary, set-intersection scoring: what the subject is ``offering``
    (R-016) overlapping what the ``opportunity`` requires. Returns ``None`` (never
    a zero-score match) when there is no overlap.

    Cross-tenant pairs ARE matched — see this module's docstring "DELIBERATE
    DIVERGENCE" section.

    Raises ``ValueError`` (mirrors ``intent.suggest_match``) if
    ``subject_intent`` does not belong to ``subject_profile``.
    """
    if (
        subject_profile.user_id != subject_intent.user_id
        or subject_profile.tenant_id != subject_intent.tenant_id
    ):
        raise ValueError("subject profile/intent pair do not describe the same user")

    matched = sorted(set(subject_intent.offering) & set(opportunity.required_skills))
    if not matched:
        return None

    return OpportunityMatch(
        subject_user_id=subject_profile.user_id,
        subject_tenant_id=subject_profile.tenant_id,
        opportunity_id=opportunity.opportunity_id,
        opportunity_tenant_id=opportunity.tenant_id,
        matched_skills=tuple(matched),
        score=len(matched),
    )


def rank_opportunities(
    subject_profile: Profile,
    subject_intent: IntentProfile,
    opportunities: Sequence[Opportunity],
    *,
    limit: int = DEFAULT_MATCH_LIMIT,
) -> list[OpportunityMatch]:
    """Rank skill-based opportunity matches for ``subject`` against a pool.

    Deterministic: ties break on ``opportunity_id`` ascending, so the same input
    always produces the same output (mirrors ``intent.rank_matches``). ``limit``
    is clamped to ``[0, MAX_MATCHES]``; ``opportunities`` beyond
    ``MAX_OPPORTUNITIES`` is rejected outright rather than silently truncated.

    This function does no I/O and does NOT de-duplicate ``opportunities`` by
    ``opportunity_id`` — a caller passing the same opportunity twice gets it
    scored (and possibly listed) twice, mirrors ``intent.rank_matches``.
    """
    if len(opportunities) > MAX_OPPORTUNITIES:
        raise ValueError(f"opportunities must not exceed {MAX_OPPORTUNITIES} entries")
    bounded_limit = max(0, min(limit, MAX_MATCHES))

    matches = [
        match
        for opportunity in opportunities
        if (match := suggest_opportunity_match(subject_profile, subject_intent, opportunity))
        is not None
    ]
    matches.sort(key=lambda m: (-m.score, m.opportunity_id))
    return matches[:bounded_limit]
