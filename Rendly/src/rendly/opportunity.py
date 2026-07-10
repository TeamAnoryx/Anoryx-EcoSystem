"""Opportunity — a deterministic skill-overlap matching seam over R-016's
intent-matching core (R-021 = FORK A1/B1/C1/D1).

HONESTY BOUNDARY (verbatim, non-removable): "Skill-based opportunity matching
(freelance + full-time)" in the roadmap's task name is NOT implemented here as
a job board, an application pipeline, or a resume/parsing engine. What ships
is a deterministic SKILL-OVERLAP scorer (:func:`suggest_opportunity_match` /
:func:`rank_opportunities`) between a caller-supplied :class:`Opportunity`
posting's ``required_skills`` and a subject's already-shipped R-016
``IntentProfile.offering`` tags — exactly the composition ADR-0016 and
ADR-0017 both named R-021 as the natural future consumer of ("skill TAGS...
R-021 skill-based opportunity matching"). This is a deliberate scope-down of
R-021 (~10-16h, 🏦 POST-INVESTMENT, sixth task of Rendly's B2C professional-
networking tier, "Depends on: R-004/R-005 + the matching core") to a minimal
seam, in the same spirit as R-012/R-016/R-017/R-018/R-019/R-020's own scoped
deliveries (see ADR-0016 §Decision, ADR-0017 §Decision).

NOT BUILT HERE (mirrors ADR-0016's/ADR-0017's/ADR-0020's own lists): a real
job board / listings marketplace, an application or hiring workflow, resume
parsing or any generated/learned relevance signal, real B2C consumer
identity/onboarding (R-023, still unshipped — this module operates over the
EXISTING enterprise ``Profile`` domain (R-002) as a placeholder actor model,
exactly as R-012/R-016/R-017/R-018/R-020 did). No persistence, no REST/wire
surface, no ML.

PRIVACY-CONTROLLED, by construction, not by policy (mirrors ``intent.py``):
a match can only be computed for a subject who has opted into R-016's
``IntentProfile`` — a subject who has not carries no ``offering`` skill set to
score against, so this module requires ``subject_intent`` as a mandatory
(not optional) argument, unlike ``event_discovery.discover_events`` where
topic ranking was one of two independent inclusion axes. There is no locality-
style "browse with no signal at all" mode here: skill overlap IS the entire
basis of a match, so a subject with an empty ``offering`` tuple simply matches
nothing, which is the honest outcome.

DELIBERATE DIVERGENCE FROM ``event_discovery.discover_events``'s "zero-score
still included" rule, CONSISTENT WITH ``intent.suggest_match`` / ``career.
suggest_trajectory_match`` / ``peer.suggest_peer``'s "never a zero-score
result" rule: :func:`suggest_opportunity_match` returns ``None`` when there is
no skill overlap. Event discovery models locality-based BROWSING, where
"nearby, no shared topics" is still a meaningful result; opportunity matching
models a PAIRWISE relevance signal between a person's skills and a specific
posting, where zero overlap is honestly "not a match," not "a match with a
zero score" (mirrors this tier's majority precedent).

DELIBERATE DIVERGENCE FROM ``culture.py`` (R-012), consistent WITH
``intent.py`` (R-016): opportunity matching does NOT reject cross-tenant
pairs. A freelance/full-time opportunity is definitionally open to candidates
outside the posting tenant (see ADR-0016 Fork B) — the same reasoning applies
unchanged.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

from .common import require_aware_utc
from .identifiers import OpportunityId, TenantId, UserId
from .intent import IntentProfile
from .profile import Profile

# A required-skill tag: short, non-empty, bounded (mirrors `intent.py`'s `IntentTag`).
# Matched directly against `IntentProfile.offering` — the same opaque, case-sensitive,
# unnormalized tag discipline this codebase already uses throughout this tier.
SkillTag = Annotated[str, StringConstraints(min_length=1, max_length=64)]

# Bounded field discipline (mirrors `intent.MAX_TAGS`): a posting's skill list is
# capped so neither storage (once a follow-up task adds it) nor the per-candidate
# scorer below is exposed to an unbounded input.
MAX_SKILLS = 16

# Bounds the candidate pool + the result set of a single ranking call (mirrors
# `intent.MAX_CANDIDATES`/`MAX_SUGGESTIONS`) — a DoS/cost guard on the scorer, not a
# product decision about "how many opportunities are useful."
MAX_CANDIDATES = 500
MAX_SUGGESTIONS = 50
DEFAULT_MATCH_LIMIT = 10


class EmploymentType(StrEnum):
    """The two kinds of opportunity this task's title names — "freelance +
    full-time" — and nothing else. A closed, fixed enum (mirrors ``career.py``'s
    own module-scoped ``OptimizationGap``), kept local to this module rather than
    in the shared ``enums.py`` because it is not reconciled with any wire contract
    (``enums.py``'s own docstring reserves that file for R-001-wire-matching
    enums plus ``OrgRole``) — this is a new, additive, pure-domain concept.
    """

    FREELANCE = "freelance"
    FULL_TIME = "full_time"


class Opportunity(BaseModel):
    """A freelance-or-full-time role posting. Immutable.

    Direct ``Opportunity(...)`` construction with hand-supplied ids is a
    lower-level primitive NOT validated against a real ``Profile`` (mirrors every
    other opt-in-style record in this codebase); :func:`bind_opportunity` is the
    canonical, validated path. ``required_skills`` is an opaque tag set matched
    directly against a subject's ``IntentProfile.offering`` — see module docstring.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    opportunity_id: OpportunityId
    tenant_id: TenantId
    posted_by_user_id: UserId
    employment_type: EmploymentType
    required_skills: tuple[SkillTag, ...]
    posted_at: datetime

    @field_validator("posted_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "posted_at")

    @field_validator("required_skills")
    @classmethod
    def _bounded_and_deduped(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_SKILLS:
            raise ValueError(f"required_skills must not exceed {MAX_SKILLS} tags")
        if len(set(value)) != len(value):
            raise ValueError("required_skills must not contain duplicates")
        return value


def bind_opportunity(
    poster_profile: Profile,
    *,
    opportunity_id: str,
    employment_type: EmploymentType,
    required_skills: Sequence[str],
    posted_at: datetime,
) -> Opportunity:
    """Build an ``Opportunity`` bound to a real ``Profile`` (the canonical path).

    ``posted_by_user_id``/``tenant_id`` are read FROM the profile, mirroring
    :func:`rendly.event.bind_event` — a posting's identity is derived from a
    validated poster, never hand-supplied. Unlike ``bind_event`` this module does
    not mint its own id (no ``new_opportunity_id`` helper is added): the caller
    already owns id generation for this pure-domain record, exactly as
    ``intent.bind_intent_profile``/``career.bind_career_goal`` mint no id of
    their own (neither has an independent identity beyond its owning user).
    """
    return Opportunity(
        opportunity_id=opportunity_id,
        tenant_id=poster_profile.tenant_id,
        posted_by_user_id=poster_profile.user_id,
        employment_type=employment_type,
        required_skills=tuple(required_skills),
        posted_at=posted_at,
    )


class OpportunityMatch(BaseModel):
    """A single deterministic skill-overlap opportunity match. Immutable.

    ``matched_skills`` is the subset of ``opportunity.required_skills`` the
    subject's ``IntentProfile.offering`` covers — reported (rather than just a
    combined score) so a future caller can show "why" a match was suggested
    without recomputing it. ``score`` is always ``len(matched_skills)`` — never
    computed independently, so it can never disagree (mirrors
    ``intent.IntentMatch``'s same discipline).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_user_id: UserId
    subject_tenant_id: TenantId
    opportunity_id: OpportunityId
    opportunity_tenant_id: TenantId
    employment_type: EmploymentType
    matched_skills: tuple[SkillTag, ...]
    score: int


def suggest_opportunity_match(
    subject_profile: Profile,
    subject_intent: IntentProfile,
    opportunity: Opportunity,
) -> OpportunityMatch | None:
    """Score a single subject/opportunity pair, or ``None`` if no match applies.

    A match exists when the subject's ``IntentProfile.offering`` overlaps the
    opportunity's ``required_skills`` — "skill-based" matching on what the
    subject can DO, not a request/offer complementary pair (``intent.
    suggest_match``'s own model): an opportunity does not itself "offer" or
    "seek" tags, it simply REQUIRES skills, so this is a plain set-intersection
    scorer, not a directional one.

    Returns ``None`` (never a zero-score match, see module docstring) when:
    - the subject IS the opportunity's poster (no self-match, mirrors every
      other ``suggest_*`` function in this codebase),
    - there is no skill overlap at all.

    Cross-tenant pairs ARE matched — see this module's docstring "DELIBERATE
    DIVERGENCE" section.

    Raises ``ValueError`` (refuses to compute, mirrors ``intent.suggest_match``)
    if ``subject_profile``/``subject_intent`` do not describe the same user.
    """
    if subject_profile.user_id != subject_intent.user_id or (
        subject_profile.tenant_id != subject_intent.tenant_id
    ):
        raise ValueError("subject profile/intent pair do not describe the same user")

    if subject_profile.user_id == opportunity.posted_by_user_id:
        return None

    matched = sorted(set(subject_intent.offering) & set(opportunity.required_skills))
    if not matched:
        return None

    return OpportunityMatch(
        subject_user_id=subject_profile.user_id,
        subject_tenant_id=subject_profile.tenant_id,
        opportunity_id=opportunity.opportunity_id,
        opportunity_tenant_id=opportunity.tenant_id,
        employment_type=opportunity.employment_type,
        matched_skills=tuple(matched),
        score=len(matched),
    )


def rank_opportunities(
    subject_profile: Profile,
    subject_intent: IntentProfile,
    candidates: Sequence[Opportunity],
    *,
    employment_types: Sequence[EmploymentType] | None = None,
    limit: int = DEFAULT_MATCH_LIMIT,
) -> list[OpportunityMatch]:
    """Rank skill-based opportunity matches for ``subject`` against a candidate pool.

    ``employment_types``, when supplied, restricts the pool to only those
    ``EmploymentType`` values BEFORE scoring — a subject who wants freelance work
    only should never see (or pay the scoring cost of) full-time postings. ``None``
    (the default) means no restriction, i.e. both kinds are considered.

    Deterministic: ties break on ``opportunity_id`` ascending, so the same input
    always produces the same output (mirrors ``intent.rank_matches``). ``limit``
    is clamped to ``[0, MAX_SUGGESTIONS]``; ``candidates`` beyond
    ``MAX_CANDIDATES`` is rejected outright rather than silently truncated.

    This function does no I/O and does NOT de-duplicate ``candidates`` by
    ``opportunity_id`` — a caller passing the same opportunity twice gets it
    scored (and possibly listed) twice, mirrors ``intent.rank_matches``.
    """
    if len(candidates) > MAX_CANDIDATES:
        raise ValueError(f"candidates must not exceed {MAX_CANDIDATES} entries")
    bounded_limit = max(0, min(limit, MAX_SUGGESTIONS))

    allowed_types = set(employment_types) if employment_types is not None else None

    matches = [
        match
        for opportunity in candidates
        if (allowed_types is None or opportunity.employment_type in allowed_types)
        and (match := suggest_opportunity_match(subject_profile, subject_intent, opportunity))
        is not None
    ]
    matches.sort(key=lambda m: (-m.score, m.opportunity_id))
    return matches[:bounded_limit]
