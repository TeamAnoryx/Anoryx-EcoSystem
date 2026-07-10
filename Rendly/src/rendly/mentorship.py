"""Mentorship — a deterministic, exact-stack, ordered-proficiency matching seam
(R-022 = FORK A1/B1/C1/D1).

HONESTY BOUNDARY (verbatim, non-removable): "Mentorship matching by tech-stack"
ships here as a DETERMINISTIC, EXACT-MATCH scorer — no ML, no fuzzy stack-name
matching, no generated mentorship advice. "Exact tech-stack proficiency" (the
roadmap's fuller phrasing) is taken literally: two ``TechStackProficiency``
records match only when their ``stack`` labels are byte-identical strings — the
same opaque-tag discipline ``career.py``'s ``CareerStage``/``discovery.py``'s
``Locality`` already use, deliberately not solved here (no synonym resolution,
no case-folding).

NOT BUILT HERE: a new opt-in type was the right call this time (unlike R-021,
which correctly REUSED ``intent.IntentProfile.offering``) because neither
existing opt-in type captures this task's actual shape: ``IntentProfile``'s tags
are an unordered set with no notion of skill LEVEL, and ``career.CareerGoal``'s
stage is a career-ladder position, not a named-technology proficiency. Ordered
proficiency in a SPECIFIC named stack is a genuinely new shape this codebase has
not modeled yet. No persistence, no REST/wire surface, no mentorship-session
scheduling/booking workflow (R-007's huddles already exist for the actual
1-on-1 mechanism, if a future task wires this seam's output to it).

PRIVACY-CONTROLLED, by construction, not by policy (mirrors ``intent.py``/
``career.py``): a user who has never called :func:`bind_tech_stack_proficiency`
has no ``TechStackProficiency`` and structurally cannot appear as a mentee or
mentor here — every function in this module requires an explicit opt-in object.

DELIBERATE DIVERGENCE FROM ``culture.py`` (R-012), consistent WITH ``intent.py``
(R-016)/``career.py`` (R-017): mentorship matching does NOT reject cross-tenant
pairs — professional mentorship across companies is definitionally cross-tenant,
the same reasoning as every other seam in this B2C tier.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator, model_validator

from .common import require_aware_utc
from .identifiers import TenantId, UserId
from .profile import Profile

# A tech-stack label: short, non-empty, bounded (mirrors career.py's CareerStage /
# discovery.py's Locality — opaque, exact-match, no fixed vocabulary).
TechStack = Annotated[str, StringConstraints(min_length=1, max_length=64)]


class ProficiencyLevel(StrEnum):
    """A closed, ORDERED proficiency scale. Order is NOT the enum's declaration
    order (Python StrEnum has no inherent ordering) — it is the explicit
    :data:`_LEVEL_RANK` mapping below, so ordering is a deliberate, visible
    decision rather than an accident of declaration order."""

    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


# The explicit ordering `ProficiencyLevel` itself does not provide. A mentor
# must rank strictly higher than a mentee on this scale (see Fork C).
_LEVEL_RANK: dict[ProficiencyLevel, int] = {
    ProficiencyLevel.BEGINNER: 0,
    ProficiencyLevel.INTERMEDIATE: 1,
    ProficiencyLevel.ADVANCED: 2,
    ProficiencyLevel.EXPERT: 3,
}

# Bounds the candidate pool + the result set of a single ranking call (mirrors
# intent.py's/career.py's MAX_CANDIDATES/MAX_SUGGESTIONS at the same magnitudes).
MAX_CANDIDATES = 500
MAX_SUGGESTIONS = 50
DEFAULT_MATCH_LIMIT = 10


class TechStackProficiency(BaseModel):
    """A user's explicit, revocable proficiency claim in ONE named tech stack.
    Immutable. A user proficient in multiple stacks holds multiple independent
    ``TechStackProficiency`` records (one per stack) — this mirrors how a real
    person's skills work, rather than forcing one record per user.

    Direct construction with hand-supplied ids is a lower-level primitive
    (mirrors ``CareerGoal``'s own reservation) NOT validated against a real
    ``Profile``; :func:`bind_tech_stack_proficiency` is the canonical path.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: UserId
    tenant_id: TenantId
    stack: TechStack
    level: ProficiencyLevel
    opted_in_at: datetime

    @field_validator("opted_in_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "opted_in_at")


def bind_tech_stack_proficiency(
    profile: Profile,
    *,
    stack: str,
    level: ProficiencyLevel,
    opted_in_at: datetime,
) -> TechStackProficiency:
    """Build a ``TechStackProficiency`` bound to a real ``Profile`` (the
    canonical path). ``user_id``/``tenant_id`` are read FROM the profile,
    mirroring :func:`rendly.career.bind_career_goal`.
    """
    return TechStackProficiency(
        user_id=profile.user_id,
        tenant_id=profile.tenant_id,
        stack=stack,
        level=level,
        opted_in_at=opted_in_at,
    )


class MentorshipMatch(BaseModel):
    """A single deterministic mentorship match. Immutable.

    ``score`` is the proficiency-rank gap (``mentor``'s rank minus ``mentee``'s
    rank on :data:`_LEVEL_RANK`) — always a positive integer 1..3. A model
    validator enforces ``score == _LEVEL_RANK[mentor_level] -
    _LEVEL_RANK[mentee_level]`` structurally, so it can never disagree with the
    two levels also carried on this record, even via direct construction.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    mentee_user_id: UserId
    mentee_tenant_id: TenantId
    mentor_user_id: UserId
    mentor_tenant_id: TenantId
    stack: str
    mentee_level: ProficiencyLevel
    mentor_level: ProficiencyLevel
    score: int

    @model_validator(mode="after")
    def _score_matches_rank_gap(self) -> "MentorshipMatch":
        expected = _LEVEL_RANK[self.mentor_level] - _LEVEL_RANK[self.mentee_level]
        if self.score != expected or expected <= 0:
            raise ValueError(
                "score must equal the mentor/mentee proficiency-rank gap, and the "
                "mentor must strictly outrank the mentee"
            )
        return self


def _require_bound(profile: Profile, proficiency: TechStackProficiency, *, label: str) -> None:
    if profile.user_id != proficiency.user_id or profile.tenant_id != proficiency.tenant_id:
        raise ValueError(f"{label} profile/proficiency pair do not describe the same user")


def suggest_mentorship_match(
    mentee_profile: Profile,
    mentee_proficiency: TechStackProficiency,
    mentor_profile: Profile,
    mentor_proficiency: TechStackProficiency,
) -> MentorshipMatch | None:
    """Score a single mentee/mentor pair, or ``None`` if no match applies.

    A match requires, in order: an EXACT (case-sensitive, byte-identical)
    ``stack`` match between the two proficiency records, and the mentor's
    :data:`_LEVEL_RANK` strictly greater than the mentee's — a peer at the
    SAME level is not a mentor (never a zero-score match, mirrors every other
    matcher in this tier).

    Returns ``None`` (never a zero-score match) when the candidate IS the
    subject, the stacks differ, or the mentor does not outrank the mentee.

    Cross-tenant pairs ARE matched — see this module's docstring "DELIBERATE
    DIVERGENCE" section.

    Raises ``ValueError`` (mirrors ``intent.suggest_match``/
    ``career.suggest_trajectory_match``) if either profile/proficiency pair is
    internally inconsistent.
    """
    _require_bound(mentee_profile, mentee_proficiency, label="mentee")
    _require_bound(mentor_profile, mentor_proficiency, label="mentor")

    if mentor_profile.user_id == mentee_profile.user_id:
        return None
    if mentor_proficiency.stack != mentee_proficiency.stack:
        return None

    gap = _LEVEL_RANK[mentor_proficiency.level] - _LEVEL_RANK[mentee_proficiency.level]
    if gap <= 0:
        return None

    return MentorshipMatch(
        mentee_user_id=mentee_profile.user_id,
        mentee_tenant_id=mentee_profile.tenant_id,
        mentor_user_id=mentor_profile.user_id,
        mentor_tenant_id=mentor_profile.tenant_id,
        stack=mentee_proficiency.stack,
        mentee_level=mentee_proficiency.level,
        mentor_level=mentor_proficiency.level,
        score=gap,
    )


def rank_mentors(
    mentee_profile: Profile,
    mentee_proficiency: TechStackProficiency,
    candidates: Sequence[tuple[Profile, TechStackProficiency]],
    *,
    limit: int = DEFAULT_MATCH_LIMIT,
) -> list[MentorshipMatch]:
    """Rank prospective mentors for ``mentee`` against a candidate pool.

    Deterministic: ties break on ``mentor_user_id`` ascending, so the same
    input always produces the same output (mirrors ``intent.rank_matches``/
    ``career.rank_trajectory_matches``). ``limit`` is clamped to
    ``[0, MAX_SUGGESTIONS]``; ``candidates`` beyond ``MAX_CANDIDATES`` is
    rejected outright rather than silently truncated.

    This function does no I/O and does NOT de-duplicate ``candidates`` by
    ``mentor_user_id`` — a caller passing the same candidate twice gets it
    scored (and possibly listed) twice, mirrors every ``rank_*`` sibling.
    """
    if len(candidates) > MAX_CANDIDATES:
        raise ValueError(f"candidates must not exceed {MAX_CANDIDATES} entries")
    bounded_limit = max(0, min(limit, MAX_SUGGESTIONS))

    matches = [
        match
        for mentor_profile, mentor_proficiency in candidates
        if (
            match := suggest_mentorship_match(
                mentee_profile, mentee_proficiency, mentor_profile, mentor_proficiency
            )
        )
        is not None
    ]
    matches.sort(key=lambda m: (-m.score, m.mentor_user_id))
    return matches[:bounded_limit]
