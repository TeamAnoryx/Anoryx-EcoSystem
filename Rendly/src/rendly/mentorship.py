"""Mentorship — a deterministic, opt-in, exact-tech-stack proficiency matching
seam (R-022 = FORK A1/B1/C1/D1).

HONESTY BOUNDARY (verbatim, non-removable): "Mentorship matching by exact
tech-stack proficiency" ships here as a DETERMINISTIC scorer over a NEW opt-in
record, :class:`MentorshipProfile` — a caller-supplied mapping of tech-stack tag
to a closed :class:`ProficiencyLevel`. No ML, no resume/transcript parsing, no
generated match explanations beyond the matched tag list itself. This is a
deliberate scope-down of R-022 (~10-16h, 🏦 POST-INVESTMENT, seventh task of
Rendly's B2C professional-networking tier) to a minimal seam, in the same
spirit as R-012/R-016/R-017/R-018/R-020/R-021's own scoped deliveries.

"exact tech-stack proficiency" is not a stylistic qualifier — it is the module's
central scope boundary, resolved two ways:

1. Matching requires the SAME exact tag on both sides. There is no fuzzy /
   related-technology expansion (e.g. "react" does not match "vue"); a shared
   tag is either present verbatim on both ``MentorshipProfile``s or it is not
   considered at all. Mirrors ``opportunity.py``'s set-intersection discipline,
   applied here to a per-tag LEVEL pair rather than a bare tag set.
2. A shared tag is a mentorship signal only when the two proficiency levels
   DIFFER. Equal levels on a shared tag are peers, not a mentor/mentee pair —
   this module reports no direction for that tag (mirrors the "never a
   zero-score match" discipline: a pair with only equal-level shared tags
   produces no ``MentorshipMatch`` at all).

NOT BUILT HERE: a new ID/entity type (mirrors ``intent.py``/``career.py``, NOT
``opportunity.py``/``event.py`` — a ``MentorshipProfile`` is a per-user opt-in
record identified by ``user_id``/``tenant_id``, not a separate posted listing);
persistence (a caller supplies the profile each time); REST/wire surface; any
notion of a mentorship "session", request/accept workflow, or scheduling — this
module only scores two caller-supplied profiles, it does not manage how a
mentorship relationship is initiated or conducted.

PRIVACY-CONTROLLED, by construction, not by policy (mirrors ``intent.py``/
``career.py``): a user who has never called :func:`bind_mentorship_profile` has
no ``MentorshipProfile`` and structurally cannot appear as a subject or a
candidate — every function in this module requires an explicit opt-in object.

DELIBERATE DIVERGENCE FROM ``culture.py`` (R-012), consistent WITH ``intent.py``
(R-016)/``career.py`` (R-017)/``opportunity.py`` (R-021): mentorship matching
does NOT reject cross-tenant pairs. B2C tech-stack mentorship is definitionally
cross-company — the same reasoning as R-016/R-017/R-020/R-021 applies
unchanged.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

from .common import require_aware_utc
from .identifiers import TenantId, UserId
from .profile import Profile

# A tech-stack tag: short, non-empty, bounded (mirrors intent.py's IntentTag).
TechStackTag = Annotated[str, StringConstraints(min_length=1, max_length=64)]

# Bounded field discipline (mirrors intent.py's MAX_TAGS): a single profile's
# proficiency list is capped so neither storage (once a future task adds it)
# nor the O(n) shared-tag scan below is exposed to an unbounded input.
MAX_TECH_STACKS = 16

# Bounds the candidate pool + the result set of a single ranking call (mirrors
# intent.py's/career.py's MAX_CANDIDATES/MAX_SUGGESTIONS at the same
# magnitudes) — a DoS/cost guard on the pairwise scorer, not a product
# decision about "how many matches are useful."
MAX_CANDIDATES = 500
MAX_SUGGESTIONS = 50
DEFAULT_MATCH_LIMIT = 10


class ProficiencyLevel(StrEnum):
    """A closed, ORDERED proficiency scale (Fork B).

    Ordered so two levels on the SAME exact tag can be compared to derive a
    mentorship direction (see :func:`suggest_mentorship_match`) — a plain
    unordered tag set (``intent.py``'s model) cannot express "more proficient
    than," only "shares this tag."
    """

    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT = "expert"


# The fixed rank order backing the enum above. Kept as an explicit mapping
# (not "derive the ordinal from enum declaration order") so a future reordering
# of the enum's members can never silently change matching semantics.
_LEVEL_RANK: dict[ProficiencyLevel, int] = {
    ProficiencyLevel.BEGINNER: 0,
    ProficiencyLevel.INTERMEDIATE: 1,
    ProficiencyLevel.ADVANCED: 2,
    ProficiencyLevel.EXPERT: 3,
}


class TechStackProficiency(BaseModel):
    """A single (tech-stack tag, proficiency level) pair. Immutable."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tag: TechStackTag
    level: ProficiencyLevel


class MentorshipProfile(BaseModel):
    """A user's explicit, revocable opt-in into tech-stack mentorship matching.

    Immutable. Absence of a ``MentorshipProfile`` for a user is the ONLY
    "opted out" state this module models — there is no separate boolean to
    forget to check (mirrors ``IntentProfile``/``CareerGoal``). Each tag may
    appear at most once — a user has exactly one proficiency level per
    tech-stack tag, never two competing claims.

    Direct ``MentorshipProfile(...)`` construction with hand-supplied ids is a
    lower-level primitive NOT validated against any real ``Profile`` (mirrors
    ``IntentProfile``'s same reservation); it exists for rehydrating an
    already-validated record. All application code that mints a NEW mentorship
    profile MUST use :func:`bind_mentorship_profile`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: UserId
    tenant_id: TenantId
    proficiencies: tuple[TechStackProficiency, ...]
    opted_in_at: datetime

    @field_validator("opted_in_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "opted_in_at")

    @field_validator("proficiencies")
    @classmethod
    def _bounded_and_deduped(
        cls, value: tuple[TechStackProficiency, ...]
    ) -> tuple[TechStackProficiency, ...]:
        if len(value) > MAX_TECH_STACKS:
            raise ValueError(f"proficiencies must not exceed {MAX_TECH_STACKS} entries")
        tags = [entry.tag for entry in value]
        if len(set(tags)) != len(tags):
            raise ValueError("proficiencies must not contain duplicate tech-stack tags")
        return value


def bind_mentorship_profile(
    profile: Profile,
    *,
    proficiencies: Mapping[str, ProficiencyLevel],
    opted_in_at: datetime,
) -> MentorshipProfile:
    """Build a ``MentorshipProfile`` bound to a real ``Profile`` (the canonical path).

    ``user_id``/``tenant_id`` are read FROM the profile, mirroring
    :func:`rendly.intent.bind_intent_profile` — an opt-in record's identity is
    derived from a validated parent, not hand-supplied. ``proficiencies`` is a
    mapping (tag -> level) rather than a sequence of pairs precisely because a
    mapping's keys are already unique, matching this record's one-level-per-tag
    invariant at the call site.
    """
    return MentorshipProfile(
        user_id=profile.user_id,
        tenant_id=profile.tenant_id,
        proficiencies=tuple(
            TechStackProficiency(tag=tag, level=level) for tag, level in proficiencies.items()
        ),
        opted_in_at=opted_in_at,
    )


class MentorshipMatch(BaseModel):
    """A single deterministic mentorship match. Immutable.

    ``candidate_mentors_on`` is the set of EXACT shared tech-stack tags where
    the CANDIDATE's level outranks the SUBJECT's (the candidate can mentor the
    subject on that stack). ``candidate_mentees_on`` is the set where the
    SUBJECT's level outranks the CANDIDATE's (the subject can mentor the
    candidate — the candidate is a mentee for that stack). Both are reported
    (rather than just a combined score) so a future caller can show "why" a
    match was suggested without recomputing it. A shared tag at EQUAL levels
    appears in neither tuple — see this module's HONESTY BOUNDARY docstring.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_user_id: UserId
    subject_tenant_id: TenantId
    candidate_user_id: UserId
    candidate_tenant_id: TenantId
    candidate_mentors_on: tuple[str, ...]
    candidate_mentees_on: tuple[str, ...]
    score: int


def _require_bound(profile: Profile, mentorship: MentorshipProfile, *, label: str) -> None:
    if profile.user_id != mentorship.user_id or profile.tenant_id != mentorship.tenant_id:
        raise ValueError(f"{label} profile/mentorship pair do not describe the same user")


def suggest_mentorship_match(
    subject_profile: Profile,
    subject_mentorship: MentorshipProfile,
    candidate_profile: Profile,
    candidate_mentorship: MentorshipProfile,
) -> MentorshipMatch | None:
    """Score a single subject/candidate pair, or ``None`` if no match applies.

    EXACT-tag, level-asymmetry scoring (the "exact tech-stack proficiency"
    part): for every tech-stack tag present on BOTH profiles, a direction is
    recorded only when the two levels differ — see this module's HONESTY
    BOUNDARY docstring. A tag present on only one side, or shared at an equal
    level, contributes nothing.

    Returns ``None`` (never a zero-score match) when:
    - the candidate IS the subject (no self-match),
    - no shared tag has differing levels.

    Cross-tenant pairs ARE matched — see this module's docstring "DELIBERATE
    DIVERGENCE" section; matches ``intent.suggest_match``'s behavior, the
    opposite of ``culture.suggest_connection``.

    Raises ``ValueError`` (refuses to compute, mirrors
    ``intent.suggest_match``) if either profile/mentorship pair is internally
    inconsistent.
    """
    _require_bound(subject_profile, subject_mentorship, label="subject")
    _require_bound(candidate_profile, candidate_mentorship, label="candidate")

    if candidate_profile.user_id == subject_profile.user_id:
        return None

    subject_levels = {entry.tag: entry.level for entry in subject_mentorship.proficiencies}
    candidate_levels = {entry.tag: entry.level for entry in candidate_mentorship.proficiencies}

    mentors_on: list[str] = []
    mentees_on: list[str] = []
    for tag in sorted(set(subject_levels) & set(candidate_levels)):
        subject_rank = _LEVEL_RANK[subject_levels[tag]]
        candidate_rank = _LEVEL_RANK[candidate_levels[tag]]
        if candidate_rank > subject_rank:
            mentors_on.append(tag)
        elif subject_rank > candidate_rank:
            mentees_on.append(tag)

    if not mentors_on and not mentees_on:
        return None

    return MentorshipMatch(
        subject_user_id=subject_profile.user_id,
        subject_tenant_id=subject_profile.tenant_id,
        candidate_user_id=candidate_profile.user_id,
        candidate_tenant_id=candidate_profile.tenant_id,
        candidate_mentors_on=tuple(mentors_on),
        candidate_mentees_on=tuple(mentees_on),
        score=len(mentors_on) + len(mentees_on),
    )


def rank_mentorship_matches(
    subject_profile: Profile,
    subject_mentorship: MentorshipProfile,
    candidates: Sequence[tuple[Profile, MentorshipProfile]],
    *,
    limit: int = DEFAULT_MATCH_LIMIT,
) -> list[MentorshipMatch]:
    """Rank mentorship matches for ``subject`` against a candidate pool.

    Deterministic: ties break on ``candidate_user_id`` ascending, so the same
    input always produces the same output (mirrors ``intent.rank_matches``).
    ``limit`` is clamped to ``[0, MAX_SUGGESTIONS]``; ``candidates`` beyond
    ``MAX_CANDIDATES`` is rejected outright rather than silently truncated.

    This function does no I/O and does NOT de-duplicate ``candidates`` by
    ``candidate_user_id`` — a caller passing the same candidate twice gets
    that candidate scored (and possibly listed) twice, mirrors
    ``intent.rank_matches``.
    """
    if len(candidates) > MAX_CANDIDATES:
        raise ValueError(f"candidates must not exceed {MAX_CANDIDATES} entries")
    bounded_limit = max(0, min(limit, MAX_SUGGESTIONS))

    matches = [
        match
        for candidate_profile, candidate_mentorship in candidates
        if (
            match := suggest_mentorship_match(
                subject_profile, subject_mentorship, candidate_profile, candidate_mentorship
            )
        )
        is not None
    ]
    matches.sort(key=lambda m: (-m.score, m.candidate_user_id))
    return matches[:bounded_limit]
