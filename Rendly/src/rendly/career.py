"""Career — a deterministic profile-optimization checklist + trajectory-stage
matching seam (R-017 = FORK A1/B1/C1/D1/E1).

HONESTY BOUNDARY (verbatim, non-removable): "AI profile optimization" in the
roadmap's task name is NOT implemented here as AI. What ships is a FIXED, NAMED
checklist over already-loaded domain objects (:func:`optimization_gaps`) — no
model, no embeddings, no generated text, no learned ranking. This is a deliberate
scope-down of R-017 (~10-16h, 🏦 POST-INVESTMENT, second task of Rendly's B2C
professional-networking tier, "Depends on: R-004/R-005 + the matching core") to a
minimal seam, in the same spirit as R-012's and R-016's own scoped deliveries (see
ADR-0012 §Decision, ADR-0016 §Decision) — this module reproduces their discipline
rather than inventing a new one.

"career-trajectory matching" ships as a NEW opt-in type, :class:`CareerGoal`, and a
directional stage-equality matcher (:func:`suggest_trajectory_match` /
:func:`rank_trajectory_matches`) — deliberately NOT a reuse of R-016's
``IntentProfile``: a career trajectory is a single current/target STAGE a person
occupies (e.g. ``"senior_engineer" -> "staff_engineer"``), not a set of arbitrary
seeking/offering skill tags, so it is modeled as its own bounded opt-in record
rather than overloading ``IntentProfile`` or ``Profile.org_role`` (a distinct,
org-membership-permission axis — FORK B of ADR-0002 — not a career ladder).

NOT BUILT HERE (mirrors ADR-0016's own list): real B2C consumer identity/onboarding
(R-023, still unshipped) — both functions below operate over the EXISTING
enterprise ``Profile`` domain (R-002) as a placeholder actor model, exactly as
R-012/R-016 did. No persistence, no REST/wire surface, no ML/embedding text
generation, no resume parsing.

PRIVACY-CONTROLLED, by construction, not by policy (mirrors ``culture.py``/
``intent.py``): a user who has never called :func:`bind_career_goal` has no
``CareerGoal`` and structurally cannot appear as a subject or a candidate in
trajectory matching — every matching function requires an explicit opt-in object.
``optimization_gaps`` takes ``career_goal``/``intent_profile`` as optional
arguments precisely because their ABSENCE is itself a reportable gap, not a scan.

DELIBERATE DIVERGENCE FROM ``culture.py`` (R-012), consistent WITH ``intent.py``
(R-016): trajectory matching does NOT reject cross-tenant pairs. B2C career
mentorship is definitionally cross-company (see ADR-0016 Fork B, reproduced here
as Fork B of ADR-0017) — the same reasoning applies unchanged.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator, model_validator

from .common import require_aware_utc
from .identifiers import TenantId, UserId
from .intent import IntentProfile
from .profile import Profile

# A trajectory stage: short, non-empty, bounded (mirrors intent.py's `IntentTag`).
CareerStage = Annotated[str, StringConstraints(min_length=1, max_length=64)]

# Bounds the candidate pool + the result set of a single ranking call (mirrors
# intent.py's MAX_CANDIDATES/MAX_SUGGESTIONS) — a DoS/cost guard on the pairwise
# scorer, not a product decision about "how many matches are useful."
MAX_CANDIDATES = 500
MAX_SUGGESTIONS = 50
DEFAULT_MATCH_LIMIT = 10

# The fixed, named checklist `optimization_gaps` evaluates — see that function's
# docstring. Kept as a module constant (not derived from the enum at call time) so
# the total is stable even if OptimizationGap ever grows a value unrelated to this
# checklist.
TOTAL_OPTIMIZATION_CHECKS = 4


class CareerGoal(BaseModel):
    """A user's explicit, revocable opt-in into career-trajectory matching.

    Immutable. Absence of a ``CareerGoal`` for a user is the ONLY "opted out" state
    this module models for trajectory matching — there is no separate boolean to
    forget to check (mirrors ``IntentProfile``). ``current_stage`` and
    ``target_stage`` are opaque, caller-defined labels (this module does not
    maintain or validate a fixed career-ladder vocabulary) and must differ: a
    "goal" that restates the current stage is not a trajectory.

    Direct ``CareerGoal(...)`` construction with hand-supplied ids is a
    lower-level primitive NOT validated against any real ``Profile`` (mirrors
    ``IntentProfile``'s same reservation); it exists for rehydrating an
    already-validated record. All application code that mints a NEW career goal
    MUST use :func:`bind_career_goal`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: UserId
    tenant_id: TenantId
    current_stage: CareerStage
    target_stage: CareerStage
    opted_in_at: datetime

    @field_validator("opted_in_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "opted_in_at")

    @model_validator(mode="after")
    def _stages_differ(self) -> "CareerGoal":
        if self.current_stage == self.target_stage:
            raise ValueError("target_stage must differ from current_stage")
        return self


def bind_career_goal(
    profile: Profile,
    *,
    current_stage: str,
    target_stage: str,
    opted_in_at: datetime,
) -> CareerGoal:
    """Build a ``CareerGoal`` bound to a real ``Profile`` (the canonical path).

    ``user_id``/``tenant_id`` are read FROM the profile, mirroring
    :func:`rendly.intent.bind_intent_profile` — an opt-in record's identity is
    derived from a validated parent, not hand-supplied.
    """
    return CareerGoal(
        user_id=profile.user_id,
        tenant_id=profile.tenant_id,
        current_stage=current_stage,
        target_stage=target_stage,
        opted_in_at=opted_in_at,
    )


class TrajectoryMatch(BaseModel):
    """A single deterministic career-trajectory match. Immutable.

    ``candidate_is_mentor`` is true when the CANDIDATE already occupies the
    SUBJECT's ``target_stage`` (a natural mentor for that specific trajectory).
    ``candidate_is_mentee`` is true when the CANDIDATE's ``target_stage`` is the
    SUBJECT's ``current_stage`` (the subject is a natural mentor for the
    candidate). Both may be true at once (mutual, differently-directed
    mentorship potential); ``score`` is the count of directions that hold (1 or
    2 — a ``TrajectoryMatch`` is never constructed for a 0 score, mirroring
    ``IntentMatch``'s "never a zero-score match" rule).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_user_id: UserId
    subject_tenant_id: TenantId
    candidate_user_id: UserId
    candidate_tenant_id: TenantId
    candidate_is_mentor: bool
    candidate_is_mentee: bool
    score: int


def _require_bound(profile: Profile, goal: CareerGoal, *, label: str) -> None:
    if profile.user_id != goal.user_id or profile.tenant_id != goal.tenant_id:
        raise ValueError(f"{label} profile/career-goal pair do not describe the same user")


def suggest_trajectory_match(
    subject_profile: Profile,
    subject_goal: CareerGoal,
    candidate_profile: Profile,
    candidate_goal: CareerGoal,
) -> TrajectoryMatch | None:
    """Score a single subject/candidate pair, or ``None`` if no match applies.

    Directional STAGE-EQUALITY scoring (the "trajectory" part, distinct from
    ``intent.suggest_match``'s tag-SET intersection): a match exists when the
    candidate already occupies the stage the subject is aiming for, OR the
    candidate is aiming for the stage the subject already occupies.

    Returns ``None`` (never a zero-score match) when:
    - the candidate IS the subject (no self-match),
    - neither direction holds.

    Cross-tenant pairs ARE matched — see this module's docstring "DELIBERATE
    DIVERGENCE" section; matches ``intent.suggest_match``'s behavior, the
    opposite of ``culture.suggest_connection``.

    Raises ``ValueError`` (refuses to compute, mirrors ``intent.suggest_match``)
    if either profile/career-goal pair is internally inconsistent.
    """
    _require_bound(subject_profile, subject_goal, label="subject")
    _require_bound(candidate_profile, candidate_goal, label="candidate")

    if candidate_profile.user_id == subject_profile.user_id:
        return None

    candidate_is_mentor = candidate_goal.current_stage == subject_goal.target_stage
    candidate_is_mentee = candidate_goal.target_stage == subject_goal.current_stage
    if not candidate_is_mentor and not candidate_is_mentee:
        return None

    return TrajectoryMatch(
        subject_user_id=subject_profile.user_id,
        subject_tenant_id=subject_profile.tenant_id,
        candidate_user_id=candidate_profile.user_id,
        candidate_tenant_id=candidate_profile.tenant_id,
        candidate_is_mentor=candidate_is_mentor,
        candidate_is_mentee=candidate_is_mentee,
        score=int(candidate_is_mentor) + int(candidate_is_mentee),
    )


def rank_trajectory_matches(
    subject_profile: Profile,
    subject_goal: CareerGoal,
    candidates: Sequence[tuple[Profile, CareerGoal]],
    *,
    limit: int = DEFAULT_MATCH_LIMIT,
) -> list[TrajectoryMatch]:
    """Rank career-trajectory matches for ``subject`` against a candidate pool.

    Deterministic: ties break on ``candidate_user_id`` ascending, so the same
    input always produces the same output (mirrors ``intent.rank_matches``).
    ``limit`` is clamped to ``[0, MAX_SUGGESTIONS]``; ``candidates`` beyond
    ``MAX_CANDIDATES`` is rejected outright rather than silently truncated.

    This function does no I/O and does NOT de-duplicate ``candidates`` by
    ``candidate_user_id`` — a caller passing the same candidate twice gets that
    candidate scored (and possibly listed) twice, mirrors ``intent.rank_matches``.
    """
    if len(candidates) > MAX_CANDIDATES:
        raise ValueError(f"candidates must not exceed {MAX_CANDIDATES} entries")
    bounded_limit = max(0, min(limit, MAX_SUGGESTIONS))

    matches = [
        match
        for candidate_profile, candidate_goal in candidates
        if (
            match := suggest_trajectory_match(
                subject_profile, subject_goal, candidate_profile, candidate_goal
            )
        )
        is not None
    ]
    matches.sort(key=lambda m: (-m.score, m.candidate_user_id))
    return matches[:bounded_limit]


class OptimizationGap(StrEnum):
    """The FIXED, NAMED gaps :func:`optimization_gaps` can report.

    Closed by construction (a ``StrEnum``, not an open string) so a caller can
    branch on a gap without string-matching, and so this module's own docstring
    "no generated text" boundary is structurally enforced — nothing here can
    return free-form advice, only these four named checks.
    """

    MISSING_TEAM = "missing_team"
    NO_SEEKING_TAGS = "no_seeking_tags"
    NO_OFFERING_TAGS = "no_offering_tags"
    NO_CAREER_GOAL = "no_career_goal"


class ProfileOptimizationReport(BaseModel):
    """The result of :func:`optimization_gaps`. Immutable.

    ``completeness_score`` is ``TOTAL_OPTIMIZATION_CHECKS - len(gaps)`` — never
    computed independently, so the two can never disagree.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_user_id: UserId
    profile_tenant_id: TenantId
    gaps: tuple[OptimizationGap, ...]
    completeness_score: int
    total_checks: int


def optimization_gaps(
    profile: Profile,
    intent_profile: IntentProfile | None = None,
    career_goal: CareerGoal | None = None,
) -> ProfileOptimizationReport:
    """Evaluate the fixed 4-check profile-completeness checklist.

    This is the whole of "AI profile optimization" as shipped — see this module's
    HONESTY BOUNDARY docstring. The four checks, always evaluated in this fixed
    order (so ``gaps`` is deterministic for the same input):

    1. ``MISSING_TEAM`` — ``profile.team`` is unset.
    2. ``NO_SEEKING_TAGS`` — ``intent_profile`` is absent, or has no ``seeking``
       tags (R-016's matching core cannot surface this user as a match target
       without at least one).
    3. ``NO_OFFERING_TAGS`` — as above, for ``offering``.
    4. ``NO_CAREER_GOAL`` — ``career_goal`` is absent (this module's own
       trajectory matching, above, cannot run for this user without one).

    ``intent_profile`` / ``career_goal`` are optional precisely because their
    absence is itself checks 2/3/4 — this function does not require a caller to
    have opted in to everything just to see what is missing.

    Raises ``ValueError`` (mirrors ``suggest_match``/``suggest_trajectory_match``)
    if a supplied ``intent_profile`` or ``career_goal`` does not belong to
    ``profile``.
    """
    if intent_profile is not None and (
        profile.user_id != intent_profile.user_id or profile.tenant_id != intent_profile.tenant_id
    ):
        raise ValueError("intent_profile does not describe the same user as profile")
    if career_goal is not None:
        _require_bound(profile, career_goal, label="profile")

    gaps: list[OptimizationGap] = []
    if profile.team is None:
        gaps.append(OptimizationGap.MISSING_TEAM)
    if intent_profile is None or not intent_profile.seeking:
        gaps.append(OptimizationGap.NO_SEEKING_TAGS)
    if intent_profile is None or not intent_profile.offering:
        gaps.append(OptimizationGap.NO_OFFERING_TAGS)
    if career_goal is None:
        gaps.append(OptimizationGap.NO_CAREER_GOAL)

    return ProfileOptimizationReport(
        profile_user_id=profile.user_id,
        profile_tenant_id=profile.tenant_id,
        gaps=tuple(gaps),
        completeness_score=TOTAL_OPTIMIZATION_CHECKS - len(gaps),
        total_checks=TOTAL_OPTIMIZATION_CHECKS,
    )
