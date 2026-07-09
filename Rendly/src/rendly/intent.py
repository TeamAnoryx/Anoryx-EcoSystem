"""Intent — a deterministic, opt-in, complementary-intent matching seam (R-016 = FORK H1).

HONESTY BOUNDARY (verbatim, non-removable): "Intent-based matching algorithm" in the
roadmap's task name is the algorithm this module ships — deterministic, not learned.
"AI-powered" language does NOT apply here: there is no model, no embeddings, no ranking
signal beyond explicit, caller-supplied tag sets. This is a deliberate scope-down of
R-016 (10-16h, 🏦 POST-INVESTMENT, first task of Rendly's B2C professional-networking
tier) to a minimal, privacy-controlled matching CORE, in the same spirit as O-009/
O-010/O-011's and R-012/R-013/R-014/R-015's own scoped deliveries (see ADR-0016
§Decision). This is the module ``profile.py``'s own non-removable boundary named and
deferred to: "intent-based matching is the post-investment tier (R-016 -> R-026) and
is deferred" — R-016 is the task licensed to introduce it, and this module is that
introduction, scoped exactly as thin as every prior 🏦 seam in this codebase.

NOT BUILT HERE (see ADR-0016 for the full list): real B2C consumer identity/onboarding
(R-023, still unshipped) — this seam operates over the EXISTING enterprise ``Profile``
domain (R-002) as a placeholder actor model, exactly as R-012 reused ``Profile`` rather
than inventing a new identity type. No persistence, no REST/wire surface, no ML.

DELIBERATE DIVERGENCE FROM ``culture.py`` (R-012), not an oversight:
- ``culture.py`` REFUSES cross-tenant pairs (internal, cross-DEPARTMENT matching within
  one company must never leak across companies). This module's whole point is B2C
  professional networking, which is definitionally CROSS-company — so ``suggest_match``
  / ``rank_matches`` do NOT reject or even inspect a candidate's tenant relative to the
  subject's. (Cross-tenant *data access* controls, e.g. who is even eligible to appear
  in a candidate pool, remain the responsibility of whatever future persistence/REST
  layer supplies that pool — this pure-compute seam trusts its caller-supplied input the
  same way ``rank_connections`` already does.)
- Matching is DIRECTIONAL/complementary (what the subject is ``seeking`` overlapping
  what a candidate is ``offering``, and vice versa), not a symmetric tag-overlap score.
  "Intent-based" means matching on complementary WANTS, not shared hobbies — a mentor
  and a mentee are a good match precisely because their tags DIFFER in a compatible way,
  which a plain intersection-of-identical-tags scorer (culture.py's model) cannot
  express.

PRIVACY-CONTROLLED, by construction, not by policy (mirrors ``culture.py``):
- A user who has never called :func:`bind_intent_profile` has no ``IntentProfile``
  record and structurally cannot appear as a subject or a candidate — every function in
  this module requires an explicit opt-in object as an argument.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

from .common import require_aware_utc
from .identifiers import TenantId, UserId
from .profile import Profile

# A seeking/offering tag: short, non-empty, bounded (mirrors `culture.py`'s `Interest`).
IntentTag = Annotated[str, StringConstraints(min_length=1, max_length=64)]

# Bounded field discipline (mirrors `culture.py`'s MAX_INTERESTS=16): each of `seeking`
# and `offering` is capped independently so neither storage nor the O(n*m) pairwise
# scorer below is exposed to an unbounded per-user tag list.
MAX_TAGS = 16

# Bounds the candidate pool + the result set of a single ranking call (mirrors
# `culture.py`'s MAX_CANDIDATES/MAX_SUGGESTIONS) — a DoS/cost guard on the pairwise
# scorer, not a product decision about "how many matches are useful."
MAX_CANDIDATES = 500
MAX_SUGGESTIONS = 50
DEFAULT_MATCH_LIMIT = 10


class IntentProfile(BaseModel):
    """A user's explicit, revocable opt-in into complementary-intent matching.

    Immutable. Absence of an ``IntentProfile`` for a user is the ONLY "opted out"
    state this module models — there is no separate boolean to forget to check.
    ``seeking`` and ``offering`` are independent opaque tag sets; the SAME tag may
    legally appear in both (e.g. someone both seeking and offering "mentorship" in
    different contexts) — this module does not second-guess that.

    Direct ``IntentProfile(...)`` construction with hand-supplied ids is a lower-level
    primitive that is NOT validated against any real ``Profile`` (mirrors
    ``culture.CultureOptIn``'s same reservation); it exists for rehydrating an
    already-validated record. All application code that mints a NEW intent profile
    MUST use :func:`bind_intent_profile`. ``suggest_match`` / ``rank_matches`` still
    cross-check every profile/intent pair it is given (``_require_bound``), so a
    mismatched pair fails at use time either way.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: UserId
    tenant_id: TenantId
    seeking: tuple[IntentTag, ...]
    offering: tuple[IntentTag, ...]
    opted_in_at: datetime

    @field_validator("opted_in_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "opted_in_at")

    @field_validator("seeking", "offering")
    @classmethod
    def _bounded_and_deduped(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        # Tags are opaque, case-sensitive, not normalized (casefolding is a product
        # decision out of scope here) — mirrors culture.py's own tag discipline.
        if len(value) > MAX_TAGS:
            raise ValueError(f"tag list must not exceed {MAX_TAGS} tags")
        if len(set(value)) != len(value):
            raise ValueError("tag list must not contain duplicates")
        return value


def bind_intent_profile(
    user_profile: Profile,
    *,
    seeking: Sequence[str],
    offering: Sequence[str],
    opted_in_at: datetime,
) -> IntentProfile:
    """Build an ``IntentProfile`` bound to a real ``Profile`` (the canonical path).

    ``user_id``/``tenant_id`` are read FROM the profile, mirroring
    :func:`rendly.culture.bind_culture_opt_in` — an opt-in record's identity is
    derived from a validated parent, not hand-supplied. Note the profile used here is
    the EXISTING enterprise ``Profile`` (R-002), a deliberate placeholder actor model
    for the not-yet-built B2C identity (R-023) — see this module's docstring.
    """
    return IntentProfile(
        user_id=user_profile.user_id,
        tenant_id=user_profile.tenant_id,
        seeking=tuple(seeking),
        offering=tuple(offering),
        opted_in_at=opted_in_at,
    )


class IntentMatch(BaseModel):
    """A single deterministic complementary-intent match. Immutable.

    ``matched_as_seeker`` is the subset of the SUBJECT's ``seeking`` tags fulfilled by
    the CANDIDATE's ``offering``. ``matched_as_offerer`` is the subset of the
    SUBJECT's ``offering`` tags that fulfill the CANDIDATE's ``seeking``. Both are
    reported (rather than just a single combined score) so a future UI can show
    "why" a match was suggested without recomputing it.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_user_id: UserId
    subject_tenant_id: TenantId
    candidate_user_id: UserId
    candidate_tenant_id: TenantId
    matched_as_seeker: tuple[str, ...]
    matched_as_offerer: tuple[str, ...]
    score: int


def _require_bound(profile: Profile, intent: IntentProfile, *, label: str) -> None:
    if profile.user_id != intent.user_id or profile.tenant_id != intent.tenant_id:
        raise ValueError(f"{label} profile/intent pair do not describe the same user")


def suggest_match(
    subject_profile: Profile,
    subject_intent: IntentProfile,
    candidate_profile: Profile,
    candidate_intent: IntentProfile,
) -> IntentMatch | None:
    """Score a single subject/candidate pair, or ``None`` if no match applies.

    Complementary, DIRECTIONAL scoring (the "intent-based" part): a match exists when
    what the subject is ``seeking`` overlaps what the candidate is ``offering``, OR
    what the subject is ``offering`` overlaps what the candidate is ``seeking`` — a
    plain shared-tag intersection (culture.py's model) would miss exactly this
    complementary case (a "mentor" offering does not literally equal a "mentee"
    seeking string, but two identically-authored tags on opposite sides do match,
    e.g. subject seeking=("mentor",) + candidate offering=("mentor",)).

    Returns ``None`` (never a zero-score match) when:
    - the candidate IS the subject (no self-match),
    - neither direction has any overlap (nothing to base a match on).

    Cross-tenant pairs ARE matched — see this module's docstring "DELIBERATE
    DIVERGENCE" section; this is the opposite of ``culture.suggest_connection``,
    intentionally.

    Raises ``ValueError`` (refuses to compute, mirrors ``culture.suggest_connection``)
    if either profile/intent pair is internally inconsistent.
    """
    _require_bound(subject_profile, subject_intent, label="subject")
    _require_bound(candidate_profile, candidate_intent, label="candidate")

    if candidate_profile.user_id == subject_profile.user_id:
        return None

    as_seeker = sorted(set(subject_intent.seeking) & set(candidate_intent.offering))
    as_offerer = sorted(set(subject_intent.offering) & set(candidate_intent.seeking))
    if not as_seeker and not as_offerer:
        return None

    return IntentMatch(
        subject_user_id=subject_profile.user_id,
        subject_tenant_id=subject_profile.tenant_id,
        candidate_user_id=candidate_profile.user_id,
        candidate_tenant_id=candidate_profile.tenant_id,
        matched_as_seeker=tuple(as_seeker),
        matched_as_offerer=tuple(as_offerer),
        score=len(as_seeker) + len(as_offerer),
    )


def rank_matches(
    subject_profile: Profile,
    subject_intent: IntentProfile,
    candidates: Sequence[tuple[Profile, IntentProfile]],
    *,
    limit: int = DEFAULT_MATCH_LIMIT,
) -> list[IntentMatch]:
    """Rank complementary-intent matches for ``subject`` against a candidate pool.

    Deterministic: ties break on ``candidate_user_id`` ascending, so the same input
    always produces the same output (mirrors ``culture.rank_connections``). ``limit``
    is clamped to ``[0, MAX_SUGGESTIONS]``; ``candidates`` beyond ``MAX_CANDIDATES``
    is rejected outright rather than silently truncated.

    This function does no I/O and does NOT de-duplicate ``candidates`` by
    ``candidate_user_id`` — a caller passing the same candidate twice gets that
    candidate scored (and possibly listed) twice, exactly as
    ``culture.rank_connections`` behaves.
    """
    if len(candidates) > MAX_CANDIDATES:
        raise ValueError(f"candidates must not exceed {MAX_CANDIDATES} entries")
    bounded_limit = max(0, min(limit, MAX_SUGGESTIONS))

    matches = [
        match
        for candidate_profile, candidate_intent in candidates
        if (
            match := suggest_match(
                subject_profile, subject_intent, candidate_profile, candidate_intent
            )
        )
        is not None
    ]
    matches.sort(key=lambda m: (-m.score, m.candidate_user_id))
    return matches[:bounded_limit]
