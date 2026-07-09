"""Peer — a deterministic composition seam over the intent (R-016) and
career-trajectory (R-017) matching cores (R-018 = FORK A1/B1/C1/D1/E1).

HONESTY BOUNDARY (verbatim, non-removable): "Hyper-personalized peer-networking
interface" in the roadmap's task name is NOT implemented here as either
personalization-by-a-model or an interface. What ships is a DETERMINISTIC
COMBINATION of two already-deterministic component scorers —
:func:`rendly.intent.suggest_match` and :func:`rendly.career.suggest_trajectory_match`
— into a single ranked suggestion. No generated text, no model, no learned
weighting, no new signal beyond what a user already opted into via R-016's
``IntentProfile`` and/or R-017's ``CareerGoal``. This is a deliberate scope-down of
R-018 (~10-16h, 🏦 POST-INVESTMENT, third task of Rendly's B2C professional-
networking tier) to a minimal composition seam, in the same spirit as R-012's,
R-016's, and R-017's own scoped deliveries (see ADR-0012 §Decision, ADR-0016
§Decision, ADR-0017 §Decision) — this module reproduces their discipline rather
than inventing a new one.

"interface" ships as NEITHER a REST endpoint NOR a frontend component — Rendly has
no frontend package to extend, and this task has no persistence-backed identity
store to build a real interface against (both R-016's and R-017's own opt-in
stores are still-deferred follow-ups). See ADR-0018 for the full reasoning.

NOT BUILT HERE (mirrors ADR-0016's/ADR-0017's own lists): real B2C consumer
identity/onboarding (R-023, still unshipped) — this module operates over the
EXISTING enterprise ``Profile`` domain (R-002) plus the existing ``IntentProfile``
(R-016) / ``CareerGoal`` (R-017) opt-in objects as a placeholder actor model,
exactly as R-012/R-016/R-017 did. No persistence, no REST/wire surface, no
frontend, no ML.

PRIVACY-CONTROLLED, by construction, not by policy (mirrors ``culture.py``/
``intent.py``/``career.py``): a component score is computed only when BOTH sides of
a pair supply the matching opt-in object; a user who opted into neither
``IntentProfile`` nor ``CareerGoal`` structurally cannot appear as a subject or a
candidate here at all (every argument is optional, but at least one component
match is required for a ``PeerSuggestion`` to be constructed — see Fork B).

DELIBERATE DIVERGENCE FROM ``culture.py`` (R-012), consistent WITH ``intent.py``
(R-016) / ``career.py`` (R-017): peer suggestion does NOT reject cross-tenant
pairs. Both composed signals already allow cross-tenant matching (B2C
professional networking is definitionally cross-company, see ADR-0016 Fork B) —
a composition of the two must not silently introduce a restriction neither
component has.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict

from .career import CareerGoal, TrajectoryMatch, suggest_trajectory_match
from .identifiers import TenantId, UserId
from .intent import IntentMatch, IntentProfile, suggest_match
from .profile import Profile

# Bounds the candidate pool + the result set of a single ranking call (mirrors
# intent.py's/career.py's MAX_CANDIDATES/MAX_SUGGESTIONS at the same magnitudes — see
# ADR-0018 Fork E: this seam's per-candidate cost is strictly higher than either
# component alone, so the conservative choice is to reuse rather than loosen them).
MAX_CANDIDATES = 500
MAX_SUGGESTIONS = 50
DEFAULT_MATCH_LIMIT = 10


class PeerSuggestion(BaseModel):
    """A single deterministic composed peer suggestion. Immutable.

    ``intent_match`` / ``trajectory_match`` are the component results this
    suggestion was combined from — at least one is always non-``None`` (never an
    all-``None`` result, mirroring ``IntentMatch``'s/``TrajectoryMatch``'s own
    "never a zero-score match" rule one level up). Both are reported (rather than
    just the combined score) so a future caller can show "why" a suggestion was
    made without recomputing it. ``score`` is always the sum of whichever
    component scores were computed — never derived independently, so it can never
    disagree with its components (see ADR-0018 Fork C).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_user_id: UserId
    subject_tenant_id: TenantId
    candidate_user_id: UserId
    candidate_tenant_id: TenantId
    intent_match: IntentMatch | None
    trajectory_match: TrajectoryMatch | None
    score: int


def suggest_peer(
    subject_profile: Profile,
    candidate_profile: Profile,
    *,
    subject_intent: IntentProfile | None = None,
    candidate_intent: IntentProfile | None = None,
    subject_goal: CareerGoal | None = None,
    candidate_goal: CareerGoal | None = None,
) -> PeerSuggestion | None:
    """Compose a single subject/candidate pair's intent + trajectory signals.

    The intent component is computed only when BOTH ``subject_intent`` and
    ``candidate_intent`` are supplied (mirrors ``intent.suggest_match``'s own
    required-pair signature — a match cannot be computed from one side alone);
    the trajectory component is computed only when BOTH ``subject_goal`` and
    ``candidate_goal`` are supplied. A missing opt-in on either side simply omits
    that ONE component — it does not poison the other (see ADR-0018 Fork B).

    Returns ``None`` when:
    - the candidate IS the subject (both component scorers already refuse this),
    - neither component signal was suppliable (no opt-in overlap to compose from),
    - both suppliable components individually score no match.

    Cross-tenant pairs ARE matched — see this module's docstring "DELIBERATE
    DIVERGENCE" section; matches ``intent.suggest_match`` and
    ``career.suggest_trajectory_match``, the opposite of
    ``culture.suggest_connection``.

    Raises ``ValueError`` (mirrors both component functions) if any supplied
    profile/opt-in pair is internally inconsistent.
    """
    intent_match: IntentMatch | None = None
    if subject_intent is not None and candidate_intent is not None:
        intent_match = suggest_match(
            subject_profile, subject_intent, candidate_profile, candidate_intent
        )

    trajectory_match: TrajectoryMatch | None = None
    if subject_goal is not None and candidate_goal is not None:
        trajectory_match = suggest_trajectory_match(
            subject_profile, subject_goal, candidate_profile, candidate_goal
        )

    if intent_match is None and trajectory_match is None:
        return None

    score = (intent_match.score if intent_match else 0) + (
        trajectory_match.score if trajectory_match else 0
    )

    return PeerSuggestion(
        subject_user_id=subject_profile.user_id,
        subject_tenant_id=subject_profile.tenant_id,
        candidate_user_id=candidate_profile.user_id,
        candidate_tenant_id=candidate_profile.tenant_id,
        intent_match=intent_match,
        trajectory_match=trajectory_match,
        score=score,
    )


def rank_peers(
    subject_profile: Profile,
    candidates: Sequence[tuple[Profile, IntentProfile | None, CareerGoal | None]],
    *,
    subject_intent: IntentProfile | None = None,
    subject_goal: CareerGoal | None = None,
    limit: int = DEFAULT_MATCH_LIMIT,
) -> list[PeerSuggestion]:
    """Rank composed peer suggestions for ``subject`` against a candidate pool.

    Each candidate entry is ``(candidate_profile, candidate_intent, candidate_goal)``
    — either opt-in may be ``None`` for a candidate who has not opted into that
    signal (see :func:`suggest_peer`). Deterministic: ties break on
    ``candidate_user_id`` ascending, so the same input always produces the same
    output (mirrors ``intent.rank_matches``/``career.rank_trajectory_matches``).
    ``limit`` is clamped to ``[0, MAX_SUGGESTIONS]``; ``candidates`` beyond
    ``MAX_CANDIDATES`` is rejected outright rather than silently truncated.

    This function does no I/O and does NOT de-duplicate ``candidates`` by
    ``candidate_user_id`` — a caller passing the same candidate twice gets that
    candidate scored (and possibly listed) twice, mirrors both component
    ``rank_*`` functions.
    """
    if len(candidates) > MAX_CANDIDATES:
        raise ValueError(f"candidates must not exceed {MAX_CANDIDATES} entries")
    bounded_limit = max(0, min(limit, MAX_SUGGESTIONS))

    suggestions = [
        suggestion
        for candidate_profile, candidate_intent, candidate_goal in candidates
        if (
            suggestion := suggest_peer(
                subject_profile,
                candidate_profile,
                subject_intent=subject_intent,
                candidate_intent=candidate_intent,
                subject_goal=subject_goal,
                candidate_goal=candidate_goal,
            )
        )
        is not None
    ]
    suggestions.sort(key=lambda s: (-s.score, s.candidate_user_id))
    return suggestions[:bounded_limit]
