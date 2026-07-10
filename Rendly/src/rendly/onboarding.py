"""Onboarding — a deterministic, ORDERED progression seam over R-017's existing
profile-optimization checklist (R-023 = FORK A1/B1/C1).

HONESTY BOUNDARY (verbatim, non-removable): "Consumer onboarding" ships here as
a deterministic ORDERING + "what's the next step" layer over
:func:`rendly.career.optimization_gaps` — no new opt-in type, no real B2C
consumer identity/signup/auth model, no persistence, no REST/wire surface, no
UI/wizard component. Every prior B2C-tier module (``culture.py``/``intent.py``/
``career.py``/``peer.py``/``privacy.py``/``event_discovery.py``/
``opportunity.py``/``mentorship.py``) named "real B2C consumer identity/
onboarding (R-023, still unshipped)" as the thing IT was not building; this
module is R-023 itself, scoped with the identical discipline — see ADR-0023 for
the full reasoning on why a real identity/signup/auth model is not built here
either.

NOT BUILT HERE: a real B2C consumer identity/signup/auth model. This module
still operates over the EXISTING enterprise ``Profile`` (R-002) plus the
existing ``IntentProfile`` (R-016) / ``CareerGoal`` (R-017) opt-in objects as
the placeholder actor model every prior B2C seam has used — inventing a real
identity/persistence/auth layer is a separate, much larger unit of work (its
own schema, migrations, RLS posture) that does not fit inside one scoped seam
task (see ADR-0023 Fork A).

WHAT THIS MODULE ADDS THAT ``career.optimization_gaps`` DOES NOT: an explicit,
FIXED step ORDER (:data:`ONBOARDING_STEP_ORDER`) plus a single "next required
step" resolver (:func:`onboarding_status`) — the actual guided-flow question
("what should this person be asked to do NEXT") that an unordered gap REPORT
does not answer by itself. This is a thin composition, not a reimplementation:
``onboarding_status`` calls ``optimization_gaps`` exactly once and derives
everything else from its result, so the two can never disagree (mirrors
``peer.py``'s composition-over-duplication discipline, ADR-0018).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from .career import CareerGoal, OptimizationGap, optimization_gaps
from .identifiers import TenantId, UserId
from .intent import IntentProfile
from .profile import Profile

# The FIXED onboarding order `onboarding_status` walks: team affiliation first
# (an org-level fact, cheapest to supply), then the two intent-tag checks
# (needed before a user can appear in R-016 matching at all), then the career
# goal (the deepest opt-in, gating R-017 matching). A DELIBERATE sequencing
# decision, not `OptimizationGap`'s declaration order by coincidence (mirrors
# `mentorship.py`'s `_LEVEL_RANK` — ordering is named explicitly, not assumed
# from an enum's source-line position; see ADR-0023 Fork B).
ONBOARDING_STEP_ORDER: tuple[OptimizationGap, ...] = (
    OptimizationGap.MISSING_TEAM,
    OptimizationGap.NO_SEEKING_TAGS,
    OptimizationGap.NO_OFFERING_TAGS,
    OptimizationGap.NO_CAREER_GOAL,
)


class OnboardingStatus(BaseModel):
    """The result of :func:`onboarding_status`. Immutable.

    ``completed_steps`` and ``next_step`` partition :data:`ONBOARDING_STEP_ORDER`
    by the SAME gap set ``optimization_gaps`` already computed — neither is
    independently recomputed, so this record can never disagree with the
    underlying ``ProfileOptimizationReport`` it was derived from.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_user_id: UserId
    profile_tenant_id: TenantId
    completed_steps: tuple[OptimizationGap, ...]
    next_step: OptimizationGap | None
    is_complete: bool
    steps_completed: int
    total_steps: int


def onboarding_status(
    profile: Profile,
    intent_profile: IntentProfile | None = None,
    career_goal: CareerGoal | None = None,
) -> OnboardingStatus:
    """Resolve the ordered onboarding progression for one user.

    Thin composition over :func:`rendly.career.optimization_gaps` (see this
    module's docstring) — every field below is derived from that single call,
    never recomputed independently.

    ``next_step`` is the FIRST entry of :data:`ONBOARDING_STEP_ORDER` still
    outstanding (i.e. still present in the underlying report's ``gaps``), or
    ``None`` once every step is complete — the fixed order is what turns an
    unordered gap set into a single, deterministic "ask them this next" answer.
    ``is_complete`` is ``next_step is None``, never computed independently of
    it.

    Raises ``ValueError`` (mirrors ``optimization_gaps``) if a supplied
    ``intent_profile`` or ``career_goal`` does not belong to ``profile``.
    """
    report = optimization_gaps(profile, intent_profile, career_goal)
    outstanding = set(report.gaps)

    completed_steps = tuple(step for step in ONBOARDING_STEP_ORDER if step not in outstanding)
    next_step = next((step for step in ONBOARDING_STEP_ORDER if step in outstanding), None)

    return OnboardingStatus(
        profile_user_id=report.profile_user_id,
        profile_tenant_id=report.profile_tenant_id,
        completed_steps=completed_steps,
        next_step=next_step,
        is_complete=next_step is None,
        steps_completed=report.completeness_score,
        total_steps=report.total_checks,
    )
