"""R-023: the consumer-onboarding ordered-progression seam (onboarding.py)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from rendly.career import TOTAL_OPTIMIZATION_CHECKS, OptimizationGap, bind_career_goal
from rendly.enums import OrgRole
from rendly.intent import bind_intent_profile
from rendly.onboarding import ONBOARDING_STEP_ORDER, OnboardingStatus, onboarding_status
from rendly.profile import Profile

_NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"


def _profile(user_id: str, *, team: str | None = None) -> Profile:
    return Profile(user_id=user_id, tenant_id=_TENANT, org_role=OrgRole.MEMBER, team=team)


def _intent(profile: Profile, *, seeking: tuple[str, ...] = (), offering: tuple[str, ...] = ()):
    return bind_intent_profile(profile, seeking=seeking, offering=offering, opted_in_at=_NOW)


def _goal(profile: Profile, *, current_stage: str = "junior", target_stage: str = "senior"):
    return bind_career_goal(
        profile, current_stage=current_stage, target_stage=target_stage, opted_in_at=_NOW
    )


# --- ONBOARDING_STEP_ORDER ------------------------------------------------------------


def test_onboarding_step_order_covers_every_optimization_gap_exactly_once():
    assert len(ONBOARDING_STEP_ORDER) == TOTAL_OPTIMIZATION_CHECKS
    assert set(ONBOARDING_STEP_ORDER) == set(OptimizationGap)
    assert len(set(ONBOARDING_STEP_ORDER)) == len(ONBOARDING_STEP_ORDER)


# --- onboarding_status -----------------------------------------------------------------


def test_onboarding_status_for_bare_profile_starts_at_first_step():
    p = _profile("11111111-1111-4111-8111-111111111111")
    status = onboarding_status(p)
    assert status.next_step == ONBOARDING_STEP_ORDER[0] == OptimizationGap.MISSING_TEAM
    assert status.completed_steps == ()
    assert status.is_complete is False
    assert status.steps_completed == 0
    assert status.total_steps == TOTAL_OPTIMIZATION_CHECKS


def test_onboarding_status_is_complete_when_every_step_satisfied():
    p = _profile("11111111-1111-4111-8111-111111111111", team="platform")
    intent = _intent(p, seeking=("mentor",), offering=("react",))
    goal = _goal(p)
    status = onboarding_status(p, intent, goal)
    assert status.is_complete is True
    assert status.next_step is None
    assert status.completed_steps == ONBOARDING_STEP_ORDER
    assert status.steps_completed == TOTAL_OPTIMIZATION_CHECKS


def test_onboarding_status_advances_next_step_as_steps_complete():
    p = _profile("11111111-1111-4111-8111-111111111111", team="platform")
    status = onboarding_status(p)
    assert status.next_step == OptimizationGap.NO_SEEKING_TAGS
    assert status.completed_steps == (OptimizationGap.MISSING_TEAM,)

    intent = _intent(p, seeking=("mentor",))
    status = onboarding_status(p, intent)
    assert status.next_step == OptimizationGap.NO_OFFERING_TAGS

    intent = _intent(p, seeking=("mentor",), offering=("react",))
    status = onboarding_status(p, intent)
    assert status.next_step == OptimizationGap.NO_CAREER_GOAL

    status = onboarding_status(p, intent, _goal(p))
    assert status.next_step is None


def test_onboarding_status_next_step_follows_fixed_order_not_completion_order():
    # Complete the LAST step first (career goal) while the FIRST step (team) is
    # still outstanding: next_step must report the earliest outstanding step in
    # ONBOARDING_STEP_ORDER, not "career goal was the most recently completed."
    p = _profile("11111111-1111-4111-8111-111111111111")  # no team
    goal = _goal(p)
    status = onboarding_status(p, career_goal=goal)
    assert status.next_step == OptimizationGap.MISSING_TEAM
    assert OptimizationGap.NO_CAREER_GOAL in status.completed_steps
    assert OptimizationGap.MISSING_TEAM not in status.completed_steps


def test_onboarding_status_completed_steps_preserve_fixed_order():
    p = _profile("11111111-1111-4111-8111-111111111111", team="platform")
    goal = _goal(p)
    status = onboarding_status(p, career_goal=goal)
    assert status.completed_steps == (
        OptimizationGap.MISSING_TEAM,
        OptimizationGap.NO_CAREER_GOAL,
    )


def test_onboarding_status_steps_completed_matches_completed_steps_length():
    p = _profile("11111111-1111-4111-8111-111111111111", team="platform")
    intent = _intent(p, seeking=("mentor",))
    status = onboarding_status(p, intent)
    assert status.steps_completed == len(status.completed_steps)


def test_onboarding_status_rejects_mismatched_intent_profile():
    p = _profile("11111111-1111-4111-8111-111111111111")
    other = _profile("22222222-2222-4222-8222-222222222222")
    intent = _intent(other)
    with pytest.raises(ValueError):
        onboarding_status(p, intent)


def test_onboarding_status_rejects_mismatched_career_goal():
    p = _profile("11111111-1111-4111-8111-111111111111")
    other = _profile("22222222-2222-4222-8222-222222222222")
    goal = _goal(other)
    with pytest.raises(ValueError):
        onboarding_status(p, career_goal=goal)


def test_onboarding_status_is_frozen():
    p = _profile("11111111-1111-4111-8111-111111111111")
    status = onboarding_status(p)
    with pytest.raises(ValidationError):
        status.is_complete = True  # type: ignore[misc]


def test_onboarding_status_rejects_extra_key():
    with pytest.raises(ValidationError):
        OnboardingStatus(
            profile_user_id="11111111-1111-4111-8111-111111111111",
            profile_tenant_id=_TENANT,
            completed_steps=(),
            next_step=OptimizationGap.MISSING_TEAM,
            is_complete=False,
            steps_completed=0,
            total_steps=TOTAL_OPTIMIZATION_CHECKS,
            extra_field=True,
        )


def test_onboarding_status_uses_profile_identity():
    p = _profile("11111111-1111-4111-8111-111111111111")
    status = onboarding_status(p)
    assert status.profile_user_id == p.user_id
    assert status.profile_tenant_id == p.tenant_id
