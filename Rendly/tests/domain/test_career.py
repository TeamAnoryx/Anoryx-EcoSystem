"""R-017: the career-trajectory matching + profile-optimization seam (career.py)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from rendly.career import (
    MAX_SUGGESTIONS,
    TOTAL_OPTIMIZATION_CHECKS,
    CareerGoal,
    OptimizationGap,
    bind_career_goal,
    optimization_gaps,
    rank_trajectory_matches,
    suggest_trajectory_match,
)
from rendly.enums import OrgRole
from rendly.intent import bind_intent_profile
from rendly.profile import Profile

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_OTHER_TENANT = "99999999-9999-4999-8999-999999999999"


def _profile(user_id: str, tenant_id: str = _TENANT, team: str | None = None) -> Profile:
    return Profile(user_id=user_id, tenant_id=tenant_id, org_role=OrgRole.MEMBER, team=team)


def _goal(profile: Profile, *, current_stage: str, target_stage: str) -> CareerGoal:
    return bind_career_goal(
        profile, current_stage=current_stage, target_stage=target_stage, opted_in_at=_NOW
    )


# --- CareerGoal construction --------------------------------------------------------


def test_bind_career_goal_derives_ids_from_profile():
    p = _profile("11111111-1111-4111-8111-111111111111")
    goal = _goal(p, current_stage="senior_engineer", target_stage="staff_engineer")
    assert goal.user_id == p.user_id
    assert goal.tenant_id == p.tenant_id
    assert goal.current_stage == "senior_engineer"
    assert goal.target_stage == "staff_engineer"


def test_career_goal_is_frozen():
    p = _profile("11111111-1111-4111-8111-111111111111")
    goal = _goal(p, current_stage="senior_engineer", target_stage="staff_engineer")
    with pytest.raises(ValidationError):
        goal.target_stage = "principal_engineer"  # type: ignore[misc]


def test_career_goal_rejects_naive_datetime():
    p = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        CareerGoal(
            user_id=p.user_id,
            tenant_id=p.tenant_id,
            current_stage="senior_engineer",
            target_stage="staff_engineer",
            opted_in_at=datetime(2026, 7, 9, 12, 0, 0),  # naive
        )


def test_career_goal_rejects_matching_current_and_target_stage():
    p = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError, match="target_stage"):
        _goal(p, current_stage="staff_engineer", target_stage="staff_engineer")


def test_career_goal_rejects_extra_key():
    p = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        CareerGoal(
            user_id=p.user_id,
            tenant_id=p.tenant_id,
            current_stage="senior_engineer",
            target_stage="staff_engineer",
            opted_in_at=_NOW,
            embedding=[0.1, 0.2],
        )


# --- suggest_trajectory_match --------------------------------------------------------


def test_suggest_trajectory_match_candidate_is_mentor():
    # subject wants to become "staff_engineer"; candidate is already there.
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    match = suggest_trajectory_match(
        subject,
        _goal(subject, current_stage="senior_engineer", target_stage="staff_engineer"),
        candidate,
        _goal(candidate, current_stage="staff_engineer", target_stage="principal_engineer"),
    )
    assert match is not None
    assert match.candidate_is_mentor is True
    assert match.candidate_is_mentee is False
    assert match.score == 1
    assert match.subject_user_id == subject.user_id
    assert match.candidate_user_id == candidate.user_id


def test_suggest_trajectory_match_candidate_is_mentee():
    # candidate wants to become what the subject already is.
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    match = suggest_trajectory_match(
        subject,
        _goal(subject, current_stage="staff_engineer", target_stage="principal_engineer"),
        candidate,
        _goal(candidate, current_stage="senior_engineer", target_stage="staff_engineer"),
    )
    assert match is not None
    assert match.candidate_is_mentor is False
    assert match.candidate_is_mentee is True
    assert match.score == 1


def test_suggest_trajectory_match_scores_both_directions_together():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    match = suggest_trajectory_match(
        subject,
        _goal(subject, current_stage="a", target_stage="b"),
        candidate,
        _goal(candidate, current_stage="b", target_stage="a"),
    )
    assert match is not None
    assert match.candidate_is_mentor is True
    assert match.candidate_is_mentee is True
    assert match.score == 2


def test_suggest_trajectory_match_none_without_any_overlap():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    match = suggest_trajectory_match(
        subject,
        _goal(subject, current_stage="senior_engineer", target_stage="staff_engineer"),
        candidate,
        _goal(candidate, current_stage="product_manager", target_stage="senior_pm"),
    )
    assert match is None


def test_suggest_trajectory_match_none_for_self():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_goal = _goal(subject, current_stage="senior_engineer", target_stage="staff_engineer")
    match = suggest_trajectory_match(subject, subject_goal, subject, subject_goal)
    assert match is None


def test_suggest_trajectory_match_allows_cross_tenant_pair():
    # Deliberate divergence from culture.suggest_connection (R-012), mirroring
    # intent.suggest_match (R-016): B2C career mentorship is cross-company.
    subject = _profile("11111111-1111-4111-8111-111111111111", tenant_id=_TENANT)
    candidate = _profile("22222222-2222-4222-8222-222222222222", tenant_id=_OTHER_TENANT)
    match = suggest_trajectory_match(
        subject,
        _goal(subject, current_stage="senior_engineer", target_stage="staff_engineer"),
        candidate,
        _goal(candidate, current_stage="staff_engineer", target_stage="principal_engineer"),
    )
    assert match is not None
    assert match.subject_tenant_id == _TENANT
    assert match.candidate_tenant_id == _OTHER_TENANT


def test_suggest_trajectory_match_rejects_mismatched_profile_goal_pair():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    other = _profile("22222222-2222-4222-8222-222222222222")
    candidate = _profile("33333333-3333-4333-8333-333333333333")
    with pytest.raises(ValueError, match="subject"):
        suggest_trajectory_match(
            subject,
            _goal(other, current_stage="senior_engineer", target_stage="staff_engineer"),
            candidate,
            _goal(candidate, current_stage="staff_engineer", target_stage="principal_engineer"),
        )


def test_suggest_trajectory_match_rejects_mismatched_candidate_pair():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    other = _profile("33333333-3333-4333-8333-333333333333")
    with pytest.raises(ValueError, match="candidate"):
        suggest_trajectory_match(
            subject,
            _goal(subject, current_stage="senior_engineer", target_stage="staff_engineer"),
            candidate,
            _goal(other, current_stage="staff_engineer", target_stage="principal_engineer"),
        )


# --- rank_trajectory_matches ----------------------------------------------------------


def test_rank_trajectory_matches_orders_by_score_desc_then_user_id_asc():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_goal = _goal(subject, current_stage="a", target_stage="b")

    mutual_a = _profile("bbbbbbbb-2222-4222-8222-222222222222")  # score=2
    mutual_b = _profile("aaaaaaaa-3333-4333-8333-333333333333")  # score=2
    mentor_only = _profile("44444444-4444-4444-8444-444444444444")  # score=1

    candidates = [
        (mutual_a, _goal(mutual_a, current_stage="b", target_stage="a")),
        (mutual_b, _goal(mutual_b, current_stage="b", target_stage="a")),
        (mentor_only, _goal(mentor_only, current_stage="b", target_stage="c")),
    ]

    ranked = rank_trajectory_matches(subject, subject_goal, candidates)
    assert [m.candidate_user_id for m in ranked] == [
        mutual_b.user_id,
        mutual_a.user_id,
        mentor_only.user_id,
    ]
    assert [m.score for m in ranked] == [2, 2, 1]


def test_rank_trajectory_matches_filters_out_none_results():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_goal = _goal(subject, current_stage="a", target_stage="b")

    no_overlap = _profile("22222222-2222-4222-8222-222222222222")
    itself = subject

    candidates = [
        (no_overlap, _goal(no_overlap, current_stage="x", target_stage="y")),
        (itself, subject_goal),
    ]

    assert rank_trajectory_matches(subject, subject_goal, candidates) == []


def test_rank_trajectory_matches_respects_limit_and_clamps_to_max():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_goal = _goal(subject, current_stage="a", target_stage="b")
    candidates = [
        (
            _profile(f"{i:08d}-0000-4000-8000-000000000000"),
            _goal(
                _profile(f"{i:08d}-0000-4000-8000-000000000000"),
                current_stage="b",
                target_stage="c",
            ),
        )
        for i in range(3)
    ]

    assert len(rank_trajectory_matches(subject, subject_goal, candidates, limit=2)) == 2
    assert len(
        rank_trajectory_matches(subject, subject_goal, candidates, limit=MAX_SUGGESTIONS + 1000)
    ) <= len(candidates)


def test_rank_trajectory_matches_rejects_oversized_candidate_pool():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_goal = _goal(subject, current_stage="a", target_stage="b")
    huge_candidate = _profile("22222222-2222-4222-8222-222222222222")
    huge_goal = _goal(huge_candidate, current_stage="b", target_stage="c")
    candidates = [(huge_candidate, huge_goal)] * 501

    with pytest.raises(ValueError, match="candidates"):
        rank_trajectory_matches(subject, subject_goal, candidates)


def test_rank_trajectory_matches_includes_cross_tenant_candidates():
    subject = _profile("11111111-1111-4111-8111-111111111111", tenant_id=_TENANT)
    subject_goal = _goal(subject, current_stage="a", target_stage="b")
    other_tenant_candidate = _profile(
        "22222222-2222-4222-8222-222222222222", tenant_id=_OTHER_TENANT
    )
    candidates = [
        (other_tenant_candidate, _goal(other_tenant_candidate, current_stage="b", target_stage="c"))
    ]

    ranked = rank_trajectory_matches(subject, subject_goal, candidates)
    assert len(ranked) == 1
    assert ranked[0].candidate_tenant_id == _OTHER_TENANT


# --- optimization_gaps ----------------------------------------------------------------


def test_optimization_gaps_reports_all_gaps_for_bare_profile():
    p = _profile("11111111-1111-4111-8111-111111111111", team=None)
    report = optimization_gaps(p)
    assert report.gaps == (
        OptimizationGap.MISSING_TEAM,
        OptimizationGap.NO_SEEKING_TAGS,
        OptimizationGap.NO_OFFERING_TAGS,
        OptimizationGap.NO_CAREER_GOAL,
    )
    assert report.completeness_score == 0
    assert report.total_checks == TOTAL_OPTIMIZATION_CHECKS
    assert report.profile_user_id == p.user_id
    assert report.profile_tenant_id == p.tenant_id


def test_optimization_gaps_reports_no_gaps_for_fully_optimized_profile():
    p = _profile("11111111-1111-4111-8111-111111111111", team="platform")
    intent = bind_intent_profile(p, seeking=("mentor",), offering=("python",), opted_in_at=_NOW)
    goal = _goal(p, current_stage="senior_engineer", target_stage="staff_engineer")
    report = optimization_gaps(p, intent, goal)
    assert report.gaps == ()
    assert report.completeness_score == TOTAL_OPTIMIZATION_CHECKS


def test_optimization_gaps_reports_partial_gaps():
    p = _profile("11111111-1111-4111-8111-111111111111", team="platform")
    intent = bind_intent_profile(p, seeking=("mentor",), offering=(), opted_in_at=_NOW)
    report = optimization_gaps(p, intent)
    assert report.gaps == (OptimizationGap.NO_OFFERING_TAGS, OptimizationGap.NO_CAREER_GOAL)
    assert report.completeness_score == 2


def test_optimization_gaps_rejects_mismatched_intent_profile():
    p = _profile("11111111-1111-4111-8111-111111111111")
    other = _profile("22222222-2222-4222-8222-222222222222")
    intent = bind_intent_profile(other, seeking=("mentor",), offering=(), opted_in_at=_NOW)
    with pytest.raises(ValueError, match="intent_profile"):
        optimization_gaps(p, intent)


def test_optimization_gaps_rejects_mismatched_career_goal():
    p = _profile("11111111-1111-4111-8111-111111111111")
    other = _profile("22222222-2222-4222-8222-222222222222")
    goal = _goal(other, current_stage="senior_engineer", target_stage="staff_engineer")
    with pytest.raises(ValueError, match="profile"):
        optimization_gaps(p, career_goal=goal)


def test_optimization_gaps_is_a_fixed_checklist_not_free_form():
    # The whole point of the HONESTY BOUNDARY: only these four named values can
    # ever appear, never generated/free-form text.
    p = _profile("11111111-1111-4111-8111-111111111111")
    report = optimization_gaps(p)
    assert all(isinstance(g, OptimizationGap) for g in report.gaps)
    assert set(OptimizationGap) == {
        OptimizationGap.MISSING_TEAM,
        OptimizationGap.NO_SEEKING_TAGS,
        OptimizationGap.NO_OFFERING_TAGS,
        OptimizationGap.NO_CAREER_GOAL,
    }
