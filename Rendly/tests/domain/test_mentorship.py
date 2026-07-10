"""R-022: the tech-stack mentorship-matching seam (mentorship.py)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from rendly.enums import OrgRole
from rendly.mentorship import (
    MAX_SUGGESTIONS,
    MentorshipMatch,
    ProficiencyLevel,
    TechStackProficiency,
    bind_tech_stack_proficiency,
    rank_mentors,
    suggest_mentorship_match,
)
from rendly.profile import Profile

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_OTHER_TENANT = "99999999-9999-4999-8999-999999999999"


def _profile(user_id: str, tenant_id: str = _TENANT) -> Profile:
    return Profile(user_id=user_id, tenant_id=tenant_id, org_role=OrgRole.MEMBER)


def _proficiency(
    profile: Profile, *, stack: str = "react", level: ProficiencyLevel = ProficiencyLevel.BEGINNER
) -> TechStackProficiency:
    return bind_tech_stack_proficiency(profile, stack=stack, level=level, opted_in_at=_NOW)


def _match_with_score(
    *, mentee_level: ProficiencyLevel, mentor_level: ProficiencyLevel, score: int
) -> MentorshipMatch:
    return MentorshipMatch(
        mentee_user_id="11111111-1111-4111-8111-111111111111",
        mentee_tenant_id=_TENANT,
        mentor_user_id="22222222-2222-4222-8222-222222222222",
        mentor_tenant_id=_TENANT,
        stack="react",
        mentee_level=mentee_level,
        mentor_level=mentor_level,
        score=score,
    )


# --- TechStackProficiency construction --------------------------------------------------


def test_bind_tech_stack_proficiency_derives_ids_from_profile():
    p = _profile("11111111-1111-4111-8111-111111111111")
    prof = _proficiency(p, stack="react", level=ProficiencyLevel.EXPERT)
    assert prof.user_id == p.user_id
    assert prof.tenant_id == p.tenant_id
    assert prof.stack == "react"
    assert prof.level == ProficiencyLevel.EXPERT


def test_tech_stack_proficiency_is_frozen():
    p = _profile("11111111-1111-4111-8111-111111111111")
    prof = _proficiency(p)
    with pytest.raises(ValidationError):
        prof.level = ProficiencyLevel.EXPERT  # type: ignore[misc]


def test_tech_stack_proficiency_rejects_naive_datetime():
    p = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        TechStackProficiency(
            user_id=p.user_id,
            tenant_id=p.tenant_id,
            stack="react",
            level=ProficiencyLevel.BEGINNER,
            opted_in_at=datetime(2026, 7, 9, 12, 0, 0),  # naive
        )


def test_tech_stack_proficiency_rejects_extra_key():
    p = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        TechStackProficiency(
            user_id=p.user_id,
            tenant_id=p.tenant_id,
            stack="react",
            level=ProficiencyLevel.BEGINNER,
            opted_in_at=_NOW,
            years_experience=5,
        )


def test_a_user_can_hold_proficiency_in_multiple_stacks():
    p = _profile("11111111-1111-4111-8111-111111111111")
    react = _proficiency(p, stack="react", level=ProficiencyLevel.EXPERT)
    rust = _proficiency(p, stack="rust", level=ProficiencyLevel.BEGINNER)
    assert react.stack != rust.stack
    assert react.user_id == rust.user_id == p.user_id


# --- suggest_mentorship_match --------------------------------------------------------------


def test_suggest_mentorship_match_scores_proficiency_gap():
    mentee = _profile("11111111-1111-4111-8111-111111111111")
    mentor = _profile("22222222-2222-4222-8222-222222222222")
    match = suggest_mentorship_match(
        mentee,
        _proficiency(mentee, stack="react", level=ProficiencyLevel.BEGINNER),
        mentor,
        _proficiency(mentor, stack="react", level=ProficiencyLevel.EXPERT),
    )
    assert match is not None
    assert match.stack == "react"
    assert match.mentee_level == ProficiencyLevel.BEGINNER
    assert match.mentor_level == ProficiencyLevel.EXPERT
    assert match.score == 3


def test_suggest_mentorship_match_scores_a_single_adjacent_level_gap():
    mentee = _profile("11111111-1111-4111-8111-111111111111")
    mentor = _profile("22222222-2222-4222-8222-222222222222")
    match = suggest_mentorship_match(
        mentee,
        _proficiency(mentee, stack="react", level=ProficiencyLevel.BEGINNER),
        mentor,
        _proficiency(mentor, stack="react", level=ProficiencyLevel.INTERMEDIATE),
    )
    assert match is not None
    assert match.score == 1


def test_mentorship_match_rejects_score_inconsistent_with_level_gap():
    with pytest.raises(ValidationError):
        _match_with_score(
            mentee_level=ProficiencyLevel.BEGINNER,
            mentor_level=ProficiencyLevel.EXPERT,
            score=1,  # real gap is 3, not 1
        )


def test_mentorship_match_rejects_nonpositive_score():
    with pytest.raises(ValidationError):
        _match_with_score(
            mentee_level=ProficiencyLevel.EXPERT,
            mentor_level=ProficiencyLevel.BEGINNER,
            score=-3,  # mentor ranks lower than mentee
        )


def test_suggest_mentorship_match_none_for_same_level():
    mentee = _profile("11111111-1111-4111-8111-111111111111")
    mentor = _profile("22222222-2222-4222-8222-222222222222")
    match = suggest_mentorship_match(
        mentee,
        _proficiency(mentee, stack="react", level=ProficiencyLevel.INTERMEDIATE),
        mentor,
        _proficiency(mentor, stack="react", level=ProficiencyLevel.INTERMEDIATE),
    )
    assert match is None


def test_suggest_mentorship_match_none_when_mentor_ranks_lower():
    mentee = _profile("11111111-1111-4111-8111-111111111111")
    mentor = _profile("22222222-2222-4222-8222-222222222222")
    match = suggest_mentorship_match(
        mentee,
        _proficiency(mentee, stack="react", level=ProficiencyLevel.ADVANCED),
        mentor,
        _proficiency(mentor, stack="react", level=ProficiencyLevel.BEGINNER),
    )
    assert match is None


def test_suggest_mentorship_match_none_for_different_stacks():
    mentee = _profile("11111111-1111-4111-8111-111111111111")
    mentor = _profile("22222222-2222-4222-8222-222222222222")
    match = suggest_mentorship_match(
        mentee,
        _proficiency(mentee, stack="react", level=ProficiencyLevel.BEGINNER),
        mentor,
        _proficiency(mentor, stack="vue", level=ProficiencyLevel.EXPERT),
    )
    assert match is None


def test_suggest_mentorship_match_stack_is_exact_not_fuzzy():
    mentee = _profile("11111111-1111-4111-8111-111111111111")
    mentor = _profile("22222222-2222-4222-8222-222222222222")
    match = suggest_mentorship_match(
        mentee,
        _proficiency(mentee, stack="React", level=ProficiencyLevel.BEGINNER),
        mentor,
        _proficiency(mentor, stack="react", level=ProficiencyLevel.EXPERT),
    )
    assert match is None


def test_suggest_mentorship_match_none_for_self():
    mentee = _profile("11111111-1111-4111-8111-111111111111")
    prof = _proficiency(mentee, stack="react", level=ProficiencyLevel.BEGINNER)
    match = suggest_mentorship_match(mentee, prof, mentee, prof)
    assert match is None


def test_suggest_mentorship_match_allows_cross_tenant_pair():
    mentee = _profile("11111111-1111-4111-8111-111111111111", tenant_id=_TENANT)
    mentor = _profile("22222222-2222-4222-8222-222222222222", tenant_id=_OTHER_TENANT)
    match = suggest_mentorship_match(
        mentee,
        _proficiency(mentee, stack="react", level=ProficiencyLevel.BEGINNER),
        mentor,
        _proficiency(mentor, stack="react", level=ProficiencyLevel.EXPERT),
    )
    assert match is not None
    assert match.mentee_tenant_id == _TENANT
    assert match.mentor_tenant_id == _OTHER_TENANT


def test_suggest_mentorship_match_rejects_mismatched_mentee_pair():
    mentee = _profile("11111111-1111-4111-8111-111111111111")
    other = _profile("22222222-2222-4222-8222-222222222222")
    mentor = _profile("33333333-3333-4333-8333-333333333333")
    with pytest.raises(ValueError, match="mentee"):
        suggest_mentorship_match(
            mentee,
            _proficiency(other, level=ProficiencyLevel.BEGINNER),
            mentor,
            _proficiency(mentor, level=ProficiencyLevel.EXPERT),
        )


def test_suggest_mentorship_match_rejects_mismatched_mentor_pair():
    mentee = _profile("11111111-1111-4111-8111-111111111111")
    mentor = _profile("22222222-2222-4222-8222-222222222222")
    other = _profile("33333333-3333-4333-8333-333333333333")
    with pytest.raises(ValueError, match="mentor"):
        suggest_mentorship_match(
            mentee,
            _proficiency(mentee, level=ProficiencyLevel.BEGINNER),
            mentor,
            _proficiency(other, level=ProficiencyLevel.EXPERT),
        )


# --- rank_mentors ----------------------------------------------------------------------------


def test_rank_mentors_orders_by_score_desc_then_mentor_id_asc():
    mentee = _profile("11111111-1111-4111-8111-111111111111")
    mentee_prof = _proficiency(mentee, stack="react", level=ProficiencyLevel.BEGINNER)

    high_a = _profile("bbbbbbbb-2222-4222-8222-222222222222")
    high_b = _profile("aaaaaaaa-3333-4333-8333-333333333333")
    low = _profile("44444444-4444-4444-8444-444444444444")

    candidates = [
        (high_a, _proficiency(high_a, stack="react", level=ProficiencyLevel.EXPERT)),
        (high_b, _proficiency(high_b, stack="react", level=ProficiencyLevel.EXPERT)),
        (low, _proficiency(low, stack="react", level=ProficiencyLevel.INTERMEDIATE)),
    ]

    ranked = rank_mentors(mentee, mentee_prof, candidates)
    assert [m.mentor_user_id for m in ranked] == [
        high_b.user_id,
        high_a.user_id,
        low.user_id,
    ]
    assert [m.score for m in ranked] == [3, 3, 1]


def test_rank_mentors_filters_out_none_results():
    mentee = _profile("11111111-1111-4111-8111-111111111111")
    mentee_prof = _proficiency(mentee, stack="react", level=ProficiencyLevel.ADVANCED)

    same_level = _profile("22222222-2222-4222-8222-222222222222")
    different_stack = _profile("33333333-3333-4333-8333-333333333333")
    itself = mentee

    candidates = [
        (same_level, _proficiency(same_level, stack="react", level=ProficiencyLevel.ADVANCED)),
        (
            different_stack,
            _proficiency(different_stack, stack="vue", level=ProficiencyLevel.EXPERT),
        ),
        (itself, mentee_prof),
    ]

    assert rank_mentors(mentee, mentee_prof, candidates) == []


def test_rank_mentors_respects_limit_and_clamps_to_max():
    mentee = _profile("11111111-1111-4111-8111-111111111111")
    mentee_prof = _proficiency(mentee, stack="react", level=ProficiencyLevel.BEGINNER)
    candidates = [
        (
            _profile(f"{i:08d}-0000-4000-8000-000000000000"),
            _proficiency(
                _profile(f"{i:08d}-0000-4000-8000-000000000000"),
                stack="react",
                level=ProficiencyLevel.EXPERT,
            ),
        )
        for i in range(3)
    ]

    assert len(rank_mentors(mentee, mentee_prof, candidates, limit=2)) == 2
    assert len(rank_mentors(mentee, mentee_prof, candidates, limit=MAX_SUGGESTIONS + 1000)) <= len(
        candidates
    )


def test_rank_mentors_clamps_a_large_matching_pool_to_max_suggestions():
    mentee = _profile("11111111-1111-4111-8111-111111111111")
    mentee_prof = _proficiency(mentee, stack="react", level=ProficiencyLevel.BEGINNER)
    candidates = [
        (
            _profile(f"{i:08d}-0000-4000-8000-000000000000"),
            _proficiency(
                _profile(f"{i:08d}-0000-4000-8000-000000000000"),
                stack="react",
                level=ProficiencyLevel.EXPERT,
            ),
        )
        for i in range(MAX_SUGGESTIONS + 1)
    ]
    ranked = rank_mentors(mentee, mentee_prof, candidates, limit=MAX_SUGGESTIONS + 1000)
    assert len(ranked) == MAX_SUGGESTIONS


def test_rank_mentors_rejects_oversized_candidate_pool():
    mentee = _profile("11111111-1111-4111-8111-111111111111")
    mentee_prof = _proficiency(mentee, stack="react", level=ProficiencyLevel.BEGINNER)
    huge_candidate = _profile("22222222-2222-4222-8222-222222222222")
    huge_prof = _proficiency(huge_candidate, stack="react", level=ProficiencyLevel.EXPERT)
    candidates = [(huge_candidate, huge_prof)] * 501

    with pytest.raises(ValueError, match="candidates"):
        rank_mentors(mentee, mentee_prof, candidates)


def test_rank_mentors_includes_cross_tenant_candidates():
    mentee = _profile("11111111-1111-4111-8111-111111111111", tenant_id=_TENANT)
    mentee_prof = _proficiency(mentee, stack="react", level=ProficiencyLevel.BEGINNER)
    other_tenant_mentor = _profile("22222222-2222-4222-8222-222222222222", tenant_id=_OTHER_TENANT)
    candidates = [
        (
            other_tenant_mentor,
            _proficiency(other_tenant_mentor, stack="react", level=ProficiencyLevel.EXPERT),
        )
    ]

    ranked = rank_mentors(mentee, mentee_prof, candidates)
    assert len(ranked) == 1
    assert ranked[0].mentor_tenant_id == _OTHER_TENANT
