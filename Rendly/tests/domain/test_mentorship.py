"""R-022: the exact-tech-stack-proficiency mentorship-matching seam (mentorship.py)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from rendly.enums import OrgRole
from rendly.mentorship import (
    MAX_CANDIDATES,
    MAX_SUGGESTIONS,
    MAX_TECH_STACKS,
    MentorshipProfile,
    ProficiencyLevel,
    TechStackProficiency,
    bind_mentorship_profile,
    rank_mentorship_matches,
    suggest_mentorship_match,
)
from rendly.profile import Profile

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_OTHER_TENANT = "99999999-9999-4999-8999-999999999999"


def _profile(user_id: str, tenant_id: str = _TENANT) -> Profile:
    return Profile(user_id=user_id, tenant_id=tenant_id, org_role=OrgRole.MEMBER)


def _mentorship(
    profile: Profile, *, proficiencies: dict[str, ProficiencyLevel] | None = None
) -> MentorshipProfile:
    return bind_mentorship_profile(profile, proficiencies=proficiencies or {}, opted_in_at=_NOW)


# --- MentorshipProfile construction -------------------------------------------------


def test_bind_mentorship_profile_derives_ids_from_profile():
    p = _profile("11111111-1111-4111-8111-111111111111")
    m = _mentorship(p, proficiencies={"react": ProficiencyLevel.ADVANCED})
    assert m.user_id == p.user_id
    assert m.tenant_id == p.tenant_id
    assert m.proficiencies == (TechStackProficiency(tag="react", level=ProficiencyLevel.ADVANCED),)


def test_mentorship_profile_is_frozen():
    p = _profile("11111111-1111-4111-8111-111111111111")
    m = _mentorship(p)
    with pytest.raises(ValidationError):
        m.opted_in_at = _NOW  # type: ignore[misc]


def test_mentorship_profile_rejects_naive_datetime():
    p = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        MentorshipProfile(
            user_id=p.user_id,
            tenant_id=p.tenant_id,
            proficiencies=(),
            opted_in_at=datetime(2026, 7, 9, 12, 0, 0),  # naive
        )


def test_mentorship_profile_accepts_exactly_max_tech_stacks():
    p = _profile("11111111-1111-4111-8111-111111111111")
    proficiencies = {f"stack{i}": ProficiencyLevel.BEGINNER for i in range(MAX_TECH_STACKS)}
    m = _mentorship(p, proficiencies=proficiencies)
    assert len(m.proficiencies) == MAX_TECH_STACKS


def test_mentorship_profile_rejects_too_many_tech_stacks():
    p = _profile("11111111-1111-4111-8111-111111111111")
    proficiencies = {f"stack{i}": ProficiencyLevel.BEGINNER for i in range(MAX_TECH_STACKS + 1)}
    with pytest.raises(ValidationError):
        _mentorship(p, proficiencies=proficiencies)


def test_mentorship_profile_rejects_duplicate_tags():
    p = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        MentorshipProfile(
            user_id=p.user_id,
            tenant_id=p.tenant_id,
            proficiencies=(
                TechStackProficiency(tag="react", level=ProficiencyLevel.BEGINNER),
                TechStackProficiency(tag="react", level=ProficiencyLevel.EXPERT),
            ),
            opted_in_at=_NOW,
        )


def test_mentorship_profile_rejects_extra_key():
    p = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        MentorshipProfile(
            user_id=p.user_id,
            tenant_id=p.tenant_id,
            proficiencies=(),
            opted_in_at=_NOW,
            notes="extra",
        )


# --- suggest_mentorship_match --------------------------------------------------------


def test_suggest_mentorship_match_candidate_mentors_subject_on_higher_level_tag():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    subject_m = _mentorship(subject, proficiencies={"react": ProficiencyLevel.BEGINNER})
    candidate_m = _mentorship(candidate, proficiencies={"react": ProficiencyLevel.EXPERT})

    match = suggest_mentorship_match(subject, subject_m, candidate, candidate_m)
    assert match is not None
    assert match.candidate_mentors_on == ("react",)
    assert match.candidate_mentees_on == ()
    assert match.score == 1


def test_suggest_mentorship_match_candidate_is_mentee_on_lower_level_tag():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    subject_m = _mentorship(subject, proficiencies={"react": ProficiencyLevel.EXPERT})
    candidate_m = _mentorship(candidate, proficiencies={"react": ProficiencyLevel.BEGINNER})

    match = suggest_mentorship_match(subject, subject_m, candidate, candidate_m)
    assert match is not None
    assert match.candidate_mentors_on == ()
    assert match.candidate_mentees_on == ("react",)
    assert match.score == 1


def test_suggest_mentorship_match_mutual_across_different_tags():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    subject_m = _mentorship(
        subject,
        proficiencies={"react": ProficiencyLevel.EXPERT, "rust": ProficiencyLevel.BEGINNER},
    )
    candidate_m = _mentorship(
        candidate,
        proficiencies={"react": ProficiencyLevel.BEGINNER, "rust": ProficiencyLevel.EXPERT},
    )

    match = suggest_mentorship_match(subject, subject_m, candidate, candidate_m)
    assert match is not None
    assert match.candidate_mentors_on == ("rust",)
    assert match.candidate_mentees_on == ("react",)
    assert match.score == 2


def test_suggest_mentorship_match_none_on_equal_level_shared_tag():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    subject_m = _mentorship(subject, proficiencies={"react": ProficiencyLevel.ADVANCED})
    candidate_m = _mentorship(candidate, proficiencies={"react": ProficiencyLevel.ADVANCED})

    assert suggest_mentorship_match(subject, subject_m, candidate, candidate_m) is None


def test_suggest_mentorship_match_ignores_non_exact_tags():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    subject_m = _mentorship(subject, proficiencies={"react": ProficiencyLevel.BEGINNER})
    candidate_m = _mentorship(candidate, proficiencies={"vue": ProficiencyLevel.EXPERT})

    assert suggest_mentorship_match(subject, subject_m, candidate, candidate_m) is None


def test_suggest_mentorship_match_none_for_self():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_m = _mentorship(subject, proficiencies={"react": ProficiencyLevel.EXPERT})

    assert suggest_mentorship_match(subject, subject_m, subject, subject_m) is None


def test_suggest_mentorship_match_allows_cross_tenant_pair():
    subject = _profile("11111111-1111-4111-8111-111111111111", tenant_id=_TENANT)
    candidate = _profile("22222222-2222-4222-8222-222222222222", tenant_id=_OTHER_TENANT)
    subject_m = _mentorship(subject, proficiencies={"react": ProficiencyLevel.BEGINNER})
    candidate_m = _mentorship(candidate, proficiencies={"react": ProficiencyLevel.EXPERT})

    match = suggest_mentorship_match(subject, subject_m, candidate, candidate_m)
    assert match is not None
    assert match.subject_tenant_id == _TENANT
    assert match.candidate_tenant_id == _OTHER_TENANT


def test_suggest_mentorship_match_rejects_mismatched_subject_pair():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    other = _profile("33333333-3333-4333-8333-333333333333")
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    other_m = _mentorship(other, proficiencies={"react": ProficiencyLevel.BEGINNER})
    candidate_m = _mentorship(candidate, proficiencies={"react": ProficiencyLevel.EXPERT})

    with pytest.raises(ValueError, match="subject"):
        suggest_mentorship_match(subject, other_m, candidate, candidate_m)


def test_suggest_mentorship_match_rejects_mismatched_candidate_pair():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    other = _profile("33333333-3333-4333-8333-333333333333")
    subject_m = _mentorship(subject, proficiencies={"react": ProficiencyLevel.BEGINNER})
    other_m = _mentorship(other, proficiencies={"react": ProficiencyLevel.EXPERT})

    with pytest.raises(ValueError, match="candidate"):
        suggest_mentorship_match(subject, subject_m, candidate, other_m)


# --- rank_mentorship_matches ----------------------------------------------------------


def test_rank_mentorship_matches_orders_by_score_desc_then_user_id_asc():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_m = _mentorship(
        subject,
        proficiencies={"react": ProficiencyLevel.EXPERT, "rust": ProficiencyLevel.EXPERT},
    )

    low = _profile("22222222-2222-4222-8222-222222222222")
    low_m = _mentorship(low, proficiencies={"react": ProficiencyLevel.BEGINNER})

    high = _profile("33333333-3333-4333-8333-333333333333")
    high_m = _mentorship(
        high,
        proficiencies={"react": ProficiencyLevel.BEGINNER, "rust": ProficiencyLevel.BEGINNER},
    )

    ranked = rank_mentorship_matches(subject, subject_m, [(low, low_m), (high, high_m)])
    assert [r.candidate_user_id for r in ranked] == [high.user_id, low.user_id]
    assert ranked[0].score == 2
    assert ranked[1].score == 1


def test_rank_mentorship_matches_filters_out_none_results():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_m = _mentorship(subject, proficiencies={"react": ProficiencyLevel.EXPERT})

    no_overlap = _profile("22222222-2222-4222-8222-222222222222")
    no_overlap_m = _mentorship(no_overlap, proficiencies={"vue": ProficiencyLevel.EXPERT})

    assert rank_mentorship_matches(subject, subject_m, [(no_overlap, no_overlap_m)]) == []


def test_rank_mentorship_matches_respects_limit_and_clamps_to_max():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_m = _mentorship(subject, proficiencies={"react": ProficiencyLevel.BEGINNER})
    candidates = [
        (
            _profile(f"{i:08d}-0000-4000-8000-000000000000"),
            _mentorship(
                _profile(f"{i:08d}-0000-4000-8000-000000000000"),
                proficiencies={"react": ProficiencyLevel.EXPERT},
            ),
        )
        for i in range(3)
    ]

    assert len(rank_mentorship_matches(subject, subject_m, candidates, limit=2)) == 2
    assert len(
        rank_mentorship_matches(subject, subject_m, candidates, limit=MAX_SUGGESTIONS + 1000)
    ) <= len(candidates)


def test_rank_mentorship_matches_clamps_a_large_matching_pool_to_max_suggestions():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_m = _mentorship(subject, proficiencies={"react": ProficiencyLevel.BEGINNER})
    candidates = [
        (
            _profile(f"{i:08d}-0000-4000-8000-000000000000"),
            _mentorship(
                _profile(f"{i:08d}-0000-4000-8000-000000000000"),
                proficiencies={"react": ProficiencyLevel.EXPERT},
            ),
        )
        for i in range(MAX_SUGGESTIONS + 1)
    ]

    ranked = rank_mentorship_matches(subject, subject_m, candidates, limit=MAX_SUGGESTIONS + 1000)
    assert len(ranked) == MAX_SUGGESTIONS


def test_rank_mentorship_matches_rejects_oversized_pool():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_m = _mentorship(subject, proficiencies={"react": ProficiencyLevel.BEGINNER})
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    candidate_m = _mentorship(candidate, proficiencies={"react": ProficiencyLevel.EXPERT})

    with pytest.raises(ValueError, match="candidates"):
        rank_mentorship_matches(
            subject, subject_m, [(candidate, candidate_m)] * (MAX_CANDIDATES + 1)
        )


def test_rank_mentorship_matches_includes_cross_tenant_candidates():
    subject = _profile("11111111-1111-4111-8111-111111111111", tenant_id=_TENANT)
    subject_m = _mentorship(subject, proficiencies={"react": ProficiencyLevel.BEGINNER})
    candidate = _profile("22222222-2222-4222-8222-222222222222", tenant_id=_OTHER_TENANT)
    candidate_m = _mentorship(candidate, proficiencies={"react": ProficiencyLevel.EXPERT})

    ranked = rank_mentorship_matches(subject, subject_m, [(candidate, candidate_m)])
    assert len(ranked) == 1
    assert ranked[0].candidate_tenant_id == _OTHER_TENANT
