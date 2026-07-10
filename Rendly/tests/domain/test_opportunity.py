"""R-021: the skill-based opportunity matching seam (opportunity.py)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from rendly.enums import OrgRole
from rendly.intent import IntentProfile
from rendly.opportunity import (
    MAX_SKILLS,
    MAX_SUGGESTIONS,
    EmploymentType,
    Opportunity,
    bind_opportunity,
    rank_opportunities,
    suggest_opportunity_match,
)
from rendly.profile import Profile

_NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_OTHER_TENANT = "99999999-9999-4999-8999-999999999999"


def _profile(user_id: str, tenant_id: str = _TENANT) -> Profile:
    return Profile(user_id=user_id, tenant_id=tenant_id, org_role=OrgRole.MEMBER)


def _intent(profile: Profile, *, offering: tuple[str, ...] = ()) -> IntentProfile:
    return IntentProfile(
        user_id=profile.user_id,
        tenant_id=profile.tenant_id,
        seeking=(),
        offering=offering,
        opted_in_at=_NOW,
    )


def _opportunity(
    poster: Profile,
    *,
    opportunity_id: str = "aaaaaaaa-0000-4000-8000-000000000000",
    employment_type: EmploymentType = EmploymentType.FREELANCE,
    required_skills: tuple[str, ...] = (),
) -> Opportunity:
    return bind_opportunity(
        poster,
        opportunity_id=opportunity_id,
        employment_type=employment_type,
        required_skills=required_skills,
        posted_at=_NOW,
    )


# --- Opportunity construction --------------------------------------------------------


def test_bind_opportunity_derives_ids_from_poster_profile():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    opportunity = _opportunity(poster, required_skills=("python",))
    assert opportunity.posted_by_user_id == poster.user_id
    assert opportunity.tenant_id == poster.tenant_id
    assert opportunity.required_skills == ("python",)


def test_opportunity_is_frozen():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    opportunity = _opportunity(poster, required_skills=("python",))
    with pytest.raises(ValidationError):
        opportunity.required_skills = ("rust",)  # type: ignore[misc]


def test_opportunity_rejects_naive_datetime():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        Opportunity(
            opportunity_id="aaaaaaaa-0000-4000-8000-000000000000",
            tenant_id=poster.tenant_id,
            posted_by_user_id=poster.user_id,
            employment_type=EmploymentType.FULL_TIME,
            required_skills=("python",),
            posted_at=datetime(2026, 7, 10, 12, 0, 0),  # naive
        )


def test_opportunity_rejects_too_many_skills():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        _opportunity(poster, required_skills=tuple(f"skill{i}" for i in range(MAX_SKILLS + 1)))


def test_opportunity_rejects_duplicate_skills():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        _opportunity(poster, required_skills=("python", "python"))


def test_opportunity_rejects_extra_key():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        Opportunity(
            opportunity_id="aaaaaaaa-0000-4000-8000-000000000000",
            tenant_id=poster.tenant_id,
            posted_by_user_id=poster.user_id,
            employment_type=EmploymentType.FREELANCE,
            required_skills=("python",),
            posted_at=_NOW,
            salary=100_000,
        )


# --- suggest_opportunity_match --------------------------------------------------------


def test_suggest_opportunity_match_scores_skill_overlap():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    subject = _profile("22222222-2222-4222-8222-222222222222")
    opportunity = _opportunity(poster, required_skills=("python", "rust", "sql"))

    match = suggest_opportunity_match(
        subject, _intent(subject, offering=("python", "rust", "go")), opportunity
    )

    assert match is not None
    assert match.matched_skills == ("python", "rust")
    assert match.score == 2
    assert match.subject_user_id == subject.user_id
    assert match.opportunity_id == opportunity.opportunity_id
    assert match.employment_type == EmploymentType.FREELANCE


def test_suggest_opportunity_match_none_without_any_overlap():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    subject = _profile("22222222-2222-4222-8222-222222222222")
    opportunity = _opportunity(poster, required_skills=("python",))

    match = suggest_opportunity_match(subject, _intent(subject, offering=("rust",)), opportunity)

    assert match is None


def test_suggest_opportunity_match_none_for_self_posted_opportunity():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    opportunity = _opportunity(poster, required_skills=("python",))

    match = suggest_opportunity_match(poster, _intent(poster, offering=("python",)), opportunity)

    assert match is None


def test_suggest_opportunity_match_allows_cross_tenant_pair():
    poster = _profile("11111111-1111-4111-8111-111111111111", tenant_id=_TENANT)
    subject = _profile("22222222-2222-4222-8222-222222222222", tenant_id=_OTHER_TENANT)
    opportunity = _opportunity(poster, required_skills=("python",))

    match = suggest_opportunity_match(subject, _intent(subject, offering=("python",)), opportunity)

    assert match is not None
    assert match.subject_tenant_id == _OTHER_TENANT
    assert match.opportunity_tenant_id == _TENANT


def test_suggest_opportunity_match_rejects_mismatched_profile_intent_pair():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    other = _profile("22222222-2222-4222-8222-222222222222")
    poster = _profile("33333333-3333-4333-8333-333333333333")
    opportunity = _opportunity(poster, required_skills=("python",))

    with pytest.raises(ValueError, match="subject"):
        suggest_opportunity_match(subject, _intent(other, offering=("python",)), opportunity)


# --- rank_opportunities -----------------------------------------------------------------


def test_rank_opportunities_orders_by_score_desc_then_opportunity_id_asc():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    subject = _profile("22222222-2222-4222-8222-222222222222")
    subject_intent = _intent(subject, offering=("python", "rust", "sql"))

    high_a = _opportunity(
        poster,
        opportunity_id="bbbbbbbb-0000-4000-8000-000000000000",
        required_skills=("python", "rust"),
    )
    high_b = _opportunity(
        poster,
        opportunity_id="aaaaaaaa-0000-4000-8000-000000000000",
        required_skills=("python", "sql"),
    )
    low = _opportunity(
        poster,
        opportunity_id="cccccccc-0000-4000-8000-000000000000",
        required_skills=("python",),
    )

    ranked = rank_opportunities(subject, subject_intent, [high_a, high_b, low])

    assert [m.opportunity_id for m in ranked] == [
        high_b.opportunity_id,
        high_a.opportunity_id,
        low.opportunity_id,
    ]
    assert [m.score for m in ranked] == [2, 2, 1]


def test_rank_opportunities_filters_out_none_results():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    subject = _profile("22222222-2222-4222-8222-222222222222")
    subject_intent = _intent(subject, offering=("python",))

    no_overlap = _opportunity(poster, required_skills=("cobol",))
    self_posted = _opportunity(subject, required_skills=("python",))

    assert rank_opportunities(subject, subject_intent, [no_overlap, self_posted]) == []


def test_rank_opportunities_filters_by_employment_type():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    subject = _profile("22222222-2222-4222-8222-222222222222")
    subject_intent = _intent(subject, offering=("python",))

    freelance = _opportunity(
        poster,
        opportunity_id="aaaaaaaa-0000-4000-8000-000000000000",
        employment_type=EmploymentType.FREELANCE,
        required_skills=("python",),
    )
    full_time = _opportunity(
        poster,
        opportunity_id="bbbbbbbb-0000-4000-8000-000000000000",
        employment_type=EmploymentType.FULL_TIME,
        required_skills=("python",),
    )

    ranked = rank_opportunities(
        subject,
        subject_intent,
        [freelance, full_time],
        employment_types=[EmploymentType.FULL_TIME],
    )

    assert [m.opportunity_id for m in ranked] == [full_time.opportunity_id]


def test_rank_opportunities_respects_limit_and_clamps_to_max():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    subject = _profile("22222222-2222-4222-8222-222222222222")
    subject_intent = _intent(subject, offering=("python",))
    candidates = [
        _opportunity(
            poster,
            opportunity_id=f"{i:08d}-0000-4000-8000-000000000000",
            required_skills=("python",),
        )
        for i in range(3)
    ]

    assert len(rank_opportunities(subject, subject_intent, candidates, limit=2)) == 2
    assert len(
        rank_opportunities(subject, subject_intent, candidates, limit=MAX_SUGGESTIONS + 1000)
    ) <= len(candidates)


def test_rank_opportunities_rejects_oversized_candidate_pool():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    subject = _profile("22222222-2222-4222-8222-222222222222")
    subject_intent = _intent(subject, offering=("python",))
    opportunity = _opportunity(poster, required_skills=("python",))

    with pytest.raises(ValueError, match="candidates"):
        rank_opportunities(subject, subject_intent, [opportunity] * 501)


def test_rank_opportunities_includes_cross_tenant_candidates():
    poster = _profile("11111111-1111-4111-8111-111111111111", tenant_id=_TENANT)
    subject = _profile("22222222-2222-4222-8222-222222222222", tenant_id=_OTHER_TENANT)
    subject_intent = _intent(subject, offering=("python",))
    opportunity = _opportunity(poster, required_skills=("python",))

    ranked = rank_opportunities(subject, subject_intent, [opportunity])

    assert len(ranked) == 1
    assert ranked[0].opportunity_tenant_id == _TENANT
