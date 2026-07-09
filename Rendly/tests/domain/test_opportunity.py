"""R-021: the skill-based opportunity-matching seam (opportunity.py)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from rendly.enums import OrgRole
from rendly.intent import bind_intent_profile
from rendly.opportunity import (
    MAX_MATCHES,
    MAX_OPPORTUNITIES,
    MAX_REQUIRED_SKILLS,
    Opportunity,
    OpportunityKind,
    bind_opportunity,
    rank_opportunities,
    suggest_opportunity_match,
)
from rendly.profile import Profile

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_OTHER_TENANT = "99999999-9999-4999-8999-999999999999"


def _profile(user_id: str, tenant_id: str = _TENANT) -> Profile:
    return Profile(user_id=user_id, tenant_id=tenant_id, org_role=OrgRole.MEMBER)


def _intent(profile: Profile, *, offering: tuple[str, ...] = ()):
    return bind_intent_profile(profile, seeking=(), offering=offering, opted_in_at=_NOW)


def _opportunity(
    poster: Profile,
    *,
    kind: OpportunityKind = OpportunityKind.FREELANCE,
    required_skills: tuple[str, ...] = (),
) -> Opportunity:
    return bind_opportunity(
        poster, title="Backend gig", kind=kind, required_skills=required_skills, posted_at=_NOW
    )


# --- Opportunity construction ----------------------------------------------------------


def test_bind_opportunity_derives_ids_from_poster():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    opp = _opportunity(poster, required_skills=("python",))
    assert opp.posted_by == poster.user_id
    assert opp.tenant_id == poster.tenant_id
    assert opp.required_skills == ("python",)


def test_opportunity_is_frozen():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    opp = _opportunity(poster)
    with pytest.raises(ValidationError):
        opp.title = "changed"  # type: ignore[misc]


def test_opportunity_rejects_naive_datetime():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        Opportunity(
            opportunity_id="11111111-1111-4111-8111-111111111111",
            tenant_id=poster.tenant_id,
            posted_by=poster.user_id,
            title="Gig",
            kind=OpportunityKind.FREELANCE,
            required_skills=(),
            posted_at=datetime(2026, 7, 9, 12, 0, 0),  # naive
        )


def test_opportunity_rejects_too_many_required_skills():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        _opportunity(poster, required_skills=tuple(f"s{i}" for i in range(MAX_REQUIRED_SKILLS + 1)))


def test_opportunity_rejects_duplicate_required_skills():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        _opportunity(poster, required_skills=("python", "python"))


def test_opportunity_kind_is_informational_only():
    # Same skills, different kind -- kind does not change match behavior (see
    # module HONESTY BOUNDARY).
    poster = _profile("11111111-1111-4111-8111-111111111111")
    subject = _profile("22222222-2222-4222-8222-222222222222")
    subject_intent = _intent(subject, offering=("python",))

    freelance = _opportunity(poster, kind=OpportunityKind.FREELANCE, required_skills=("python",))
    full_time = _opportunity(poster, kind=OpportunityKind.FULL_TIME, required_skills=("python",))

    m1 = suggest_opportunity_match(subject, subject_intent, freelance)
    m2 = suggest_opportunity_match(subject, subject_intent, full_time)
    assert m1 is not None and m2 is not None
    assert m1.score == m2.score == 1


# --- suggest_opportunity_match -----------------------------------------------------------


def test_suggest_opportunity_match_scores_skill_overlap():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    subject = _profile("22222222-2222-4222-8222-222222222222")
    subject_intent = _intent(subject, offering=("python", "django", "postgres"))
    opp = _opportunity(poster, required_skills=("python", "postgres", "aws"))

    match = suggest_opportunity_match(subject, subject_intent, opp)
    assert match is not None
    assert match.matched_skills == ("postgres", "python")
    assert match.score == 2
    assert match.subject_user_id == subject.user_id
    assert match.opportunity_id == opp.opportunity_id
    assert match.opportunity_tenant_id == opp.tenant_id


def test_suggest_opportunity_match_none_without_overlap():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    subject = _profile("22222222-2222-4222-8222-222222222222")
    subject_intent = _intent(subject, offering=("rust",))
    opp = _opportunity(poster, required_skills=("python",))

    assert suggest_opportunity_match(subject, subject_intent, opp) is None


def test_suggest_opportunity_match_none_when_subject_offers_nothing():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    subject = _profile("22222222-2222-4222-8222-222222222222")
    subject_intent = _intent(subject, offering=())
    opp = _opportunity(poster, required_skills=("python",))

    assert suggest_opportunity_match(subject, subject_intent, opp) is None


def test_suggest_opportunity_match_allows_cross_tenant_pair():
    poster = _profile("11111111-1111-4111-8111-111111111111", tenant_id=_TENANT)
    subject = _profile("22222222-2222-4222-8222-222222222222", tenant_id=_OTHER_TENANT)
    subject_intent = _intent(subject, offering=("python",))
    opp = _opportunity(poster, required_skills=("python",))

    match = suggest_opportunity_match(subject, subject_intent, opp)
    assert match is not None
    assert match.subject_tenant_id == _OTHER_TENANT
    assert match.opportunity_tenant_id == _TENANT


def test_suggest_opportunity_match_rejects_mismatched_subject_intent_pair():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    subject = _profile("22222222-2222-4222-8222-222222222222")
    other = _profile("33333333-3333-4333-8333-333333333333")
    other_intent = _intent(other, offering=("python",))
    opp = _opportunity(poster, required_skills=("python",))

    with pytest.raises(ValueError, match="subject"):
        suggest_opportunity_match(subject, other_intent, opp)


# --- rank_opportunities -------------------------------------------------------------------


def test_rank_opportunities_orders_by_score_desc_then_opportunity_id_asc():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    subject = _profile("22222222-2222-4222-8222-222222222222")
    subject_intent = _intent(subject, offering=("python", "django", "aws"))

    high = _opportunity(poster, required_skills=("python", "django"))
    low = _opportunity(poster, required_skills=("python",))

    ranked = rank_opportunities(subject, subject_intent, [low, high])
    assert [r.opportunity_id for r in ranked] == [high.opportunity_id, low.opportunity_id]
    assert ranked[0].score == 2
    assert ranked[1].score == 1


def test_rank_opportunities_filters_out_none_results():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    subject = _profile("22222222-2222-4222-8222-222222222222")
    subject_intent = _intent(subject, offering=("python",))

    no_overlap = _opportunity(poster, required_skills=("rust",))
    assert rank_opportunities(subject, subject_intent, [no_overlap]) == []


def test_rank_opportunities_respects_limit_and_clamps_to_max():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    subject = _profile("22222222-2222-4222-8222-222222222222")
    subject_intent = _intent(subject, offering=("python",))
    opportunities = [_opportunity(poster, required_skills=("python",)) for _ in range(3)]

    assert len(rank_opportunities(subject, subject_intent, opportunities, limit=2)) == 2
    assert len(
        rank_opportunities(subject, subject_intent, opportunities, limit=MAX_MATCHES + 1000)
    ) <= len(opportunities)


def test_rank_opportunities_rejects_oversized_pool():
    poster = _profile("11111111-1111-4111-8111-111111111111")
    subject = _profile("22222222-2222-4222-8222-222222222222")
    subject_intent = _intent(subject, offering=("python",))
    opp = _opportunity(poster, required_skills=("python",))

    with pytest.raises(ValueError, match="opportunities"):
        rank_opportunities(subject, subject_intent, [opp] * (MAX_OPPORTUNITIES + 1))


def test_rank_opportunities_includes_cross_tenant_opportunities():
    poster = _profile("11111111-1111-4111-8111-111111111111", tenant_id=_OTHER_TENANT)
    subject = _profile("22222222-2222-4222-8222-222222222222", tenant_id=_TENANT)
    subject_intent = _intent(subject, offering=("python",))
    opp = _opportunity(poster, required_skills=("python",))

    ranked = rank_opportunities(subject, subject_intent, [opp])
    assert len(ranked) == 1
    assert ranked[0].opportunity_tenant_id == _OTHER_TENANT
