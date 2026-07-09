"""R-016: the complementary-intent matching seam (intent.py)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from rendly.enums import OrgRole
from rendly.intent import (
    MAX_SUGGESTIONS,
    MAX_TAGS,
    IntentProfile,
    bind_intent_profile,
    rank_matches,
    suggest_match,
)
from rendly.profile import Profile

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_OTHER_TENANT = "99999999-9999-4999-8999-999999999999"


def _profile(user_id: str, tenant_id: str = _TENANT) -> Profile:
    return Profile(user_id=user_id, tenant_id=tenant_id, org_role=OrgRole.MEMBER)


def _intent(
    profile: Profile, *, seeking: tuple[str, ...] = (), offering: tuple[str, ...] = ()
) -> IntentProfile:
    return bind_intent_profile(profile, seeking=seeking, offering=offering, opted_in_at=_NOW)


# --- IntentProfile construction -----------------------------------------------------


def test_bind_intent_profile_derives_ids_from_profile():
    p = _profile("11111111-1111-4111-8111-111111111111")
    intent = _intent(p, seeking=("mentor",), offering=("python",))
    assert intent.user_id == p.user_id
    assert intent.tenant_id == p.tenant_id
    assert intent.seeking == ("mentor",)
    assert intent.offering == ("python",)


def test_intent_profile_is_frozen():
    p = _profile("11111111-1111-4111-8111-111111111111")
    intent = _intent(p, seeking=("mentor",))
    with pytest.raises(ValidationError):
        intent.seeking = ("cofounder",)  # type: ignore[misc]


def test_intent_profile_rejects_naive_datetime():
    p = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        IntentProfile(
            user_id=p.user_id,
            tenant_id=p.tenant_id,
            seeking=("mentor",),
            offering=(),
            opted_in_at=datetime(2026, 7, 9, 12, 0, 0),  # naive
        )


@pytest.mark.parametrize("field", ["seeking", "offering"])
def test_intent_profile_rejects_too_many_tags(field):
    p = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        _intent(p, **{field: tuple(f"tag{i}" for i in range(MAX_TAGS + 1))})


@pytest.mark.parametrize("field", ["seeking", "offering"])
def test_intent_profile_rejects_duplicate_tags(field):
    p = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        _intent(p, **{field: ("mentor", "mentor")})


def test_intent_profile_rejects_extra_key():
    p = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        IntentProfile(
            user_id=p.user_id,
            tenant_id=p.tenant_id,
            seeking=("mentor",),
            offering=(),
            opted_in_at=_NOW,
            embedding=[0.1, 0.2],
        )


def test_intent_profile_allows_same_tag_on_both_sides():
    # A tag may legally appear in both `seeking` and `offering` -- this module does
    # not second-guess a user who is both seeking and offering "mentorship".
    p = _profile("11111111-1111-4111-8111-111111111111")
    intent = _intent(p, seeking=("mentorship",), offering=("mentorship",))
    assert intent.seeking == intent.offering == ("mentorship",)


# --- suggest_match ---------------------------------------------------------------


def test_suggest_match_scores_complementary_seeking_and_offering():
    # subject seeks "mentor"; candidate offers "mentor" -- a complementary match
    # even though the literal tag never appears on the SAME field for both.
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    match = suggest_match(
        subject,
        _intent(subject, seeking=("mentor", "cofounder"), offering=("python",)),
        candidate,
        _intent(candidate, seeking=(), offering=("mentor",)),
    )
    assert match is not None
    assert match.matched_as_seeker == ("mentor",)
    assert match.matched_as_offerer == ()
    assert match.score == 1
    assert match.subject_user_id == subject.user_id
    assert match.candidate_user_id == candidate.user_id
    assert match.subject_tenant_id == subject.tenant_id
    assert match.candidate_tenant_id == candidate.tenant_id


def test_suggest_match_scores_both_directions_together():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    match = suggest_match(
        subject,
        _intent(subject, seeking=("mentor",), offering=("python",)),
        candidate,
        _intent(candidate, seeking=("python",), offering=("mentor",)),
    )
    assert match is not None
    assert match.matched_as_seeker == ("mentor",)
    assert match.matched_as_offerer == ("python",)
    assert match.score == 2


def test_suggest_match_none_when_both_want_the_same_thing():
    # The false-positive a symmetric (culture.py-style) scorer would produce: both
    # subject and candidate SEEK "mentor" -- not a complementary match.
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    match = suggest_match(
        subject,
        _intent(subject, seeking=("mentor",), offering=()),
        candidate,
        _intent(candidate, seeking=("mentor",), offering=()),
    )
    assert match is None


def test_suggest_match_none_without_any_overlap():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    match = suggest_match(
        subject,
        _intent(subject, seeking=("mentor",), offering=("python",)),
        candidate,
        _intent(candidate, seeking=("rust",), offering=("cofounder",)),
    )
    assert match is None


def test_suggest_match_none_for_self():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_intent = _intent(subject, seeking=("mentor",), offering=("mentor",))
    match = suggest_match(subject, subject_intent, subject, subject_intent)
    assert match is None


def test_suggest_match_allows_cross_tenant_pair():
    # Deliberate divergence from culture.suggest_connection (R-012), which REFUSES
    # cross-tenant pairs: B2C professional-networking matching is definitionally
    # cross-company, so this seam does not gate on tenant at all.
    subject = _profile("11111111-1111-4111-8111-111111111111", tenant_id=_TENANT)
    candidate = _profile("22222222-2222-4222-8222-222222222222", tenant_id=_OTHER_TENANT)
    match = suggest_match(
        subject,
        _intent(subject, seeking=("mentor",), offering=()),
        candidate,
        _intent(candidate, seeking=(), offering=("mentor",)),
    )
    assert match is not None
    assert match.subject_tenant_id == _TENANT
    assert match.candidate_tenant_id == _OTHER_TENANT


def test_suggest_match_rejects_mismatched_profile_intent_pair():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    other = _profile("22222222-2222-4222-8222-222222222222")
    candidate = _profile("33333333-3333-4333-8333-333333333333")
    with pytest.raises(ValueError, match="subject"):
        suggest_match(
            subject,
            _intent(other, seeking=("mentor",)),  # intent belongs to a DIFFERENT profile
            candidate,
            _intent(candidate, offering=("mentor",)),
        )


def test_suggest_match_rejects_mismatched_candidate_pair():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    other = _profile("33333333-3333-4333-8333-333333333333")
    with pytest.raises(ValueError, match="candidate"):
        suggest_match(
            subject,
            _intent(subject, seeking=("mentor",)),
            candidate,
            _intent(other, offering=("mentor",)),  # intent belongs to a DIFFERENT profile
        )


# --- rank_matches ------------------------------------------------------------------


def test_rank_matches_orders_by_score_desc_then_user_id_asc():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_intent = _intent(subject, seeking=("mentor", "cofounder"), offering=("python", "rust"))

    # high_a/high_b both score=2 (one seeker-match + one offerer-match); low scores=1.
    high_a = _profile("bbbbbbbb-2222-4222-8222-222222222222")
    high_b = _profile("aaaaaaaa-3333-4333-8333-333333333333")
    low = _profile("44444444-4444-4444-8444-444444444444")

    candidates = [
        (high_a, _intent(high_a, seeking=("python",), offering=("mentor",))),
        (high_b, _intent(high_b, seeking=("rust",), offering=("mentor",))),
        (low, _intent(low, seeking=(), offering=("mentor",))),
    ]

    ranked = rank_matches(subject, subject_intent, candidates)
    assert [m.candidate_user_id for m in ranked] == [
        high_b.user_id,
        high_a.user_id,
        low.user_id,
    ]
    assert [m.score for m in ranked] == [2, 2, 1]


def test_rank_matches_filters_out_none_results():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_intent = _intent(subject, seeking=("mentor",), offering=())

    same_seeker = _profile("22222222-2222-4222-8222-222222222222")
    no_overlap = _profile("33333333-3333-4333-8333-333333333333")
    itself = subject

    candidates = [
        (same_seeker, _intent(same_seeker, seeking=("mentor",), offering=())),
        (no_overlap, _intent(no_overlap, seeking=("cofounder",), offering=("rust",))),
        (itself, subject_intent),
    ]

    assert rank_matches(subject, subject_intent, candidates) == []


def test_rank_matches_respects_limit_and_clamps_to_max():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_intent = _intent(subject, seeking=("mentor",), offering=())
    candidates = [
        (
            _profile(f"{i:08d}-0000-4000-8000-000000000000"),
            _intent(
                _profile(f"{i:08d}-0000-4000-8000-000000000000"),
                seeking=(),
                offering=("mentor",),
            ),
        )
        for i in range(3)
    ]

    assert len(rank_matches(subject, subject_intent, candidates, limit=2)) == 2
    # A limit far above MAX_SUGGESTIONS is clamped, not honored -- a caller cannot
    # widen the DoS bound just by passing a large number.
    assert len(
        rank_matches(subject, subject_intent, candidates, limit=MAX_SUGGESTIONS + 1000)
    ) <= len(candidates)


def test_rank_matches_rejects_oversized_candidate_pool():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_intent = _intent(subject, seeking=("mentor",), offering=())
    huge_candidate = _profile("22222222-2222-4222-8222-222222222222")
    huge_intent = _intent(huge_candidate, seeking=(), offering=("mentor",))
    candidates = [(huge_candidate, huge_intent)] * 501

    with pytest.raises(ValueError, match="candidates"):
        rank_matches(subject, subject_intent, candidates)


def test_rank_matches_includes_cross_tenant_candidates():
    # Mirrors suggest_match's own cross-tenant-allowed behavior at the ranking layer:
    # a cross-tenant candidate is not silently dropped from a ranked pool.
    subject = _profile("11111111-1111-4111-8111-111111111111", tenant_id=_TENANT)
    subject_intent = _intent(subject, seeking=("mentor",), offering=())
    other_tenant_candidate = _profile(
        "22222222-2222-4222-8222-222222222222", tenant_id=_OTHER_TENANT
    )
    candidates = [
        (
            other_tenant_candidate,
            _intent(other_tenant_candidate, seeking=(), offering=("mentor",)),
        )
    ]

    ranked = rank_matches(subject, subject_intent, candidates)
    assert len(ranked) == 1
    assert ranked[0].candidate_tenant_id == _OTHER_TENANT
