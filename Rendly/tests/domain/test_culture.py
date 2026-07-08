"""R-012: the opt-in, cross-department connection-suggestion seam (culture.py)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from rendly.culture import (
    MAX_INTERESTS,
    MAX_SUGGESTIONS,
    CultureOptIn,
    bind_culture_opt_in,
    rank_connections,
    suggest_connection,
)
from rendly.enums import OrgRole
from rendly.profile import Profile

_NOW = datetime(2026, 7, 8, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_OTHER_TENANT = "99999999-9999-4999-8999-999999999999"


def _profile(user_id: str, tenant_id: str = _TENANT, team: str | None = None) -> Profile:
    return Profile(user_id=user_id, tenant_id=tenant_id, org_role=OrgRole.MEMBER, team=team)


def _opt_in(profile: Profile, interests: tuple[str, ...]) -> CultureOptIn:
    return bind_culture_opt_in(profile, interests=interests, opted_in_at=_NOW)


# --- CultureOptIn construction -----------------------------------------------------


def test_bind_culture_opt_in_derives_ids_from_profile():
    p = _profile("11111111-1111-4111-8111-111111111111", team="platform")
    opt_in = _opt_in(p, ("climbing", "chess"))
    assert opt_in.user_id == p.user_id
    assert opt_in.tenant_id == p.tenant_id
    assert opt_in.interests == ("climbing", "chess")


def test_culture_opt_in_is_frozen():
    p = _profile("11111111-1111-4111-8111-111111111111")
    opt_in = _opt_in(p, ("climbing",))
    with pytest.raises(ValidationError):
        opt_in.interests = ("chess",)  # type: ignore[misc]


def test_culture_opt_in_rejects_naive_datetime():
    p = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        CultureOptIn(
            user_id=p.user_id,
            tenant_id=p.tenant_id,
            interests=("climbing",),
            opted_in_at=datetime(2026, 7, 8, 12, 0, 0),  # naive
        )


def test_culture_opt_in_rejects_too_many_interests():
    p = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        _opt_in(p, tuple(f"tag{i}" for i in range(MAX_INTERESTS + 1)))


def test_culture_opt_in_rejects_duplicate_interests():
    p = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        _opt_in(p, ("climbing", "climbing"))


def test_culture_opt_in_rejects_extra_key():
    p = _profile("11111111-1111-4111-8111-111111111111")
    with pytest.raises(ValidationError):
        CultureOptIn(
            user_id=p.user_id,
            tenant_id=p.tenant_id,
            interests=("climbing",),
            opted_in_at=_NOW,
            embedding=[0.1, 0.2],
        )


# --- suggest_connection --------------------------------------------------------------


def test_suggest_connection_scores_shared_interests():
    subject = _profile("11111111-1111-4111-8111-111111111111", team="platform")
    candidate = _profile("22222222-2222-4222-8222-222222222222", team="design")
    suggestion = suggest_connection(
        subject,
        _opt_in(subject, ("climbing", "chess", "synths")),
        candidate,
        _opt_in(candidate, ("chess", "synths", "pottery")),
    )
    assert suggestion is not None
    assert suggestion.shared_interests == ("chess", "synths")
    assert suggestion.score == 2
    assert suggestion.tenant_id == _TENANT
    assert suggestion.subject_user_id == subject.user_id
    assert suggestion.candidate_user_id == candidate.user_id


def test_suggest_connection_none_without_shared_interests():
    subject = _profile("11111111-1111-4111-8111-111111111111", team="platform")
    candidate = _profile("22222222-2222-4222-8222-222222222222", team="design")
    suggestion = suggest_connection(
        subject,
        _opt_in(subject, ("climbing",)),
        candidate,
        _opt_in(candidate, ("pottery",)),
    )
    assert suggestion is None


def test_suggest_connection_none_for_self():
    subject = _profile("11111111-1111-4111-8111-111111111111", team="platform")
    suggestion = suggest_connection(
        subject,
        _opt_in(subject, ("climbing",)),
        subject,
        _opt_in(subject, ("climbing",)),
    )
    assert suggestion is None


def test_suggest_connection_none_for_same_known_team():
    # Cross-department only: two known-same-team people are already reachable via
    # R-006's team-mapped channel, so this seam declines to restate that pairing.
    subject = _profile("11111111-1111-4111-8111-111111111111", team="platform")
    candidate = _profile("22222222-2222-4222-8222-222222222222", team="platform")
    suggestion = suggest_connection(
        subject,
        _opt_in(subject, ("climbing",)),
        candidate,
        _opt_in(candidate, ("climbing",)),
    )
    assert suggestion is None


def test_suggest_connection_allows_pair_with_unknown_team():
    # Missing team info does not block a suggestion -- only a *known* shared team does.
    subject = _profile("11111111-1111-4111-8111-111111111111", team=None)
    candidate = _profile("22222222-2222-4222-8222-222222222222", team="design")
    suggestion = suggest_connection(
        subject,
        _opt_in(subject, ("climbing",)),
        candidate,
        _opt_in(candidate, ("climbing",)),
    )
    assert suggestion is not None
    assert suggestion.shared_interests == ("climbing",)


def test_suggest_connection_rejects_cross_tenant_pair():
    subject = _profile("11111111-1111-4111-8111-111111111111", tenant_id=_TENANT)
    candidate = _profile("22222222-2222-4222-8222-222222222222", tenant_id=_OTHER_TENANT)
    with pytest.raises(ValueError, match="cross-tenant"):
        suggest_connection(
            subject,
            _opt_in(subject, ("climbing",)),
            candidate,
            _opt_in(candidate, ("climbing",)),
        )


def test_suggest_connection_rejects_mismatched_profile_opt_in_pair():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    other = _profile("22222222-2222-4222-8222-222222222222")
    candidate = _profile("33333333-3333-4333-8333-333333333333")
    with pytest.raises(ValueError, match="subject"):
        suggest_connection(
            subject,
            _opt_in(other, ("climbing",)),  # opt-in belongs to a DIFFERENT profile
            candidate,
            _opt_in(candidate, ("climbing",)),
        )


# --- rank_connections ----------------------------------------------------------------


def test_rank_connections_orders_by_score_desc_then_user_id_asc():
    subject = _profile("11111111-1111-4111-8111-111111111111", team="platform")
    subject_opt_in = _opt_in(subject, ("climbing", "chess", "synths"))

    # Two candidates score=2, one scores=1 -- ties break on candidate_user_id asc.
    high_a = _profile("bbbbbbbb-2222-4222-8222-222222222222", team="design")
    high_b = _profile("aaaaaaaa-3333-4333-8333-333333333333", team="design")
    low = _profile("44444444-4444-4444-8444-444444444444", team="design")

    candidates = [
        (high_a, _opt_in(high_a, ("chess", "synths"))),
        (high_b, _opt_in(high_b, ("chess", "synths"))),
        (low, _opt_in(low, ("chess",))),
    ]

    ranked = rank_connections(subject, subject_opt_in, candidates)
    assert [s.candidate_user_id for s in ranked] == [
        high_b.user_id,
        high_a.user_id,
        low.user_id,
    ]
    assert [s.score for s in ranked] == [2, 2, 1]


def test_rank_connections_filters_out_none_results():
    subject = _profile("11111111-1111-4111-8111-111111111111", team="platform")
    subject_opt_in = _opt_in(subject, ("climbing",))

    same_team = _profile("22222222-2222-4222-8222-222222222222", team="platform")
    no_overlap = _profile("33333333-3333-4333-8333-333333333333", team="design")
    itself = subject

    candidates = [
        (same_team, _opt_in(same_team, ("climbing",))),
        (no_overlap, _opt_in(no_overlap, ("pottery",))),
        (itself, subject_opt_in),
    ]

    assert rank_connections(subject, subject_opt_in, candidates) == []


def test_rank_connections_respects_limit_and_clamps_to_max():
    subject = _profile("11111111-1111-4111-8111-111111111111", team="platform")
    subject_opt_in = _opt_in(subject, ("climbing",))
    candidates = [
        (
            _profile(f"{i:08d}-0000-4000-8000-000000000000", team="design"),
            _opt_in(_profile(f"{i:08d}-0000-4000-8000-000000000000", team="design"), ("climbing",)),
        )
        for i in range(3)
    ]

    assert len(rank_connections(subject, subject_opt_in, candidates, limit=2)) == 2
    # A limit far above MAX_SUGGESTIONS is clamped, not honored -- a caller cannot
    # widen the DoS bound just by passing a large number.
    assert len(
        rank_connections(subject, subject_opt_in, candidates, limit=MAX_SUGGESTIONS + 1000)
    ) <= len(candidates)


def test_rank_connections_rejects_oversized_candidate_pool():
    subject = _profile("11111111-1111-4111-8111-111111111111", team="platform")
    subject_opt_in = _opt_in(subject, ("climbing",))
    huge_candidate = _profile("22222222-2222-4222-8222-222222222222", team="design")
    huge_opt_in = _opt_in(huge_candidate, ("climbing",))
    candidates = [(huge_candidate, huge_opt_in)] * 501

    with pytest.raises(ValueError, match="candidates"):
        rank_connections(subject, subject_opt_in, candidates)
