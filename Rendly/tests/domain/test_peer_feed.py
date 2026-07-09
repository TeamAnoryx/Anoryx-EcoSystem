"""R-018: the multi-signal peer-feed assembly seam (peer_feed.py)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from rendly.career import bind_career_goal, suggest_trajectory_match
from rendly.enums import OrgRole
from rendly.intent import bind_intent_profile, suggest_match
from rendly.peer_feed import (
    MAX_FEED_SUGGESTIONS,
    MAX_INPUT_MATCHES,
    build_peer_feed,
)
from rendly.profile import Profile

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_SUBJECT_ID = "11111111-1111-4111-8111-111111111111"


def _profile(user_id: str, tenant_id: str = _TENANT) -> Profile:
    return Profile(user_id=user_id, tenant_id=tenant_id, org_role=OrgRole.MEMBER)


_SUBJECT = _profile(_SUBJECT_ID)


def _intent_match(candidate_id: str, *, seeking=(), offering=()):
    subject_intent = bind_intent_profile(
        _SUBJECT, seeking=seeking, offering=offering, opted_in_at=_NOW
    )
    candidate = _profile(candidate_id)
    # Build a complementary candidate intent so a match always results.
    candidate_intent = bind_intent_profile(
        candidate, seeking=offering, offering=seeking, opted_in_at=_NOW
    )
    return suggest_match(_SUBJECT, subject_intent, candidate, candidate_intent)


def _trajectory_match(candidate_id: str, *, current_stage: str, target_stage: str):
    subject_goal = bind_career_goal(
        _SUBJECT, current_stage=current_stage, target_stage=target_stage, opted_in_at=_NOW
    )
    candidate = _profile(candidate_id)
    candidate_goal = bind_career_goal(
        candidate, current_stage=target_stage, target_stage=current_stage, opted_in_at=_NOW
    )
    return suggest_trajectory_match(_SUBJECT, subject_goal, candidate, candidate_goal)


# --- build_peer_feed -----------------------------------------------------------------


def test_build_peer_feed_merges_intent_only_candidate():
    candidate_id = "22222222-2222-4222-8222-222222222222"
    im = _intent_match(candidate_id, seeking=("mentor",), offering=())
    assert im is not None

    feed = build_peer_feed(_SUBJECT_ID, _TENANT, [im], [])
    assert len(feed) == 1
    row = feed[0]
    assert row.candidate_user_id == candidate_id
    assert row.intent_score == im.score
    assert row.trajectory_score == 0
    assert row.combined_score == im.score
    assert row.has_intent_match is True
    assert row.has_trajectory_match is False


def test_build_peer_feed_merges_trajectory_only_candidate():
    candidate_id = "22222222-2222-4222-8222-222222222222"
    tm = _trajectory_match(
        candidate_id, current_stage="senior_engineer", target_stage="staff_engineer"
    )
    assert tm is not None

    feed = build_peer_feed(_SUBJECT_ID, _TENANT, [], [tm])
    assert len(feed) == 1
    row = feed[0]
    assert row.candidate_user_id == candidate_id
    assert row.intent_score == 0
    assert row.trajectory_score == tm.score
    assert row.combined_score == tm.score
    assert row.has_intent_match is False
    assert row.has_trajectory_match is True


def test_build_peer_feed_combines_both_signals_for_the_same_candidate():
    candidate_id = "22222222-2222-4222-8222-222222222222"
    im = _intent_match(candidate_id, seeking=("mentor",), offering=())
    tm = _trajectory_match(
        candidate_id, current_stage="senior_engineer", target_stage="staff_engineer"
    )
    assert im is not None and tm is not None

    feed = build_peer_feed(_SUBJECT_ID, _TENANT, [im], [tm])
    assert len(feed) == 1
    row = feed[0]
    assert row.candidate_user_id == candidate_id
    assert row.intent_score == im.score
    assert row.trajectory_score == tm.score
    assert row.combined_score == im.score + tm.score
    assert row.has_intent_match is True
    assert row.has_trajectory_match is True


def test_build_peer_feed_orders_by_combined_score_desc_then_user_id_asc():
    high_a = "bbbbbbbb-2222-4222-8222-222222222222"
    high_b = "aaaaaaaa-3333-4333-8333-333333333333"
    low = "44444444-4444-4444-8444-444444444444"

    im_high_a = _intent_match(high_a, seeking=("mentor",), offering=())
    tm_high_a = _trajectory_match(high_a, current_stage="a", target_stage="b")
    im_high_b = _intent_match(high_b, seeking=("mentor",), offering=())
    tm_high_b = _trajectory_match(high_b, current_stage="a", target_stage="b")
    im_low = _intent_match(low, seeking=("mentor",), offering=())

    feed = build_peer_feed(
        _SUBJECT_ID,
        _TENANT,
        [im_high_a, im_high_b, im_low],
        [tm_high_a, tm_high_b],
    )
    assert [s.candidate_user_id for s in feed] == [high_b, high_a, low]


def test_build_peer_feed_respects_limit_and_clamps_to_max():
    matches = [
        _intent_match(f"{i:08d}-0000-4000-8000-000000000000", seeking=("mentor",), offering=())
        for i in range(3)
    ]
    assert len(build_peer_feed(_SUBJECT_ID, _TENANT, matches, [], limit=2)) == 2
    assert len(
        build_peer_feed(_SUBJECT_ID, _TENANT, matches, [], limit=MAX_FEED_SUGGESTIONS + 1000)
    ) <= len(matches)


def test_build_peer_feed_rejects_oversized_intent_matches():
    one = _intent_match("22222222-2222-4222-8222-222222222222", seeking=("mentor",), offering=())
    with pytest.raises(ValueError, match="intent_matches"):
        build_peer_feed(_SUBJECT_ID, _TENANT, [one] * (MAX_INPUT_MATCHES + 1), [])


def test_build_peer_feed_rejects_oversized_trajectory_matches():
    one = _trajectory_match(
        "22222222-2222-4222-8222-222222222222", current_stage="a", target_stage="b"
    )
    with pytest.raises(ValueError, match="trajectory_matches"):
        build_peer_feed(_SUBJECT_ID, _TENANT, [], [one] * (MAX_INPUT_MATCHES + 1))


def test_build_peer_feed_rejects_intent_match_for_a_different_subject():
    other_subject = _profile("33333333-3333-4333-8333-333333333333")
    other_intent = bind_intent_profile(
        other_subject, seeking=("mentor",), offering=(), opted_in_at=_NOW
    )
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    candidate_intent = bind_intent_profile(
        candidate, seeking=(), offering=("mentor",), opted_in_at=_NOW
    )
    foreign_match = suggest_match(other_subject, other_intent, candidate, candidate_intent)
    assert foreign_match is not None

    with pytest.raises(ValueError, match="intent_matches"):
        build_peer_feed(_SUBJECT_ID, _TENANT, [foreign_match], [])


def test_build_peer_feed_rejects_trajectory_match_for_a_different_subject():
    other_subject = _profile("33333333-3333-4333-8333-333333333333")
    other_goal = bind_career_goal(
        other_subject, current_stage="a", target_stage="b", opted_in_at=_NOW
    )
    candidate = _profile("22222222-2222-4222-8222-222222222222")
    candidate_goal = bind_career_goal(
        candidate, current_stage="b", target_stage="a", opted_in_at=_NOW
    )
    foreign_match = suggest_trajectory_match(other_subject, other_goal, candidate, candidate_goal)
    assert foreign_match is not None

    with pytest.raises(ValueError, match="trajectory_matches"):
        build_peer_feed(_SUBJECT_ID, _TENANT, [], [foreign_match])


def test_build_peer_feed_empty_inputs_yield_empty_feed():
    assert build_peer_feed(_SUBJECT_ID, _TENANT, [], []) == []


def test_peer_suggestion_is_frozen():
    candidate_id = "22222222-2222-4222-8222-222222222222"
    im = _intent_match(candidate_id, seeking=("mentor",), offering=())
    feed = build_peer_feed(_SUBJECT_ID, _TENANT, [im], [])
    with pytest.raises(Exception):
        feed[0].combined_score = 999  # type: ignore[misc]
