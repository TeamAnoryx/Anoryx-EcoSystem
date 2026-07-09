"""R-018: the peer-networking composition seam over intent + career (peer.py)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from rendly.career import bind_career_goal
from rendly.enums import OrgRole
from rendly.intent import bind_intent_profile
from rendly.peer import MAX_SUGGESTIONS, rank_peers, suggest_peer
from rendly.profile import Profile

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_OTHER_TENANT = "99999999-9999-4999-8999-999999999999"


def _profile(user_id: str, tenant_id: str = _TENANT, team: str | None = None) -> Profile:
    return Profile(user_id=user_id, tenant_id=tenant_id, org_role=OrgRole.MEMBER, team=team)


def _intent(profile: Profile, *, seeking=(), offering=()):
    return bind_intent_profile(profile, seeking=seeking, offering=offering, opted_in_at=_NOW)


def _goal(profile: Profile, *, current_stage: str, target_stage: str):
    return bind_career_goal(
        profile, current_stage=current_stage, target_stage=target_stage, opted_in_at=_NOW
    )


# --- suggest_peer: signal composition -------------------------------------------------


def test_suggest_peer_combines_both_signals_when_both_opted_in():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")

    suggestion = suggest_peer(
        subject,
        candidate,
        subject_intent=_intent(subject, seeking=("mentor",), offering=()),
        candidate_intent=_intent(candidate, seeking=(), offering=("mentor",)),
        subject_goal=_goal(subject, current_stage="senior_engineer", target_stage="staff_engineer"),
        candidate_goal=_goal(
            candidate, current_stage="staff_engineer", target_stage="principal_engineer"
        ),
    )

    assert suggestion is not None
    assert suggestion.intent_match is not None
    assert suggestion.trajectory_match is not None
    assert suggestion.intent_match.score == 1
    assert suggestion.trajectory_match.score == 1
    assert suggestion.score == 2
    assert suggestion.subject_user_id == subject.user_id
    assert suggestion.candidate_user_id == candidate.user_id


def test_suggest_peer_intent_only_when_candidate_has_no_career_goal():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")

    suggestion = suggest_peer(
        subject,
        candidate,
        subject_intent=_intent(subject, seeking=("mentor",), offering=()),
        candidate_intent=_intent(candidate, seeking=(), offering=("mentor",)),
        subject_goal=_goal(subject, current_stage="senior_engineer", target_stage="staff_engineer"),
        candidate_goal=None,
    )

    assert suggestion is not None
    assert suggestion.intent_match is not None
    assert suggestion.trajectory_match is None
    assert suggestion.score == 1


def test_suggest_peer_trajectory_only_when_neither_side_has_intent():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")

    suggestion = suggest_peer(
        subject,
        candidate,
        subject_goal=_goal(subject, current_stage="senior_engineer", target_stage="staff_engineer"),
        candidate_goal=_goal(
            candidate, current_stage="staff_engineer", target_stage="principal_engineer"
        ),
    )

    assert suggestion is not None
    assert suggestion.intent_match is None
    assert suggestion.trajectory_match is not None
    assert suggestion.score == 1


def test_suggest_peer_one_sided_opt_in_omits_that_component_not_the_whole_pair():
    # Subject opted into intent; candidate did not. Trajectory still composes.
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")

    suggestion = suggest_peer(
        subject,
        candidate,
        subject_intent=_intent(subject, seeking=("mentor",), offering=()),
        candidate_intent=None,
        subject_goal=_goal(subject, current_stage="senior_engineer", target_stage="staff_engineer"),
        candidate_goal=_goal(
            candidate, current_stage="staff_engineer", target_stage="principal_engineer"
        ),
    )

    assert suggestion is not None
    assert suggestion.intent_match is None
    assert suggestion.trajectory_match is not None
    assert suggestion.score == 1


def test_suggest_peer_none_when_no_signal_suppliable():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")

    assert suggest_peer(subject, candidate) is None


def test_suggest_peer_none_when_suppliable_components_have_no_overlap():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    candidate = _profile("22222222-2222-4222-8222-222222222222")

    suggestion = suggest_peer(
        subject,
        candidate,
        subject_intent=_intent(subject, seeking=("mentor",), offering=()),
        candidate_intent=_intent(candidate, seeking=("mentor",), offering=()),
        subject_goal=_goal(subject, current_stage="senior_engineer", target_stage="staff_engineer"),
        candidate_goal=_goal(candidate, current_stage="product_manager", target_stage="senior_pm"),
    )

    assert suggestion is None


def test_suggest_peer_none_for_self():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_intent = _intent(subject, seeking=("mentor",), offering=("mentor",))
    suggestion = suggest_peer(
        subject,
        subject,
        subject_intent=subject_intent,
        candidate_intent=subject_intent,
    )
    assert suggestion is None


def test_suggest_peer_allows_cross_tenant_pair():
    # Deliberate divergence from culture.suggest_connection (R-012), mirroring
    # intent.suggest_match / career.suggest_trajectory_match.
    subject = _profile("11111111-1111-4111-8111-111111111111", tenant_id=_TENANT)
    candidate = _profile("22222222-2222-4222-8222-222222222222", tenant_id=_OTHER_TENANT)

    suggestion = suggest_peer(
        subject,
        candidate,
        subject_intent=_intent(subject, seeking=("mentor",), offering=()),
        candidate_intent=_intent(candidate, seeking=(), offering=("mentor",)),
    )

    assert suggestion is not None
    assert suggestion.subject_tenant_id == _TENANT
    assert suggestion.candidate_tenant_id == _OTHER_TENANT


def test_suggest_peer_rejects_mismatched_intent_pair():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    other = _profile("22222222-2222-4222-8222-222222222222")
    candidate = _profile("33333333-3333-4333-8333-333333333333")

    with pytest.raises(ValueError, match="subject"):
        suggest_peer(
            subject,
            candidate,
            subject_intent=_intent(other, seeking=("mentor",), offering=()),
            candidate_intent=_intent(candidate, seeking=(), offering=("mentor",)),
        )


def test_suggest_peer_rejects_mismatched_goal_pair():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    other = _profile("22222222-2222-4222-8222-222222222222")
    candidate = _profile("33333333-3333-4333-8333-333333333333")

    with pytest.raises(ValueError, match="candidate"):
        suggest_peer(
            subject,
            candidate,
            subject_goal=_goal(subject, current_stage="a", target_stage="b"),
            candidate_goal=_goal(other, current_stage="b", target_stage="a"),
        )


# --- rank_peers -------------------------------------------------------------------------


def test_rank_peers_orders_by_combined_score_desc_then_user_id_asc():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_intent = _intent(subject, seeking=("mentor",), offering=())
    subject_goal = _goal(subject, current_stage="a", target_stage="b")

    both_signals = _profile("bbbbbbbb-2222-4222-8222-222222222222")  # intent 1 + traj 1 = 2
    intent_only = _profile("cccccccc-3333-4333-8333-333333333333")  # intent 1 = 1
    no_match = _profile("44444444-4444-4444-8444-444444444444")

    candidates = [
        (
            both_signals,
            _intent(both_signals, seeking=(), offering=("mentor",)),
            _goal(both_signals, current_stage="b", target_stage="c"),
        ),
        (
            intent_only,
            _intent(intent_only, seeking=(), offering=("mentor",)),
            None,
        ),
        (
            no_match,
            _intent(no_match, seeking=("x",), offering=("y",)),
            None,
        ),
    ]

    ranked = rank_peers(
        subject, candidates, subject_intent=subject_intent, subject_goal=subject_goal
    )
    assert [s.candidate_user_id for s in ranked] == [both_signals.user_id, intent_only.user_id]
    assert [s.score for s in ranked] == [2, 1]


def test_rank_peers_filters_out_none_results():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_intent = _intent(subject, seeking=("mentor",), offering=())

    no_overlap = _profile("22222222-2222-4222-8222-222222222222")
    unopted = _profile("33333333-3333-4333-8333-333333333333")

    candidates = [
        (no_overlap, _intent(no_overlap, seeking=("x",), offering=("y",)), None),
        (unopted, None, None),
    ]

    assert rank_peers(subject, candidates, subject_intent=subject_intent) == []


def test_rank_peers_respects_limit_and_clamps_to_max():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_intent = _intent(subject, seeking=("mentor",), offering=())
    candidates = [
        (
            _profile(f"{i:08d}-0000-4000-8000-000000000000"),
            _intent(
                _profile(f"{i:08d}-0000-4000-8000-000000000000"), seeking=(), offering=("mentor",)
            ),
            None,
        )
        for i in range(3)
    ]

    assert len(rank_peers(subject, candidates, subject_intent=subject_intent, limit=2)) == 2
    assert len(
        rank_peers(subject, candidates, subject_intent=subject_intent, limit=MAX_SUGGESTIONS + 1000)
    ) <= len(candidates)


def test_rank_peers_rejects_oversized_candidate_pool():
    subject = _profile("11111111-1111-4111-8111-111111111111")
    subject_intent = _intent(subject, seeking=("mentor",), offering=())
    huge_candidate = _profile("22222222-2222-4222-8222-222222222222")
    huge_intent = _intent(huge_candidate, seeking=(), offering=("mentor",))
    candidates = [(huge_candidate, huge_intent, None)] * 501

    with pytest.raises(ValueError, match="candidates"):
        rank_peers(subject, candidates, subject_intent=subject_intent)


def test_rank_peers_includes_cross_tenant_candidates():
    subject = _profile("11111111-1111-4111-8111-111111111111", tenant_id=_TENANT)
    subject_intent = _intent(subject, seeking=("mentor",), offering=())
    other_tenant_candidate = _profile(
        "22222222-2222-4222-8222-222222222222", tenant_id=_OTHER_TENANT
    )
    candidates = [
        (
            other_tenant_candidate,
            _intent(other_tenant_candidate, seeking=(), offering=("mentor",)),
            None,
        )
    ]

    ranked = rank_peers(subject, candidates, subject_intent=subject_intent)
    assert len(ranked) == 1
    assert ranked[0].candidate_tenant_id == _OTHER_TENANT
