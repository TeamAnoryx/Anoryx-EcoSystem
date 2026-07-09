"""R-019: the privacy-controlled DM authorization gate (dm_privacy.py)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from rendly.dm_privacy import (
    DmAudience,
    ProfileField,
    authorize_dm,
    bind_dm_privacy_settings,
)
from rendly.enums import OrgRole
from rendly.intent import bind_intent_profile
from rendly.peer import suggest_peer
from rendly.profile import Profile

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_OTHER_TENANT = "99999999-9999-4999-8999-999999999999"


def _profile(user_id: str, tenant_id: str = _TENANT, team: str | None = None) -> Profile:
    return Profile(user_id=user_id, tenant_id=tenant_id, org_role=OrgRole.MEMBER, team=team)


def _settings(profile: Profile, *, audience: DmAudience, exposed_fields=()):
    return bind_dm_privacy_settings(
        profile, audience=audience, exposed_fields=exposed_fields, opted_in_at=_NOW
    )


_SUBJECT = _profile("11111111-1111-4111-8111-111111111111")
_CANDIDATE = _profile("22222222-2222-4222-8222-222222222222")


# --- authorize_dm: audience combinations ------------------------------------------------


def test_authorize_dm_both_anyone_authorizes():
    result = authorize_dm(
        _SUBJECT,
        _settings(_SUBJECT, audience=DmAudience.ANYONE),
        _CANDIDATE,
        _settings(_CANDIDATE, audience=DmAudience.ANYONE),
    )
    assert result is not None
    assert result.subject_user_id == _SUBJECT.user_id
    assert result.candidate_user_id == _CANDIDATE.user_id
    assert result.subject_audience == DmAudience.ANYONE
    assert result.candidate_audience == DmAudience.ANYONE
    assert result.peer_suggestion is None


def test_authorize_dm_either_side_nobody_refuses():
    subject_refuses = authorize_dm(
        _SUBJECT,
        _settings(_SUBJECT, audience=DmAudience.NOBODY),
        _CANDIDATE,
        _settings(_CANDIDATE, audience=DmAudience.ANYONE),
    )
    candidate_refuses = authorize_dm(
        _SUBJECT,
        _settings(_SUBJECT, audience=DmAudience.ANYONE),
        _CANDIDATE,
        _settings(_CANDIDATE, audience=DmAudience.NOBODY),
    )
    assert subject_refuses is None
    assert candidate_refuses is None


def test_authorize_dm_matches_only_requires_peer_suggestion():
    without_match = authorize_dm(
        _SUBJECT,
        _settings(_SUBJECT, audience=DmAudience.MATCHES_ONLY),
        _CANDIDATE,
        _settings(_CANDIDATE, audience=DmAudience.ANYONE),
    )
    assert without_match is None

    real_suggestion = suggest_peer(
        _SUBJECT,
        _CANDIDATE,
        subject_intent=bind_intent_profile(
            _SUBJECT, seeking=("mentor",), offering=(), opted_in_at=_NOW
        ),
        candidate_intent=bind_intent_profile(
            _CANDIDATE, seeking=(), offering=("mentor",), opted_in_at=_NOW
        ),
    )
    assert real_suggestion is not None

    with_match = authorize_dm(
        _SUBJECT,
        _settings(_SUBJECT, audience=DmAudience.MATCHES_ONLY),
        _CANDIDATE,
        _settings(_CANDIDATE, audience=DmAudience.ANYONE),
        peer_suggestion=real_suggestion,
    )
    assert with_match is not None
    assert with_match.peer_suggestion == real_suggestion


def test_authorize_dm_matches_only_on_both_sides_with_single_peer_suggestion():
    suggestion = suggest_peer(
        _SUBJECT,
        _CANDIDATE,
        subject_intent=bind_intent_profile(
            _SUBJECT, seeking=("mentor",), offering=(), opted_in_at=_NOW
        ),
        candidate_intent=bind_intent_profile(
            _CANDIDATE, seeking=(), offering=("mentor",), opted_in_at=_NOW
        ),
    )
    assert suggestion is not None

    result = authorize_dm(
        _SUBJECT,
        _settings(_SUBJECT, audience=DmAudience.MATCHES_ONLY),
        _CANDIDATE,
        _settings(_CANDIDATE, audience=DmAudience.MATCHES_ONLY),
        peer_suggestion=suggestion,
    )
    assert result is not None


def test_authorize_dm_none_for_self():
    assert (
        authorize_dm(
            _SUBJECT,
            _settings(_SUBJECT, audience=DmAudience.ANYONE),
            _SUBJECT,
            _settings(_SUBJECT, audience=DmAudience.ANYONE),
        )
        is None
    )


def test_authorize_dm_allows_cross_tenant_pair():
    other_tenant_candidate = _profile(
        "33333333-3333-4333-8333-333333333333", tenant_id=_OTHER_TENANT
    )
    result = authorize_dm(
        _SUBJECT,
        _settings(_SUBJECT, audience=DmAudience.ANYONE),
        other_tenant_candidate,
        _settings(other_tenant_candidate, audience=DmAudience.ANYONE),
    )
    assert result is not None
    assert result.subject_tenant_id == _TENANT
    assert result.candidate_tenant_id == _OTHER_TENANT


# --- authorize_dm: exposed fields --------------------------------------------------------


def test_authorize_dm_reports_each_sides_own_exposed_fields_independently():
    result = authorize_dm(
        _SUBJECT,
        _settings(_SUBJECT, audience=DmAudience.ANYONE, exposed_fields=(ProfileField.TEAM,)),
        _CANDIDATE,
        _settings(_CANDIDATE, audience=DmAudience.ANYONE, exposed_fields=()),
    )
    assert result is not None
    assert result.subject_exposed_fields == (ProfileField.TEAM,)
    assert result.candidate_exposed_fields == ()


# --- authorize_dm: validation --------------------------------------------------------------


def test_authorize_dm_rejects_mismatched_subject_settings():
    other = _profile("33333333-3333-4333-8333-333333333333")
    with pytest.raises(ValueError, match="subject"):
        authorize_dm(
            _SUBJECT,
            _settings(other, audience=DmAudience.ANYONE),
            _CANDIDATE,
            _settings(_CANDIDATE, audience=DmAudience.ANYONE),
        )


def test_authorize_dm_rejects_mismatched_candidate_settings():
    other = _profile("33333333-3333-4333-8333-333333333333")
    with pytest.raises(ValueError, match="candidate"):
        authorize_dm(
            _SUBJECT,
            _settings(_SUBJECT, audience=DmAudience.ANYONE),
            _CANDIDATE,
            _settings(other, audience=DmAudience.ANYONE),
        )


def test_authorize_dm_rejects_peer_suggestion_for_a_different_pair():
    unrelated = _profile("44444444-4444-4444-8444-444444444444")
    stray_suggestion = suggest_peer(
        _SUBJECT,
        unrelated,
        subject_intent=bind_intent_profile(
            _SUBJECT, seeking=("mentor",), offering=(), opted_in_at=_NOW
        ),
        candidate_intent=bind_intent_profile(
            unrelated, seeking=(), offering=("mentor",), opted_in_at=_NOW
        ),
    )
    assert stray_suggestion is not None

    with pytest.raises(ValueError, match="peer_suggestion"):
        authorize_dm(
            _SUBJECT,
            _settings(_SUBJECT, audience=DmAudience.MATCHES_ONLY),
            _CANDIDATE,
            _settings(_CANDIDATE, audience=DmAudience.ANYONE),
            peer_suggestion=stray_suggestion,
        )


# --- DmPrivacySettings validation --------------------------------------------------------


def test_dm_privacy_settings_rejects_duplicate_exposed_fields():
    with pytest.raises(ValueError):
        bind_dm_privacy_settings(
            _SUBJECT,
            audience=DmAudience.ANYONE,
            exposed_fields=(ProfileField.TEAM, ProfileField.TEAM),
            opted_in_at=_NOW,
        )


def test_dm_privacy_settings_rejects_oversized_exposed_fields():
    with pytest.raises(ValueError, match="exceed"):
        bind_dm_privacy_settings(
            _SUBJECT,
            audience=DmAudience.ANYONE,
            exposed_fields=(ProfileField.TEAM, ProfileField.ORG_ROLE, ProfileField.TEAM),
            opted_in_at=_NOW,
        )


def test_dm_privacy_settings_rejects_naive_opted_in_at():
    with pytest.raises(ValueError):
        bind_dm_privacy_settings(
            _SUBJECT,
            audience=DmAudience.ANYONE,
            opted_in_at=datetime(2026, 7, 9, 12, 0, 0),
        )


def test_bind_dm_privacy_settings_derives_identity_from_profile():
    settings = _settings(_SUBJECT, audience=DmAudience.ANYONE)
    assert settings.user_id == _SUBJECT.user_id
    assert settings.tenant_id == _SUBJECT.tenant_id
