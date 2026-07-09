"""R-019: the granular data-exposure seam (privacy.py)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from rendly.career import bind_career_goal
from rendly.enums import OrgRole
from rendly.intent import bind_intent_profile
from rendly.privacy import (
    PrivacyField,
    PrivacySettings,
    bind_privacy_settings,
    reveal,
)
from rendly.profile import Profile

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_USER_ID = "11111111-1111-4111-8111-111111111111"


def _profile(team: str | None = "platform") -> Profile:
    return Profile(user_id=_USER_ID, tenant_id=_TENANT, org_role=OrgRole.MEMBER, team=team)


_PROFILE = _profile()


def _settings(*fields: PrivacyField) -> PrivacySettings:
    return bind_privacy_settings(_PROFILE, granted_fields=fields, updated_at=_NOW)


def _intent(seeking=("mentor",), offering=("python",)):
    return bind_intent_profile(_PROFILE, seeking=seeking, offering=offering, opted_in_at=_NOW)


def _goal(current_stage="senior_engineer", target_stage="staff_engineer"):
    return bind_career_goal(
        _PROFILE, current_stage=current_stage, target_stage=target_stage, opted_in_at=_NOW
    )


# --- PrivacySettings construction -----------------------------------------------------


def test_bind_privacy_settings_derives_ids_from_profile():
    settings = bind_privacy_settings(_PROFILE, granted_fields=(PrivacyField.TEAM,), updated_at=_NOW)
    assert settings.user_id == _PROFILE.user_id
    assert settings.tenant_id == _PROFILE.tenant_id
    assert settings.granted_fields == (PrivacyField.TEAM,)


def test_bind_privacy_settings_defaults_to_nothing_granted():
    settings = bind_privacy_settings(_PROFILE, updated_at=_NOW)
    assert settings.granted_fields == ()


def test_privacy_settings_is_frozen():
    settings = _settings(PrivacyField.TEAM)
    with pytest.raises(ValidationError):
        settings.granted_fields = ()  # type: ignore[misc]


def test_privacy_settings_rejects_naive_datetime():
    with pytest.raises(ValidationError):
        PrivacySettings(
            user_id=_USER_ID,
            tenant_id=_TENANT,
            granted_fields=(),
            updated_at=datetime(2026, 7, 9, 12, 0, 0),  # naive
        )


def test_privacy_settings_rejects_duplicate_grants():
    with pytest.raises(ValidationError, match="duplicates"):
        PrivacySettings(
            user_id=_USER_ID,
            tenant_id=_TENANT,
            granted_fields=(PrivacyField.TEAM, PrivacyField.TEAM),
            updated_at=_NOW,
        )


def test_privacy_settings_rejects_extra_key():
    with pytest.raises(ValidationError):
        PrivacySettings(
            user_id=_USER_ID,
            tenant_id=_TENANT,
            granted_fields=(),
            updated_at=_NOW,
            embedding=[0.1, 0.2],
        )


# --- reveal: fail-closed defaults ------------------------------------------------------


def test_reveal_with_no_settings_hides_everything():
    view = reveal(_PROFILE, None, intent_profile=_intent(), career_goal=_goal())
    assert view.user_id == _PROFILE.user_id
    assert view.tenant_id == _PROFILE.tenant_id
    assert view.team is None
    assert view.intent_seeking is None
    assert view.intent_offering is None
    assert view.career_current_stage is None
    assert view.career_target_stage is None


def test_reveal_with_empty_grants_hides_everything():
    view = reveal(_PROFILE, _settings(), intent_profile=_intent(), career_goal=_goal())
    assert view.team is None
    assert view.intent_seeking is None
    assert view.intent_offering is None
    assert view.career_current_stage is None
    assert view.career_target_stage is None


def test_reveal_grants_are_independent_per_field():
    settings = _settings(PrivacyField.INTENT_SEEKING, PrivacyField.CAREER_TARGET_STAGE)
    view = reveal(_PROFILE, settings, intent_profile=_intent(), career_goal=_goal())
    assert view.intent_seeking == ("mentor",)
    assert view.intent_offering is None
    assert view.career_target_stage == "staff_engineer"
    assert view.career_current_stage is None
    assert view.team is None


def test_reveal_grants_everything_when_all_fields_granted():
    settings = _settings(*PrivacyField)
    view = reveal(_PROFILE, settings, intent_profile=_intent(), career_goal=_goal())
    assert view.team == "platform"
    assert view.intent_seeking == ("mentor",)
    assert view.intent_offering == ("python",)
    assert view.career_current_stage == "senior_engineer"
    assert view.career_target_stage == "staff_engineer"


@pytest.mark.parametrize(
    ("field", "attr"),
    [
        (PrivacyField.INTENT_SEEKING, "intent_seeking"),
        (PrivacyField.INTENT_OFFERING, "intent_offering"),
        (PrivacyField.CAREER_CURRENT_STAGE, "career_current_stage"),
        (PrivacyField.CAREER_TARGET_STAGE, "career_target_stage"),
    ],
)
def test_reveal_granted_field_with_no_source_record_is_still_none(field, attr):
    # A field granted but with no intent_profile/career_goal supplied at all --
    # a viewer cannot distinguish "not granted" from "granted but nothing to show".
    settings = _settings(field)
    view = reveal(_PROFILE, settings)  # no intent_profile, no career_goal
    assert getattr(view, attr) is None


def test_reveal_team_none_on_profile_is_withheld_as_none_even_when_granted():
    profile = _profile(team=None)
    settings = bind_privacy_settings(profile, granted_fields=(PrivacyField.TEAM,), updated_at=_NOW)
    view = reveal(profile, settings)
    assert view.team is None


def test_reveal_grants_a_real_empty_value_not_a_withheld_none():
    # A granted field whose opted-in source value is itself empty must surface
    # as the real empty value, not be confused with "withheld" (None).
    settings = _settings(PrivacyField.INTENT_SEEKING)
    intent = _intent(seeking=(), offering=("python",))
    view = reveal(_PROFILE, settings, intent_profile=intent)
    assert view.intent_seeking == ()
    assert view.intent_seeking is not None


# --- reveal: provenance checks ----------------------------------------------------------


def test_reveal_rejects_settings_for_a_different_user():
    other = Profile(
        user_id="22222222-2222-4222-8222-222222222222", tenant_id=_TENANT, org_role=OrgRole.MEMBER
    )
    other_settings = bind_privacy_settings(
        other, granted_fields=(PrivacyField.TEAM,), updated_at=_NOW
    )
    with pytest.raises(ValueError, match="same user"):
        reveal(_PROFILE, other_settings)


def test_reveal_rejects_settings_for_same_user_id_but_different_tenant():
    # Same user_id, different tenant_id -- _check_owner's OR must catch a
    # tenant mismatch even when the user_id half happens to match.
    mismatched_settings = PrivacySettings(
        user_id=_USER_ID,
        tenant_id="99999999-9999-4999-8999-999999999999",
        granted_fields=(PrivacyField.TEAM,),
        updated_at=_NOW,
    )
    with pytest.raises(ValueError, match="same user"):
        reveal(_PROFILE, mismatched_settings)


def test_reveal_rejects_intent_profile_for_a_different_user():
    other = Profile(
        user_id="22222222-2222-4222-8222-222222222222", tenant_id=_TENANT, org_role=OrgRole.MEMBER
    )
    other_intent = bind_intent_profile(other, seeking=("mentor",), offering=(), opted_in_at=_NOW)
    with pytest.raises(ValueError, match="same user"):
        reveal(_PROFILE, _settings(), intent_profile=other_intent)


def test_reveal_rejects_career_goal_for_a_different_user():
    other = Profile(
        user_id="22222222-2222-4222-8222-222222222222", tenant_id=_TENANT, org_role=OrgRole.MEMBER
    )
    other_goal = bind_career_goal(other, current_stage="a", target_stage="b", opted_in_at=_NOW)
    with pytest.raises(ValueError, match="same user"):
        reveal(_PROFILE, _settings(), career_goal=other_goal)


def test_exposed_profile_view_is_frozen():
    view = reveal(_PROFILE, None)
    with pytest.raises(ValidationError):
        view.team = "leaked"  # type: ignore[misc]
