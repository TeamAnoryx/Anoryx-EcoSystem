"""Privacy — a deterministic, fail-closed, per-field exposure-grant seam (R-019 =
FORK A1/B1/C1).

HONESTY BOUNDARY (verbatim, non-removable): "Privacy-controlled DM portal" in the
roadmap's task name ships here as neither a DM portal (no message transport, no
persistence, no REST/UI) nor per-viewer/per-relationship differentiated privacy.
What ships is the "granular data exposure" half, taken literally: a fail-closed,
per-FIELD (not per-whole-profile) exposure-grant model (:class:`PrivacySettings`)
and a deterministic redaction function (:func:`reveal`) that produces a view
containing ONLY the fields a user has explicitly granted — everything else is
withheld, including to a caller who supplies no settings at all. This is a
deliberate scope-down of R-019 (~10-16h, 🏦 POST-INVESTMENT, fifth task of Rendly's
B2C professional-networking tier) to a minimal seam, in the same spirit as
R-012/R-016/R-017/R-018's own scoped deliveries.

NOT BUILT HERE: a DM portal (no message transport — Rendly's existing R-005
real-time chat already owns messaging; this module does not touch it), any UI, any
REST/wire surface, persistence for ``PrivacySettings`` (a caller supplies it each
time, exactly as ``intent.IntentProfile``/``career.CareerGoal`` do), and per-viewer
differentiation (see Fork C's disclosed limitation below) — Rendly's pure-domain
package has no "who am I connected to / who am I DMing" concept to key a per-viewer
grant against; that is a persistence/relationship-modeling task of its own.

PRIVACY-CONTROLLED, by construction, not by policy: the DEFAULT is hidden, not
visible. A field is exposed only if its exact ``PrivacyField`` value is present in
``PrivacySettings.granted_fields`` for that user, and :func:`reveal` never infers a
grant from anything else (no "public by default", no inheriting an intent/career
opt-in as an implicit grant to show it). A caller with NO ``PrivacySettings`` at
all gets a fully redacted view — the only unconditionally-exposed fields are the
subject's own ``user_id``/``tenant_id`` (already always exposed on every match/view
type in this codebase, e.g. ``intent.IntentMatch``/``career.TrajectoryMatch``, and
needed to address the record at all).
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator

from .career import CareerGoal
from .common import require_aware_utc
from .identifiers import TenantId, UserId
from .intent import IntentProfile
from .profile import Profile


class PrivacyField(StrEnum):
    """The FIXED, NAMED set of optional profile-adjacent fields this seam can
    grant or withhold. Closed by construction (a ``StrEnum``, not an open string)
    — mirrors ``career.OptimizationGap``'s "fixed checklist" discipline, so a
    grant can never reference a field this module does not know how to redact.
    """

    TEAM = "team"
    INTENT_SEEKING = "intent_seeking"
    INTENT_OFFERING = "intent_offering"
    CAREER_CURRENT_STAGE = "career_current_stage"
    CAREER_TARGET_STAGE = "career_target_stage"


class PrivacySettings(BaseModel):
    """A user's explicit, revocable, per-field exposure grant. Immutable.

    Absence of ``PrivacySettings`` for a user (``None`` passed to :func:`reveal`)
    is the fail-closed "nothing granted" state — mirrors ``IntentProfile``'s/
    ``CareerGoal``'s own "absence is the only opted-out state" idiom, but inverted:
    here, absence means "expose nothing" rather than "not eligible to match",
    because the honest default for privacy controls is DENY, not ALLOW.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: UserId
    tenant_id: TenantId
    granted_fields: tuple[PrivacyField, ...]
    updated_at: datetime

    @field_validator("updated_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "updated_at")

    @field_validator("granted_fields")
    @classmethod
    def _no_duplicates(cls, value: tuple[PrivacyField, ...]) -> tuple[PrivacyField, ...]:
        if len(set(value)) != len(value):
            raise ValueError("granted_fields must not contain duplicates")
        return value


def bind_privacy_settings(
    profile: Profile,
    *,
    granted_fields: tuple[PrivacyField, ...] = (),
    updated_at: datetime,
) -> PrivacySettings:
    """Build ``PrivacySettings`` bound to a real ``Profile`` (the canonical path).

    ``user_id``/``tenant_id`` are read FROM the profile, mirroring
    :func:`rendly.intent.bind_intent_profile`. ``granted_fields`` defaults to
    empty — the fail-closed "grant nothing yet" starting state.
    """
    return PrivacySettings(
        user_id=profile.user_id,
        tenant_id=profile.tenant_id,
        granted_fields=granted_fields,
        updated_at=updated_at,
    )


class ExposedProfileView(BaseModel):
    """A redacted, per-field view of a ``Profile`` (+ opt-in records), produced by
    :func:`reveal`. Immutable. Each optional field is either its real value (if
    granted) or ``None`` (withheld OR simply absent on the source record — a viewer
    cannot distinguish "not granted" from "granted but not set", which is itself
    part of the privacy guarantee: a withheld field must not leak its own
    withheld-ness any more precisely than an absent one).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: UserId
    tenant_id: TenantId
    team: str | None
    intent_seeking: tuple[str, ...] | None
    intent_offering: tuple[str, ...] | None
    career_current_stage: str | None
    career_target_stage: str | None


def _check_owner(user_id: str, tenant_id: str, other_user_id: str, other_tenant_id: str) -> None:
    if user_id != other_user_id or tenant_id != other_tenant_id:
        raise ValueError("settings/intent_profile/career_goal do not describe the same user")


def reveal(
    profile: Profile,
    settings: PrivacySettings | None,
    *,
    intent_profile: IntentProfile | None = None,
    career_goal: CareerGoal | None = None,
) -> ExposedProfileView:
    """Produce a redacted view of ``profile`` (+ opt-ins) per ``settings``.

    Fail-closed: ``settings=None`` (no privacy settings on record for this user)
    yields a view with every optional field ``None`` — NOT the unredacted profile.
    Each of the five ``PrivacyField`` values is checked independently: a user may
    grant ``INTENT_SEEKING`` without ``INTENT_OFFERING``, or ``CAREER_TARGET_STAGE``
    (what they're aiming for) without ``CAREER_CURRENT_STAGE`` (where they are now)
    — this is the "granular" part of "granular data exposure", not an all-or-
    nothing profile visibility toggle.

    This function does NOT differentiate by viewer — the same ``ExposedProfileView``
    results regardless of who is asking. Rendly's pure-domain package has no "who is
    this viewer to the subject" relationship concept to key a per-viewer grant
    against (R-005's real-time chat/DM relationships live in the realtime/
    persistence layers, not here); a future task that wants per-counterparty
    differentiated exposure owns modeling that relationship first.

    Raises ``ValueError`` if a supplied ``settings``, ``intent_profile``, or
    ``career_goal`` does not belong to ``profile`` — mirrors
    ``career.optimization_gaps``'s same cross-checking discipline.
    """
    if settings is not None:
        _check_owner(profile.user_id, profile.tenant_id, settings.user_id, settings.tenant_id)
    if intent_profile is not None:
        _check_owner(
            profile.user_id, profile.tenant_id, intent_profile.user_id, intent_profile.tenant_id
        )
    if career_goal is not None:
        _check_owner(profile.user_id, profile.tenant_id, career_goal.user_id, career_goal.tenant_id)

    granted = set(settings.granted_fields) if settings is not None else set()

    return ExposedProfileView(
        user_id=profile.user_id,
        tenant_id=profile.tenant_id,
        team=(profile.team if PrivacyField.TEAM in granted else None),
        intent_seeking=(
            intent_profile.seeking
            if intent_profile is not None and PrivacyField.INTENT_SEEKING in granted
            else None
        ),
        intent_offering=(
            intent_profile.offering
            if intent_profile is not None and PrivacyField.INTENT_OFFERING in granted
            else None
        ),
        career_current_stage=(
            career_goal.current_stage
            if career_goal is not None and PrivacyField.CAREER_CURRENT_STAGE in granted
            else None
        ),
        career_target_stage=(
            career_goal.target_stage
            if career_goal is not None and PrivacyField.CAREER_TARGET_STAGE in granted
            else None
        ),
    )
