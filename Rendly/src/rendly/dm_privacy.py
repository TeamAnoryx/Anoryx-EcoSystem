"""DmPrivacy — a deterministic, opt-in, mutual DM-authorization gate with granular
per-field profile exposure (R-019 = FORK A1/B1/C1/D1/E1).

HONESTY BOUNDARY (verbatim, non-removable): "Privacy-controlled DM portal (granular
data exposure)" in the roadmap's task name is NOT implemented here as a portal —
there is no REST endpoint, no persistence, and no UI. What ships is the pure-domain
AUTHORIZATION GATE the eventual portal would call before letting two users exchange
a direct message: a deterministic, mutual opt-in check plus a granular, per-field
profile-exposure decision. This is a deliberate scope-down of R-019 (~10-16h, 🏦
POST-INVESTMENT, fourth task of Rendly's B2C professional-networking tier,
"Depends on: R-004/R-005 + the matching core") to a minimal seam, in the same spirit
as R-012's/R-016's/R-017's/R-018's own scoped deliveries (see ADR-0012 §Decision,
ADR-0016 §Decision, ADR-0017 §Decision, ADR-0018 §Decision) — this module reproduces
their discipline rather than inventing a new one.

"the matching core" dependency named in the roadmap is R-018's composition seam
(:mod:`rendly.peer`): a ``MATCHES_ONLY`` audience choice (see :class:`DmAudience`) is
gated on a caller-supplied :class:`~rendly.peer.PeerSuggestion` for the exact pair
being authorized — this module does not recompute matching itself, it composes
R-018's already-shipped result exactly as R-018 composed R-016's/R-017's.

NOT BUILT HERE (mirrors ADR-0018's own list): real B2C consumer identity/onboarding
(R-023, still unshipped) — this module operates over the EXISTING enterprise
``Profile`` domain (R-002) as a placeholder actor model, exactly as R-012/R-016/
R-017/R-018 did. No persistence (no new store, no new migration — a follow-up task
owns wiring ``DmPrivacySettings`` to a real per-user settings store). No REST/wire
surface, no frontend, no ML. No wiring to the REAL ``rendly.realtime`` chat runtime
(R-005's ``ChannelType.DM`` channels are tenant-scoped, RLS-protected, and entirely
separate from this cross-tenant B2C authorization gate) — a follow-up task owns
connecting this gate to actual DM-channel creation. No candidate-pool
discovery/enumeration (mirrors ADR-0016's/ADR-0017's/ADR-0018's own exclusion) —
``authorize_dm`` decides ONE already-identified pair; R-024 (Discovery feed) remains
the natural home for deciding which candidates a subject is even shown.

PRIVACY-CONTROLLED, by construction, not by policy (mirrors ``culture.py``/
``intent.py``/``career.py``/``peer.py``): a user who has never called
:func:`bind_dm_privacy_settings` has no ``DmPrivacySettings`` and structurally
cannot be authorized to send OR receive a DM here — ``authorize_dm`` REQUIRES a
real settings object for both sides (unlike ``peer.suggest_peer``'s optional
component signals), because the default for an un-opted-in user must be
fail-closed, not silently permissive. Granular data exposure is opt-in per field
(:class:`ProfileField`) and defaults to revealing NOTHING beyond what authorization
itself already required.

DELIBERATE DIVERGENCE FROM ``culture.py`` (R-012), consistent WITH ``intent.py``
(R-016) / ``career.py`` (R-017) / ``peer.py`` (R-018): DM authorization does NOT
reject cross-tenant pairs. B2C professional networking is definitionally
cross-company (see ADR-0016 Fork B, reproduced by ADR-0017/0018's own Fork B/D) —
the same reasoning applies unchanged; this gate sits downstream of the matching
core that already allows cross-tenant pairs.

DELIBERATE DIVERGENCE FROM ``peer.suggest_peer`` (R-018): authorization is MUTUAL,
not one-sided. ``peer.py``'s composed signals report a suggestion FOR a subject
ABOUT a candidate; a DM is a two-way channel, so BOTH participants' own
``DmAudience`` choice must independently permit the pairing (see Fork B) —
otherwise a permissive subject could unilaterally message a candidate whose own
settings would have refused them, defeating the "privacy-controlled" premise.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, field_validator

from .common import require_aware_utc
from .identifiers import TenantId, UserId
from .peer import PeerSuggestion
from .profile import Profile


class DmAudience(StrEnum):
    """Who a user permits to open a DM with them. Closed, fixed 3-value enum.

    ``NOBODY`` and ``ANYONE`` are the two unconditional extremes; ``MATCHES_ONLY``
    defers to the R-018 matching core (see Fork A/B below) rather than this module
    reimplementing any matching logic itself.
    """

    NOBODY = "nobody"
    MATCHES_ONLY = "matches_only"
    ANYONE = "anyone"


class ProfileField(StrEnum):
    """The FIXED, NAMED ``Profile`` fields eligible for granular DM exposure.

    Closed by construction (mirrors ``career.OptimizationGap``) — deliberately
    limited to the two internal affiliation fields ``profile.py``'s own docstring
    names as never serialized through R-001's locked, public ``User`` wire shape
    (``org_role`` / ``team``). ``user_id``/``tenant_id`` are addressing identifiers
    a DM counterpart already learns simply by being authorized (see
    :class:`DmAuthorization`), not something a per-field exposure choice could
    withhold, so they are intentionally excluded from this enum.
    """

    ORG_ROLE = "org_role"
    TEAM = "team"


# Bounded field discipline (mirrors `intent.py`'s `MAX_TAGS`): ProfileField is a closed
# 2-value enum, so this is really just a dedup guard, but the same explicit bound as every
# other opt-in tuple field in this codebase is applied for consistency.
MAX_EXPOSED_FIELDS = len(ProfileField)


class DmPrivacySettings(BaseModel):
    """A user's explicit, revocable opt-in into DM authorization. Immutable.

    Absence of a ``DmPrivacySettings`` for a user is the ONLY "opted out" state
    this module models — there is no separate boolean to forget to check, and
    (unlike ``IntentProfile``/``CareerGoal``, whose absence only excludes a user
    from MATCHING) absence here means the user structurally CANNOT be authorized
    to send or receive a DM at all, on either side of a pair — see
    :func:`authorize_dm`'s required (non-``Optional``) arguments.

    ``audience`` has no default: a caller minting a new ``DmPrivacySettings`` MUST
    make an explicit choice rather than falling back to a permissive default.
    ``exposed_fields`` defaults to empty — granular exposure is opt-IN per field,
    never assumed.

    Direct ``DmPrivacySettings(...)`` construction with hand-supplied ids is a
    lower-level primitive NOT validated against any real ``Profile`` (mirrors
    ``IntentProfile``'s/``CareerGoal``'s same reservation); it exists for
    rehydrating an already-validated record. All application code that mints NEW
    settings MUST use :func:`bind_dm_privacy_settings`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: UserId
    tenant_id: TenantId
    audience: DmAudience
    exposed_fields: tuple[ProfileField, ...] = ()
    opted_in_at: datetime

    @field_validator("opted_in_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "opted_in_at")

    @field_validator("exposed_fields")
    @classmethod
    def _bounded_and_deduped(cls, value: tuple[ProfileField, ...]) -> tuple[ProfileField, ...]:
        if len(value) > MAX_EXPOSED_FIELDS:
            raise ValueError(f"exposed_fields must not exceed {MAX_EXPOSED_FIELDS} entries")
        if len(set(value)) != len(value):
            raise ValueError("exposed_fields must not contain duplicates")
        return value


def bind_dm_privacy_settings(
    profile: Profile,
    *,
    audience: DmAudience,
    exposed_fields: tuple[ProfileField, ...] = (),
    opted_in_at: datetime,
) -> DmPrivacySettings:
    """Build ``DmPrivacySettings`` bound to a real ``Profile`` (the canonical path).

    ``user_id``/``tenant_id`` are read FROM the profile, mirroring
    :func:`rendly.intent.bind_intent_profile` / :func:`rendly.career.bind_career_goal`
    — an opt-in record's identity is derived from a validated parent, not
    hand-supplied.
    """
    return DmPrivacySettings(
        user_id=profile.user_id,
        tenant_id=profile.tenant_id,
        audience=audience,
        exposed_fields=exposed_fields,
        opted_in_at=opted_in_at,
    )


class DmAuthorization(BaseModel):
    """The result of a successful :func:`authorize_dm` call. Immutable.

    Mirrors ``PeerSuggestion``'s "report why, not just the outcome" discipline: the
    ``*_audience`` fields record which ``DmAudience`` choice each side authorized
    under, and ``peer_suggestion`` (when the pairing relied on it) is carried
    through unchanged so a caller can show "why" without recomputing it.
    ``*_exposed_fields`` are each side's OWN ``exposed_fields`` choice — reported
    independently, never merged or intersected, because what subject reveals to
    candidate and what candidate reveals to subject are independent decisions.

    There is no ``authorized: bool`` field: mirrors ``IntentMatch``/
    ``TrajectoryMatch``/``PeerSuggestion``'s "never a zero/false result" rule —
    :func:`authorize_dm` returns ``None`` instead of a ``DmAuthorization`` with
    ``authorized=False``, so a truthy return is itself the authorization.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_user_id: UserId
    subject_tenant_id: TenantId
    candidate_user_id: UserId
    candidate_tenant_id: TenantId
    subject_audience: DmAudience
    candidate_audience: DmAudience
    subject_exposed_fields: tuple[ProfileField, ...]
    candidate_exposed_fields: tuple[ProfileField, ...]
    peer_suggestion: PeerSuggestion | None


def _require_bound(profile: Profile, settings: DmPrivacySettings, *, label: str) -> None:
    if profile.user_id != settings.user_id or profile.tenant_id != settings.tenant_id:
        raise ValueError(f"{label} profile/dm-privacy-settings pair do not describe the same user")


def _require_connects_pair(
    peer_suggestion: PeerSuggestion, subject_profile: Profile, candidate_profile: Profile
) -> None:
    pair = {peer_suggestion.subject_user_id, peer_suggestion.candidate_user_id}
    if pair != {subject_profile.user_id, candidate_profile.user_id}:
        raise ValueError("peer_suggestion does not connect subject_profile and candidate_profile")


def _permits(settings: DmPrivacySettings, *, has_peer_match: bool) -> bool:
    if settings.audience == DmAudience.NOBODY:
        return False
    if settings.audience == DmAudience.ANYONE:
        return True
    return has_peer_match  # DmAudience.MATCHES_ONLY


def authorize_dm(
    subject_profile: Profile,
    subject_settings: DmPrivacySettings,
    candidate_profile: Profile,
    candidate_settings: DmPrivacySettings,
    *,
    peer_suggestion: PeerSuggestion | None = None,
) -> DmAuthorization | None:
    """Decide whether ``subject`` may open a DM with ``candidate``, or ``None`` if not.

    MUTUAL gate (Fork B, the divergence from ``peer.suggest_peer`` named in this
    module's docstring): authorization requires BOTH sides' own ``DmAudience``
    choice to independently permit the pairing (:func:`_permits`) — a permissive
    subject cannot unilaterally message a candidate whose own settings refuse them,
    and vice versa.

    ``DmAudience.MATCHES_ONLY`` on either side is satisfied only when
    ``peer_suggestion`` is supplied AND connects EXACTLY ``subject_profile`` and
    ``candidate_profile`` (order-independent — a ``PeerSuggestion`` computed in
    either direction proves the same underlying match, see ``rendly.peer``'s own
    symmetric-overlap scoring). A caller with no ``PeerSuggestion`` for the pair
    simply omits it, which fails any ``MATCHES_ONLY`` side closed.

    Returns ``None`` (never a "denied" object, mirrors ``suggest_match``/
    ``suggest_trajectory_match``/``suggest_peer``'s "never a zero-score match"
    rule) when:
    - the candidate IS the subject (no self-DM),
    - either side's ``DmAudience`` refuses the pairing.

    Cross-tenant pairs ARE authorized — see this module's docstring "DELIBERATE
    DIVERGENCE FROM culture.py" section; matches ``peer.suggest_peer``'s posture.

    Raises ``ValueError`` (refuses to compute, mirrors ``suggest_peer``) if either
    profile/settings pair is internally inconsistent, or if a supplied
    ``peer_suggestion`` does not connect this exact pair.
    """
    _require_bound(subject_profile, subject_settings, label="subject")
    _require_bound(candidate_profile, candidate_settings, label="candidate")
    if peer_suggestion is not None:
        _require_connects_pair(peer_suggestion, subject_profile, candidate_profile)

    if candidate_profile.user_id == subject_profile.user_id:
        return None

    has_peer_match = peer_suggestion is not None
    subject_permits = _permits(subject_settings, has_peer_match=has_peer_match)
    candidate_permits = _permits(candidate_settings, has_peer_match=has_peer_match)
    if not (subject_permits and candidate_permits):
        return None

    return DmAuthorization(
        subject_user_id=subject_profile.user_id,
        subject_tenant_id=subject_profile.tenant_id,
        candidate_user_id=candidate_profile.user_id,
        candidate_tenant_id=candidate_profile.tenant_id,
        subject_audience=subject_settings.audience,
        candidate_audience=candidate_settings.audience,
        subject_exposed_fields=subject_settings.exposed_fields,
        candidate_exposed_fields=candidate_settings.exposed_fields,
        peer_suggestion=peer_suggestion,
    )
