"""Culture — an opt-in, cross-department connection-suggestion seam (R-012 = FORK G1).

HONESTY BOUNDARY (verbatim, non-removable): "AI-powered" in the roadmap's task name
describes the post-investment vision, not this implementation. What ships here is a
DETERMINISTIC tag-overlap scorer — no model, no embeddings, no learned ranking. This
is a deliberate scope-down of R-012 (Complex, 16-22h, 🏦 POST-INVESTMENT) to a minimal,
privacy-controlled seam, in the same spirit as O-009/O-010/O-011's scoped deliveries
(see ADR-0012 §Decision). Distinct from and does NOT touch profile.py's own
non-removable boundary ("intent-based matching is the post-investment B2C tier
R-016 -> R-026, deferred") — that boundary is about an *Intent* entity replacing
Profile's org_role/team; ``CultureOptIn`` below is a new, separate, additive entity
and introduces no Intent entity, no preference vector, and no B2C matching.

PRIVACY-CONTROLLED, by construction, not by policy:
- A user who has never called :func:`bind_culture_opt_in` has no ``CultureOptIn``
  record and structurally cannot appear as a subject or a candidate — every function
  in this module requires an explicit opt-in object as an argument; there is no
  code path that scans or infers interests from a user who did not opt in.
- Matching NEVER crosses tenants: :func:`suggest_connection` derives ``tenant_id``
  from the subject's own ``Profile``/``CultureOptIn`` pair and REFUSES (``ValueError``)
  a candidate pair from a different tenant, mirroring :func:`rendly.membership.
  bind_membership`'s cross-tenant refusal.
- Matching is restricted to CROSS-department pairs: a candidate sharing the
  subject's own (non-null) ``team`` is excluded — the point of R-012 is bridging
  department silos, not restating an existing team-mapped channel (R-006).

NO REST/persistence surface ships in this task (deliberate scope-down, see ADR-0012):
this is a pure, storage-agnostic computation seam over already-loaded ``Profile`` +
``CultureOptIn`` pairs, exactly as R-002 shipped domain-only before R-004 added
persistence. Wiring an opt-in store + a REST endpoint is left to a follow-up task.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

from .common import require_aware_utc
from .identifiers import TenantId, UserId
from .profile import Profile

# An interest tag: short, non-empty, bounded (mirrors `Team`'s 1..128 discipline).
Interest = Annotated[str, StringConstraints(min_length=1, max_length=64)]

# Bounded field discipline (mirrors `detectors` maxItems 16, `ice_servers` maxItems 16):
# a per-user opt-in tag list is capped so neither storage nor the O(n*m) pairwise
# scorer below is exposed to an unbounded input.
MAX_INTERESTS = 16

# Bounds the candidate pool + the result set of a single ranking call — a DoS/cost
# guard on the pairwise scorer, not a product decision about "how many suggestions
# are useful." Matches this codebase's existing hard-capped-list discipline.
MAX_CANDIDATES = 500
MAX_SUGGESTIONS = 50
DEFAULT_SUGGESTION_LIMIT = 10


class CultureOptIn(BaseModel):
    """A user's explicit, revocable opt-in into cross-department connection matching.

    Immutable. Absence of a ``CultureOptIn`` for a user is the ONLY "opted out" state
    this module models — there is no separate boolean to forget to check.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    user_id: UserId
    tenant_id: TenantId
    interests: tuple[Interest, ...]
    opted_in_at: datetime

    @field_validator("opted_in_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "opted_in_at")

    @field_validator("interests")
    @classmethod
    def _bounded_and_deduped(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) > MAX_INTERESTS:
            raise ValueError(f"interests must not exceed {MAX_INTERESTS} tags")
        # Order-independent dedup, case-sensitive (tags are opaque, not normalized —
        # normalization/casefolding is a product decision out of scope here). A
        # stable, deterministic order is kept for reproducible serialization.
        deduped = tuple(dict.fromkeys(value))
        if len(deduped) != len(value):
            raise ValueError("interests must not contain duplicates")
        return deduped


def bind_culture_opt_in(
    user_profile: Profile,
    *,
    interests: Sequence[str],
    opted_in_at: datetime,
) -> CultureOptIn:
    """Build a ``CultureOptIn`` bound to a real ``Profile`` (the canonical path).

    ``user_id``/``tenant_id`` are read FROM the profile, mirroring
    :func:`rendly.profile.bind_profile` and :func:`rendly.membership.bind_membership` —
    an opt-in record's identity is derived from a validated parent, not hand-supplied.
    """
    return CultureOptIn(
        user_id=user_profile.user_id,
        tenant_id=user_profile.tenant_id,
        interests=tuple(interests),
        opted_in_at=opted_in_at,
    )


class ConnectionSuggestion(BaseModel):
    """A single deterministic cross-department connection suggestion. Immutable."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: TenantId
    subject_user_id: UserId
    candidate_user_id: UserId
    shared_interests: tuple[str, ...]
    score: int


def _require_bound(profile: Profile, opt_in: CultureOptIn, *, label: str) -> None:
    if profile.user_id != opt_in.user_id or profile.tenant_id != opt_in.tenant_id:
        raise ValueError(f"{label} profile/opt-in pair do not describe the same user")


def suggest_connection(
    subject_profile: Profile,
    subject_opt_in: CultureOptIn,
    candidate_profile: Profile,
    candidate_opt_in: CultureOptIn,
) -> ConnectionSuggestion | None:
    """Score a single subject/candidate pair, or ``None`` if no suggestion applies.

    Returns ``None`` (never a zero-score suggestion) when:
    - the candidate IS the subject (no self-suggestion),
    - the pair shares no interest tag (nothing to base a suggestion on),
    - both have a non-null ``team`` and it is the SAME team (cross-department only —
      a same-team pair is already reachable via R-006's team-mapped channel).

    Raises ``ValueError`` (refuses to compute, mirrors ``bind_membership``) if either
    profile/opt-in pair is internally inconsistent, or if subject and candidate are
    not in the same tenant — this module never crosses a tenant boundary.
    """
    _require_bound(subject_profile, subject_opt_in, label="subject")
    _require_bound(candidate_profile, candidate_opt_in, label="candidate")
    if subject_profile.tenant_id != candidate_profile.tenant_id:
        raise ValueError("cross-tenant connection suggestion rejected")

    if candidate_profile.user_id == subject_profile.user_id:
        return None
    if (
        subject_profile.team is not None
        and candidate_profile.team is not None
        and subject_profile.team == candidate_profile.team
    ):
        return None

    shared = sorted(set(subject_opt_in.interests) & set(candidate_opt_in.interests))
    if not shared:
        return None

    return ConnectionSuggestion(
        tenant_id=subject_profile.tenant_id,
        subject_user_id=subject_profile.user_id,
        candidate_user_id=candidate_profile.user_id,
        shared_interests=tuple(shared),
        score=len(shared),
    )


def rank_connections(
    subject_profile: Profile,
    subject_opt_in: CultureOptIn,
    candidates: Sequence[tuple[Profile, CultureOptIn]],
    *,
    limit: int = DEFAULT_SUGGESTION_LIMIT,
) -> list[ConnectionSuggestion]:
    """Rank cross-department suggestions for ``subject`` against a candidate pool.

    Deterministic: ties break on ``candidate_user_id`` ascending, so the same input
    always produces the same output (no hidden randomness/recency bias). ``limit``
    is clamped to ``[0, MAX_SUGGESTIONS]``; ``candidates`` beyond ``MAX_CANDIDATES``
    is rejected outright rather than silently truncated (a caller must page its own
    candidate pool, not rely on this function to hide an unbounded scan).
    """
    if len(candidates) > MAX_CANDIDATES:
        raise ValueError(f"candidates must not exceed {MAX_CANDIDATES} entries")
    bounded_limit = max(0, min(limit, MAX_SUGGESTIONS))

    suggestions = [
        suggestion
        for candidate_profile, candidate_opt_in in candidates
        if (
            suggestion := suggest_connection(
                subject_profile, subject_opt_in, candidate_profile, candidate_opt_in
            )
        )
        is not None
    ]
    suggestions.sort(key=lambda s: (-s.score, s.candidate_user_id))
    return suggestions[:bounded_limit]
