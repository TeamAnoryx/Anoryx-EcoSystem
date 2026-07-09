"""Peer feed — a deterministic multi-signal aggregation seam (R-018 = FORK A1/B1).

HONESTY BOUNDARY (verbatim, non-removable): "Hyper-personalized peer-networking
INTERFACE" in the roadmap's task name ships here as neither an interface (no REST
route, no UI) nor as ML personalization. What ships is :func:`build_peer_feed` — a
DETERMINISTIC merge of two already-deterministic signal seams this codebase already
has (R-016's ``intent.IntentMatch`` and R-017's ``career.TrajectoryMatch``) into one
ranked view per candidate. "Hyper-personalized" means "combines more than one
opted-in signal type for the same subject", not "uses a model to personalize" — no
embeddings, no learned weighting, no behavioral/click data. This is a deliberate
scope-down of R-018 (~10-16h, 🏦 POST-INVESTMENT, third task of Rendly's B2C
professional-networking tier) to a minimal aggregation seam, in the same spirit as
R-012/R-016/R-017's own scoped deliveries (see ADR-0012, ADR-0016, ADR-0017
§Decision) — this module reproduces their discipline rather than inventing a new
one.

NOT BUILT HERE (mirrors ADR-0016/ADR-0017's own lists): a REST/wire surface (no
``openapi.yaml`` change — a future task owns the endpoint that calls
``intent.rank_matches`` + ``career.rank_trajectory_matches`` and feeds their output
here), a UI ("interface" in the roadmap's task name), real B2C consumer identity
(R-023, still unshipped), persistence, and any THIRD signal source beyond R-016/
R-017 (e.g. ``culture.py`` is deliberately excluded — see Fork A below).

This module does NO matching of its own and touches NO ``Profile``/opt-in records —
it is a pure MERGE over already-computed ``IntentMatch``/``TrajectoryMatch``
sequences (themselves already privacy-controlled and bounded by construction in
``intent.py``/``career.py``), so it inherits their privacy/DoS posture rather than
reimplementing it.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict

from .career import TrajectoryMatch
from .identifiers import TenantId, UserId
from .intent import IntentMatch

# Bounds each input sequence independently — a DoS guard, not a product decision.
# Set to MAX_SUGGESTIONS (50) from both intent.py/career.py's own rank_* functions:
# a caller passing THEIR output straight through never trips this; a caller passing
# a hand-built, oversized list is rejected outright rather than silently truncated.
MAX_INPUT_MATCHES = 50

# Bounds the result set of a single feed-assembly call (mirrors intent.py/career.py's
# MAX_SUGGESTIONS discipline).
MAX_FEED_SUGGESTIONS = 50
DEFAULT_FEED_LIMIT = 10


class PeerSuggestion(BaseModel):
    """A single deterministic, multi-signal peer suggestion. Immutable.

    ``intent_score`` / ``trajectory_score`` are 0 when that signal has no match for
    this candidate (an ``IntentMatch``/``TrajectoryMatch`` is never zero-score when
    present — see each module's own "never a zero-score match" rule — so a nonzero
    field here always means a real match existed). ``combined_score`` is always
    ``intent_score + trajectory_score``, never computed independently, so the two
    can never disagree (mirrors ``career.ProfileOptimizationReport``'s own
    derived-field discipline).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    subject_user_id: UserId
    subject_tenant_id: TenantId
    candidate_user_id: UserId
    candidate_tenant_id: TenantId
    intent_score: int
    trajectory_score: int
    combined_score: int
    has_intent_match: bool
    has_trajectory_match: bool


def _check_subject(
    matches: Sequence[IntentMatch] | Sequence[TrajectoryMatch],
    *,
    subject_user_id: str,
    subject_tenant_id: str,
    label: str,
) -> None:
    for m in matches:
        if m.subject_user_id != subject_user_id or m.subject_tenant_id != subject_tenant_id:
            raise ValueError(f"{label} contains a match for a different subject")


def build_peer_feed(
    subject_user_id: UserId,
    subject_tenant_id: TenantId,
    intent_matches: Sequence[IntentMatch],
    trajectory_matches: Sequence[TrajectoryMatch],
    *,
    limit: int = DEFAULT_FEED_LIMIT,
) -> list[PeerSuggestion]:
    """Merge R-016 intent matches + R-017 trajectory matches into one ranked feed.

    Every candidate present in EITHER input list appears at most once in the
    output, with both signals combined (a candidate present in both lists gets
    both scores summed, not two separate rows) — this is the whole of "hyper-
    personalized" as shipped: more than one opted-in signal considered together,
    deterministically, for the same subject.

    Deterministic: ties break on ``candidate_user_id`` ascending, so the same
    input always produces the same output (mirrors ``intent.rank_matches`` /
    ``career.rank_trajectory_matches``). ``limit`` is clamped to
    ``[0, MAX_FEED_SUGGESTIONS]``. Each of ``intent_matches`` / ``trajectory_matches``
    beyond ``MAX_INPUT_MATCHES`` is rejected outright rather than silently
    truncated.

    Raises ``ValueError`` if any match in either input does not belong to
    ``subject_user_id``/``subject_tenant_id`` — this function trusts neither
    input's provenance any more than ``intent.rank_matches``/
    ``career.rank_trajectory_matches`` trust their own candidate pools.
    """
    if len(intent_matches) > MAX_INPUT_MATCHES:
        raise ValueError(f"intent_matches must not exceed {MAX_INPUT_MATCHES} entries")
    if len(trajectory_matches) > MAX_INPUT_MATCHES:
        raise ValueError(f"trajectory_matches must not exceed {MAX_INPUT_MATCHES} entries")
    _check_subject(
        intent_matches,
        subject_user_id=subject_user_id,
        subject_tenant_id=subject_tenant_id,
        label="intent_matches",
    )
    _check_subject(
        trajectory_matches,
        subject_user_id=subject_user_id,
        subject_tenant_id=subject_tenant_id,
        label="trajectory_matches",
    )
    bounded_limit = max(0, min(limit, MAX_FEED_SUGGESTIONS))

    # candidate_user_id -> (candidate_tenant_id, intent_score, trajectory_score)
    merged: dict[str, list] = {}
    for im in intent_matches:
        row = merged.setdefault(im.candidate_user_id, [im.candidate_tenant_id, 0, 0])
        row[1] += im.score
    for tm in trajectory_matches:
        row = merged.setdefault(tm.candidate_user_id, [tm.candidate_tenant_id, 0, 0])
        row[2] += tm.score

    suggestions = [
        PeerSuggestion(
            subject_user_id=subject_user_id,
            subject_tenant_id=subject_tenant_id,
            candidate_user_id=candidate_user_id,
            candidate_tenant_id=candidate_tenant_id,
            intent_score=intent_score,
            trajectory_score=trajectory_score,
            combined_score=intent_score + trajectory_score,
            has_intent_match=intent_score > 0,
            has_trajectory_match=trajectory_score > 0,
        )
        for candidate_user_id, (
            candidate_tenant_id,
            intent_score,
            trajectory_score,
        ) in merged.items()
    ]
    suggestions.sort(key=lambda s: (-s.combined_score, s.candidate_user_id))
    return suggestions[:bounded_limit]
