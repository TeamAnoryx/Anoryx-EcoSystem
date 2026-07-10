"""DiscoveryFeed — a deterministic, cross-type COMPOSITION seam over the four
already-shipped B2C ranking outputs: peer suggestions (R-018), event discovery
(R-020), opportunity matches (R-021), and mentorship matches (R-022) (R-024 =
FORK A1/B1/C1).

HONESTY BOUNDARY (verbatim, non-removable): "Discovery feed (B2C)" ships here as
a deterministic MERGE of caller-supplied, ALREADY-RANKED result lists from
``peer.rank_peers``, ``event_discovery.discover_events``,
``opportunity.rank_opportunities``, and ``mentorship.rank_mentors`` into ONE
ordered sequence of :class:`FeedItem` — no candidate-pool sourcing, no
persistence, no ML/learned relevance, no cross-type score normalization. This is
a deliberate scope-down of R-024 (~10-16h, 🏦 POST-INVESTMENT, ninth task of
Rendly's B2C professional-networking tier, "Depends on: R-004/R-005 + the
matching core") to a minimal seam, in the same spirit as R-012/R-016/R-017/
R-018/R-019/R-020/R-021/R-022/R-023's own scoped deliveries (see ADR-0024).

"Discovery feed" cannot honestly mean this module SOURCES real candidates.
ADR-0016/0017/0018/0020 each named R-024 as the future owner of "candidate-pool
eligibility/discovery" — but every one of those signals is itself still
caller-supplied and unpersisted (no ``intent_profiles``/``career_goals``/
``tech_stack_proficiencies``/``opportunities``/``event_listings`` store exists
yet), so sourcing real candidates is not an honestly buildable slice today; it
requires the still-deferred persistence layer named by every prior ADR in this
tier. What IS honestly buildable now, without inventing that store, is the ONE
new problem none of the four component modules solves: given a subject's
ALREADY-RANKED results from all four (each independently produced, each in its
own incommensurable unit — topic-overlap count, skill-tag overlap count,
proficiency-rank gap, intent+trajectory score sum), how does a caller render
ONE feed instead of four separate lists? See ADR-0024 for the full reasoning.

NOT BUILT HERE (mirrors every prior B2C-tier module's own list): real
candidate-pool sourcing/eligibility (still the largest deferred piece — see
above), persistence (this module is pure computation over caller-supplied,
already-ranked sequences), REST/wire surface (nothing in
``contracts/openapi.yaml`` changes), any frontend/UI, and any cross-type
relevance MODEL (no learned weighting, no "engagement" signal, no per-user
feed-mix preference — see Fork B's rejection of a weighted merge).

PRIVACY-CONTROLLED, by construction, not by policy (mirrors every prior
seam in this tier): this module has no candidate-sourcing capability at all —
it can only ever surface what the caller already computed via the four opt-in
gated component functions, so a user who opted into none of R-016/R-017/
R-021/R-022's signals and has no locality-eligible R-020 listings simply
supplies empty sequences and gets an empty feed, never an inferred result.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, model_validator

from .event_discovery import EventDiscoveryResult
from .identifiers import TenantId, UserId
from .mentorship import MentorshipMatch
from .opportunity import OpportunityMatch
from .peer import PeerSuggestion

# Bounds a single component's input length (mirrors the ceiling each component's
# own `rank_*`/`discover_events` function already enforces on ITS OWN output via
# MAX_SUGGESTIONS/MAX_MATCHES — a compliant caller can never hand this module more
# than that per type; this is a defense-in-depth DoS guard, not a product limit).
MAX_ITEMS_PER_TYPE = 50

# Bounds the composed feed's result set (same magnitude discipline as every
# component's own MAX_SUGGESTIONS/MAX_MATCHES).
DEFAULT_FEED_LIMIT = 20
MAX_FEED_LIMIT = 50

# The fixed, deterministic type interleave order (see Fork B) — alphabetical by
# kind value, not insertion order, so it does not silently change if this
# module's imports or parameter order are ever reshuffled.
_FEED_TYPE_ORDER: tuple["FeedItemKind", ...]


class FeedItemKind(StrEnum):
    """The four component signal types this feed composes. Closed by
    construction — a fifth type cannot be added without a code change here."""

    EVENT = "event"
    MENTORSHIP = "mentorship"
    OPPORTUNITY = "opportunity"
    PEER = "peer"


_FEED_TYPE_ORDER = (
    FeedItemKind.EVENT,
    FeedItemKind.MENTORSHIP,
    FeedItemKind.OPPORTUNITY,
    FeedItemKind.PEER,
)


class FeedItem(BaseModel):
    """One entry in a composed discovery feed. Immutable.

    Exactly one of the four payload fields is set, and it MUST match ``kind`` —
    enforced structurally (see the model validator below) so a ``FeedItem`` can
    never claim to be a ``peer`` entry while carrying an ``opportunity_match``
    payload, even via direct construction. Each payload is the component
    module's OWN result type, unchanged — this module wraps, it does not
    re-derive or duplicate any component's fields.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: FeedItemKind
    peer_suggestion: PeerSuggestion | None = None
    event_discovery: EventDiscoveryResult | None = None
    opportunity_match: OpportunityMatch | None = None
    mentorship_match: MentorshipMatch | None = None

    @model_validator(mode="after")
    def _exactly_one_payload_matches_kind(self) -> "FeedItem":
        payload_by_kind = {
            FeedItemKind.PEER: self.peer_suggestion,
            FeedItemKind.EVENT: self.event_discovery,
            FeedItemKind.OPPORTUNITY: self.opportunity_match,
            FeedItemKind.MENTORSHIP: self.mentorship_match,
        }
        present = [kind for kind, payload in payload_by_kind.items() if payload is not None]
        if present != [self.kind]:
            raise ValueError("exactly one payload matching `kind` must be set")
        return self


def _require_subject(
    label: str,
    entry_user_id: str,
    entry_tenant_id: str,
    subject_user_id: str,
    subject_tenant_id: str,
) -> None:
    if entry_user_id != subject_user_id or entry_tenant_id != subject_tenant_id:
        raise ValueError(f"{label} entry does not belong to subject")


def compose_feed(
    subject_user_id: UserId,
    subject_tenant_id: TenantId,
    *,
    peer_suggestions: Sequence[PeerSuggestion] = (),
    event_discoveries: Sequence[EventDiscoveryResult] = (),
    opportunity_matches: Sequence[OpportunityMatch] = (),
    mentorship_matches: Sequence[MentorshipMatch] = (),
    limit: int = DEFAULT_FEED_LIMIT,
) -> list[FeedItem]:
    """Compose one deterministic feed from four already-ranked component lists.

    Each ``*_matches``/``*_discoveries`` sequence is ASSUMED to already be
    best-first (i.e. produced by that component's own ``rank_peers``/
    ``discover_events``/``rank_opportunities``/``rank_mentors``) — this
    function does not re-sort WITHIN a type, only interleaves ACROSS types, in
    the fixed round-robin order EVENT, MENTORSHIP, OPPORTUNITY, PEER (see
    ADR-0024 Fork B for why no cross-type score is invented to merge by).

    ``peer_suggestions``/``opportunity_matches`` entries must each belong to
    ``(subject_user_id, subject_tenant_id)`` via their own ``subject_user_id``/
    ``subject_tenant_id`` fields; ``mentorship_matches`` entries must belong to
    the subject via their own ``mentee_user_id``/``mentee_tenant_id`` (the
    subject is always the mentee asking "who can mentor me" in this feed —
    ``rank_mentors`` is never called the other way). ``event_discoveries``
    carries no subject identity (``discover_events`` does not require one) and
    is not cross-checked. Raises ``ValueError`` on any mismatch.

    Each input sequence beyond :data:`MAX_ITEMS_PER_TYPE` is rejected outright
    rather than silently truncated. ``limit`` is clamped to
    ``[0, MAX_FEED_LIMIT]``.

    This function does no I/O and performs no candidate-pool sourcing — it only
    ever composes what the caller already computed (see module docstring).
    """
    for label, sequence in (
        ("peer_suggestions", peer_suggestions),
        ("event_discoveries", event_discoveries),
        ("opportunity_matches", opportunity_matches),
        ("mentorship_matches", mentorship_matches),
    ):
        if len(sequence) > MAX_ITEMS_PER_TYPE:
            raise ValueError(f"{label} must not exceed {MAX_ITEMS_PER_TYPE} entries")

    for peer_suggestion in peer_suggestions:
        _require_subject(
            "peer_suggestions",
            peer_suggestion.subject_user_id,
            peer_suggestion.subject_tenant_id,
            subject_user_id,
            subject_tenant_id,
        )
    for opportunity_match in opportunity_matches:
        _require_subject(
            "opportunity_matches",
            opportunity_match.subject_user_id,
            opportunity_match.subject_tenant_id,
            subject_user_id,
            subject_tenant_id,
        )
    for mentorship_match in mentorship_matches:
        _require_subject(
            "mentorship_matches",
            mentorship_match.mentee_user_id,
            mentorship_match.mentee_tenant_id,
            subject_user_id,
            subject_tenant_id,
        )

    bounded_limit = max(0, min(limit, MAX_FEED_LIMIT))

    queues: dict[FeedItemKind, list[FeedItem]] = {
        FeedItemKind.EVENT: [
            FeedItem(kind=FeedItemKind.EVENT, event_discovery=item) for item in event_discoveries
        ],
        FeedItemKind.MENTORSHIP: [
            FeedItem(kind=FeedItemKind.MENTORSHIP, mentorship_match=item)
            for item in mentorship_matches
        ],
        FeedItemKind.OPPORTUNITY: [
            FeedItem(kind=FeedItemKind.OPPORTUNITY, opportunity_match=item)
            for item in opportunity_matches
        ],
        FeedItemKind.PEER: [
            FeedItem(kind=FeedItemKind.PEER, peer_suggestion=item) for item in peer_suggestions
        ],
    }

    max_len = max((len(queue) for queue in queues.values()), default=0)
    feed: list[FeedItem] = []
    for round_index in range(max_len):
        for kind in _FEED_TYPE_ORDER:
            queue = queues[kind]
            if round_index < len(queue):
                feed.append(queue[round_index])
                if len(feed) >= bounded_limit:
                    return feed
    return feed
