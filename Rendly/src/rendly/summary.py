"""Summary — a deterministic extractive-digest seam over already-loaded comms (R-015).

HONESTY BOUNDARY (verbatim, non-removable): the roadmap names R-015 "Context-aware
summarization of comms + meeting transcripts... AI summaries of executive comms/
transcripts; smart scheduling vs corporate calendars; automated outreach tracking"
(Complex, 16-22h, 🏦 POST-INVESTMENT). "AI summaries", "context-aware", "smart
scheduling", and "outreach tracking" describe the funded-future vision, not this
delivery. What ships here is a DETERMINISTIC, EXTRACTIVE digest over caller-supplied
comms — word-frequency keyword extraction + highest-scoring message selection. No
model, no embeddings, no generated (abstractive) text, exactly the "high-coverage
detection" / "likely defect" honesty discipline the root CLAUDE.md requires ecosystem-
wide ("audit-ready" not "compliant", etc.) applied to "summary": this module produces
a DIGEST, never a claimed "AI summary". This is a deliberate scope-down of R-015 in
the same spirit as O-009/O-010/O-011, R-012, R-013, and R-014's own scoped deliveries
(see ADR-0015 §Decision) — not the full vision.

Explicitly NOT built here (named, not silently skipped — see ADR-0015):
- No abstractive/generative summarization. There is no LLM/AI-provider dependency
  anywhere in Rendly (verified: no such import exists in this package), and R-008
  (ADR-0008 Fork A) already closed the door on reaching across product folders for
  Sentinel's own inference seam ("no shared-library mechanism across product
  folders in this monorepo... agents stay inside their assigned subproject").
  Bridging to a real AI provider is a separate, future integration task, not a
  silent addition here.
- No "meeting transcript" summarization. R-001 D4 (LOCKED) and R-009 (ADR-0009)
  both hold that huddle media is P2P and NEVER relayed through or recorded by
  Rendly, so `persistence.huddle_repo.archive_ended_huddle` persists only
  session METADATA (participants, `started_at`/`ended_at`) — there is no
  transcript text anywhere in this codebase to summarize. `summarize_huddle`
  below is honestly scoped to that metadata only; it does not pretend to
  summarize a conversation that Rendly structurally never sees.
- No "smart scheduling vs corporate calendars". No calendar integration
  (external or internal) exists anywhere in this codebase to schedule against.
- No "automated outreach tracking". No CRM/outreach integration exists anywhere
  in this codebase to track against.
- No persistence, no REST/wire surface, no `contracts/openapi.yaml` touch. This
  is a storage-agnostic computation seam over caller-supplied records, exactly
  as R-012's `culture.py` and R-013's `event.py` shipped domain-only before any
  persistence/REST follow-up.

This module intentionally does NOT import `rendly.realtime.message.Message` or
`rendly.realtime.huddle.Huddle` — the codebase's existing import direction is
`realtime -> domain` (nothing under the domain layer imports `realtime`), and this
module lives beside `culture.py`/`event.py` in that same domain layer. Instead it
defines its own minimal, decoupled `DigestMessage` input type (mirrors
`event.py`'s sibling-constant precedent, ADR-0013 Fork B, applied to a type
rather than a constant).
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator, model_validator

from .common import require_aware_utc
from .identifiers import ChannelId, TenantId, UserId, UuidStr

# Sibling redeclarations of the R-005-owned `MessageId` (`realtime/message.py`) and the
# ordinary `str` `huddle_id` (`realtime/huddle.py`) — see module docstring on why this
# module does not import `realtime.*` for them.
MessageId = UuidStr
HuddleId = UuidStr

# Mirrors `realtime.message.MessageContent` (`messages.schema.json` text_content,
# maxLength 16384) — redeclared locally for the same layering reason as the ids above.
DigestMessageContent = Annotated[str, StringConstraints(max_length=16384)]

# Bounded-list discipline (mirrors `culture.py`'s MAX_INTERESTS/MAX_CANDIDATES,
# `event.py`'s MAX_SESSIONS_PER_EVENT): a digest window is capped so neither the
# keyword scan nor the highlight-selection scan below is exposed to an unbounded
# input. A caller summarizing a longer history must page/window it itself.
MAX_MESSAGES = 1000
MAX_KEYWORDS = 10
MAX_HIGHLIGHTS = 5
DEFAULT_KEYWORD_LIMIT = MAX_KEYWORDS
DEFAULT_HIGHLIGHT_LIMIT = MAX_HIGHLIGHTS

# A keyword shorter than this is treated as noise (mirrors common extractive-summary
# practice); deterministic and independent of any external stopword corpus/library.
MIN_KEYWORD_LENGTH = 3

_TOKEN_RE = re.compile(r"[a-z0-9]+")

# A small, fixed, English stopword list — deliberately NOT sourced from an external
# corpus/library (keeps this module dependency-free and its output reproducible across
# environments/versions). Not exhaustive; a caller wanting different coverage is out
# of scope for this deterministic seam.
_STOPWORDS = frozenset(
    {
        "the",
        "and",
        "for",
        "are",
        "but",
        "not",
        "you",
        "all",
        "can",
        "her",
        "was",
        "one",
        "our",
        "out",
        "day",
        "get",
        "has",
        "him",
        "his",
        "how",
        "man",
        "new",
        "now",
        "old",
        "see",
        "two",
        "way",
        "who",
        "boy",
        "did",
        "its",
        "let",
        "put",
        "say",
        "she",
        "too",
        "use",
        "with",
        "that",
        "this",
        "have",
        "from",
        "they",
        "will",
        "would",
        "there",
        "their",
        "what",
        "about",
        "which",
        "when",
        "make",
        "like",
        "time",
        "just",
        "know",
        "take",
        "into",
        "your",
        "some",
        "could",
        "them",
        "than",
        "then",
        "look",
        "only",
        "come",
        "over",
        "think",
        "also",
        "back",
        "after",
        "work",
        "first",
        "well",
        "even",
        "want",
        "because",
        "these",
        "give",
        "most",
        "yeah",
        "okay",
        "thanks",
        "please",
        "hey",
        "hi",
        "hello",
    }
)


class DigestMessage(BaseModel):
    """A minimal, decoupled input record for :func:`summarize_messages`.

    Deliberately NOT `rendly.realtime.message.Message` (see module docstring): only
    the fields the digest algorithm actually needs. A caller loading real messages
    (e.g. via `persistence.chat_repo.load_message_history`) maps each row's `Message`
    into a `DigestMessage`; this module never reaches into `realtime` or
    `persistence` itself.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    message_id: MessageId
    tenant_id: TenantId
    channel_id: ChannelId
    sender_user_id: UserId
    content: DigestMessageContent
    seq: int
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "created_at")

    @field_validator("seq")
    @classmethod
    def _seq_nonneg(cls, value: int) -> int:
        if value < 0:
            raise ValueError("seq must be >= 0 (the archival ordering sequence)")
        return value


class CommsDigest(BaseModel):
    """A deterministic, extractive digest of a bounded window of channel messages.

    Immutable. `top_keywords` and `highlight_message_ids` are both empty-tuple-safe
    (a window with no extractable keywords still produces a valid digest with zero
    keywords/highlights, rather than raising).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: TenantId
    channel_id: ChannelId
    message_count: int
    participant_ids: tuple[UserId, ...]
    period_start: datetime
    period_end: datetime
    top_keywords: tuple[str, ...]
    highlight_message_ids: tuple[MessageId, ...]


class HuddleDigest(BaseModel):
    """A metadata-only digest of one archived huddle (see module docstring: there is
    no transcript content anywhere in this codebase to summarize). Immutable.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: TenantId
    huddle_id: HuddleId
    participant_ids: tuple[UserId, ...]
    started_at: datetime
    ended_at: datetime
    duration_seconds: int

    @field_validator("started_at", "ended_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "timestamp")

    @model_validator(mode="after")
    def _ended_after_started(self) -> "HuddleDigest":
        if self.ended_at <= self.started_at:
            raise ValueError("ended_at must be strictly after started_at")
        return self


def _tokenize(content: str) -> frozenset[str]:
    return frozenset(
        token
        for token in _TOKEN_RE.findall(content.lower())
        if len(token) >= MIN_KEYWORD_LENGTH and token not in _STOPWORDS
    )


def summarize_messages(
    messages: Sequence[DigestMessage],
    *,
    keyword_limit: int = DEFAULT_KEYWORD_LIMIT,
    highlight_limit: int = DEFAULT_HIGHLIGHT_LIMIT,
) -> CommsDigest:
    """Build a deterministic extractive digest of `messages`.

    `messages` must all share one `tenant_id` and one `channel_id` (mirrors
    `event.schedule_session`'s "existing_sessions must all belong to the same
    event" refusal) and must not exceed `MAX_MESSAGES` (bounded-list guard; a
    caller summarizing a longer history must window it itself, exactly as
    `culture.rank_connections` requires of its own `candidates`).

    Algorithm (deterministic, no hidden randomness/insertion-order dependence):
    1. Tokenize every message's `content` into a SET of distinct tokens (lowercase,
       alnum runs, stopwords and sub-`MIN_KEYWORD_LENGTH` tokens dropped) — a token
       repeated within one message counts once for that message, so a single
       message's internal repetition cannot alone dominate the digest.
    2. `top_keywords` = the `keyword_limit` tokens present in the most messages
       (message-frequency, not raw occurrence count), ties broken alphabetically
       (`(-message_count, token)`).
    3. Each message is scored by how many of `top_keywords` it contains; the
       `highlight_limit` highest-scoring messages are selected (ties broken by
       `seq` ascending — the earliest message wins), then returned in
       chronological (`seq`-ascending) order regardless of score rank.

    Raises `ValueError` on an empty or oversized `messages`, or a `messages`
    entry that does not share the same `tenant_id`/`channel_id` as the rest —
    never silently drops/truncates the mismatched entry.
    """
    if not messages:
        raise ValueError("messages must not be empty")
    if len(messages) > MAX_MESSAGES:
        raise ValueError(f"messages must not exceed {MAX_MESSAGES} entries")

    tenant_id = messages[0].tenant_id
    channel_id = messages[0].channel_id
    for message in messages:
        if message.tenant_id != tenant_id or message.channel_id != channel_id:
            raise ValueError("messages must all share the same tenant_id and channel_id")

    bounded_keyword_limit = max(0, min(keyword_limit, MAX_KEYWORDS))
    bounded_highlight_limit = max(0, min(highlight_limit, MAX_HIGHLIGHTS))

    per_message_tokens = [_tokenize(message.content) for message in messages]
    token_counts: Counter[str] = Counter()
    for tokens in per_message_tokens:
        token_counts.update(tokens)

    top_keywords = tuple(
        token
        for token, _count in sorted(token_counts.items(), key=lambda item: (-item[1], item[0]))[
            :bounded_keyword_limit
        ]
    )
    keyword_set = frozenset(top_keywords)

    scored = [
        (sum(1 for token in tokens if token in keyword_set), message.seq, message.message_id)
        for message, tokens in zip(messages, per_message_tokens)
    ]
    scored.sort(key=lambda entry: (-entry[0], entry[1]))
    selected = scored[:bounded_highlight_limit]
    highlight_message_ids = tuple(
        message_id for _score, _seq, message_id in sorted(selected, key=lambda entry: entry[1])
    )

    return CommsDigest(
        tenant_id=tenant_id,
        channel_id=channel_id,
        message_count=len(messages),
        participant_ids=tuple(sorted({message.sender_user_id for message in messages})),
        period_start=min(message.created_at for message in messages),
        period_end=max(message.created_at for message in messages),
        top_keywords=top_keywords,
        highlight_message_ids=highlight_message_ids,
    )


def summarize_huddle(
    *,
    tenant_id: str,
    huddle_id: str,
    participant_ids: Sequence[str],
    started_at: datetime,
    ended_at: datetime,
) -> HuddleDigest:
    """Build a metadata-only digest of one archived huddle (see module docstring:
    no transcript content exists anywhere in this codebase). Raises `ValueError`
    for an empty `participant_ids`; timestamp ordering and awareness are enforced
    by `HuddleDigest`'s own validators.
    """
    if not participant_ids:
        raise ValueError("participant_ids must not be empty")

    # `duration_seconds` is computed unconditionally; if `ended_at <= started_at` the
    # value below is non-positive, but `HuddleDigest._ended_after_started` rejects the
    # whole construction before any caller ever observes it.
    return HuddleDigest(
        tenant_id=tenant_id,
        huddle_id=huddle_id,
        participant_ids=tuple(sorted(participant_ids)),
        started_at=started_at,
        ended_at=ended_at,
        duration_seconds=int((ended_at - started_at).total_seconds()),
    )
