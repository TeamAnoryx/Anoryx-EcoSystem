"""R-015: the deterministic extractive-digest seam over comms/huddle metadata (summary.py)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from rendly.summary import (
    MAX_HIGHLIGHTS,
    MAX_KEYWORDS,
    MAX_MESSAGES,
    DigestMessage,
    HuddleDigest,
    summarize_huddle,
    summarize_messages,
)

_NOW = datetime(2026, 7, 9, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_OTHER_TENANT = "99999999-9999-4999-8999-999999999999"
_CHANNEL = "22222222-2222-4222-8222-222222222222"
_OTHER_CHANNEL = "88888888-8888-4888-8888-888888888888"
_ALICE = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_BOB = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"


def _message(
    *,
    seq: int,
    content: str,
    sender_user_id: str = _ALICE,
    tenant_id: str = _TENANT,
    channel_id: str = _CHANNEL,
    message_id: str | None = None,
    created_at: datetime | None = None,
) -> DigestMessage:
    return DigestMessage(
        message_id=message_id or f"{seq:08d}-0000-4000-8000-000000000000",
        tenant_id=tenant_id,
        channel_id=channel_id,
        sender_user_id=sender_user_id,
        content=content,
        seq=seq,
        created_at=created_at or (_NOW + timedelta(minutes=seq)),
    )


# --- DigestMessage construction ------------------------------------------------------------


def test_digest_message_is_frozen():
    message = _message(seq=0, content="hello")
    with pytest.raises(ValidationError):
        message.content = "renamed"  # type: ignore[misc]


def test_digest_message_rejects_naive_created_at():
    with pytest.raises(ValidationError):
        DigestMessage(
            message_id="00000000-0000-4000-8000-000000000000",
            tenant_id=_TENANT,
            channel_id=_CHANNEL,
            sender_user_id=_ALICE,
            content="hello",
            seq=0,
            created_at=datetime(2026, 7, 9, 12, 0, 0),  # naive
        )


def test_digest_message_rejects_negative_seq():
    with pytest.raises(ValidationError, match="seq must be >= 0"):
        _message(seq=-1, content="hello")


def test_digest_message_rejects_extra_key():
    with pytest.raises(ValidationError):
        DigestMessage(
            message_id="00000000-0000-4000-8000-000000000000",
            tenant_id=_TENANT,
            channel_id=_CHANNEL,
            sender_user_id=_ALICE,
            content="hello",
            seq=0,
            created_at=_NOW,
            transcript=True,
        )


# --- summarize_messages: happy path ---------------------------------------------------------


def test_summarize_messages_reports_count_participants_and_period():
    messages = [
        _message(seq=0, content="deploy the release pipeline", sender_user_id=_ALICE),
        _message(seq=1, content="release pipeline looks green", sender_user_id=_BOB),
    ]
    digest = summarize_messages(messages)
    assert digest.tenant_id == _TENANT
    assert digest.channel_id == _CHANNEL
    assert digest.message_count == 2
    assert digest.participant_ids == tuple(sorted((_ALICE, _BOB)))
    assert digest.period_start == messages[0].created_at
    assert digest.period_end == messages[1].created_at


def test_summarize_messages_extracts_keywords_present_in_the_most_messages_first():
    messages = [
        _message(seq=0, content="pipeline release"),
        _message(seq=1, content="pipeline outage"),
        _message(seq=2, content="pipeline outage system"),
    ]
    digest = summarize_messages(messages, keyword_limit=2)
    # "pipeline" appears in all 3 messages, "outage" in 2, "release"/"system" in 1 each.
    assert digest.top_keywords == ("pipeline", "outage")


def test_summarize_messages_keyword_count_is_per_message_not_raw_occurrences():
    # a single message repeating "pipeline" 5 times still only counts once for that
    # message, so it cannot alone outrank a term spread across two other messages.
    messages = [
        _message(seq=0, content="pipeline pipeline pipeline pipeline pipeline"),
        _message(seq=1, content="outage"),
        _message(seq=2, content="outage"),
    ]
    digest = summarize_messages(messages, keyword_limit=2)
    assert digest.top_keywords == ("outage", "pipeline")


def test_summarize_messages_keyword_ties_break_alphabetically():
    messages = [_message(seq=0, content="zebra apple zebra apple")]
    digest = summarize_messages(messages, keyword_limit=2)
    assert digest.top_keywords == ("apple", "zebra")


def test_summarize_messages_drops_stopwords_and_short_tokens():
    messages = [_message(seq=0, content="the a it is of to on at hi")]
    digest = summarize_messages(messages)
    assert digest.top_keywords == ()


def test_summarize_messages_highlights_highest_scoring_messages_in_chronological_order():
    messages = [
        _message(seq=0, content="unrelated chatter about lunch"),
        _message(seq=1, content="outage outage pipeline"),
        _message(seq=2, content="pipeline pipeline outage"),
    ]
    digest = summarize_messages(messages, keyword_limit=2, highlight_limit=2)
    assert digest.top_keywords == ("outage", "pipeline")
    # messages[1] and messages[2] both score higher than messages[0] (no keyword hits);
    # the two highlights come back in seq order, not score order.
    assert digest.highlight_message_ids == (messages[1].message_id, messages[2].message_id)


def test_summarize_messages_highlight_ties_break_on_earliest_seq():
    messages = [
        _message(seq=0, content="pipeline outage"),
        _message(seq=1, content="pipeline outage"),
        _message(seq=2, content="pipeline outage"),
    ]
    digest = summarize_messages(messages, keyword_limit=2, highlight_limit=1)
    assert digest.highlight_message_ids == (messages[0].message_id,)


def test_summarize_messages_is_deterministic_regardless_of_input_order():
    forward = [
        _message(seq=0, content="pipeline outage"),
        _message(seq=1, content="pipeline stable"),
    ]
    reversed_input = list(reversed(forward))
    assert summarize_messages(forward) == summarize_messages(reversed_input)


# --- summarize_messages: bounds + limits -----------------------------------------------------


def test_summarize_messages_rejects_empty_input():
    with pytest.raises(ValueError, match="must not be empty"):
        summarize_messages([])


def test_summarize_messages_rejects_oversized_input():
    messages = [_message(seq=i, content="hello world") for i in range(MAX_MESSAGES + 1)]
    with pytest.raises(ValueError, match="must not exceed"):
        summarize_messages(messages)


def test_summarize_messages_accepts_max_sized_input():
    messages = [_message(seq=i, content="hello world") for i in range(MAX_MESSAGES)]
    digest = summarize_messages(messages)
    assert digest.message_count == MAX_MESSAGES


def test_summarize_messages_rejects_mismatched_tenant():
    messages = [
        _message(seq=0, content="hello", tenant_id=_TENANT),
        _message(seq=1, content="world", tenant_id=_OTHER_TENANT),
    ]
    with pytest.raises(ValueError, match="same tenant_id and channel_id"):
        summarize_messages(messages)


def test_summarize_messages_rejects_mismatched_channel():
    messages = [
        _message(seq=0, content="hello", channel_id=_CHANNEL),
        _message(seq=1, content="world", channel_id=_OTHER_CHANNEL),
    ]
    with pytest.raises(ValueError, match="same tenant_id and channel_id"):
        summarize_messages(messages)


def test_summarize_messages_clamps_keyword_and_highlight_limits_above_max():
    messages = [_message(seq=i, content=f"word{i} word{i} common") for i in range(20)]
    digest = summarize_messages(
        messages, keyword_limit=MAX_KEYWORDS + 50, highlight_limit=MAX_HIGHLIGHTS + 50
    )
    assert len(digest.top_keywords) <= MAX_KEYWORDS
    assert len(digest.highlight_message_ids) <= MAX_HIGHLIGHTS


def test_summarize_messages_clamps_negative_limits_to_zero():
    messages = [_message(seq=0, content="pipeline outage")]
    digest = summarize_messages(messages, keyword_limit=-5, highlight_limit=-5)
    assert digest.top_keywords == ()
    assert digest.highlight_message_ids == ()


def test_comms_digest_is_frozen():
    digest = summarize_messages([_message(seq=0, content="hello world")])
    with pytest.raises(ValidationError):
        digest.message_count = 99  # type: ignore[misc]


# --- summarize_huddle: metadata-only digest ---------------------------------------------------


def test_summarize_huddle_reports_duration_and_sorted_participants():
    started_at = _NOW
    ended_at = _NOW + timedelta(minutes=15)
    digest = summarize_huddle(
        tenant_id=_TENANT,
        huddle_id="33333333-3333-4333-8333-333333333333",
        participant_ids=[_BOB, _ALICE],
        started_at=started_at,
        ended_at=ended_at,
    )
    assert digest.participant_ids == (_ALICE, _BOB)
    assert digest.duration_seconds == 900
    assert digest.started_at == started_at
    assert digest.ended_at == ended_at


def test_summarize_huddle_rejects_empty_participants():
    with pytest.raises(ValueError, match="participant_ids must not be empty"):
        summarize_huddle(
            tenant_id=_TENANT,
            huddle_id="33333333-3333-4333-8333-333333333333",
            participant_ids=[],
            started_at=_NOW,
            ended_at=_NOW + timedelta(minutes=1),
        )


def test_summarize_huddle_rejects_ended_at_not_after_started_at():
    with pytest.raises(ValidationError, match="ended_at must be strictly after started_at"):
        summarize_huddle(
            tenant_id=_TENANT,
            huddle_id="33333333-3333-4333-8333-333333333333",
            participant_ids=[_ALICE],
            started_at=_NOW,
            ended_at=_NOW,
        )


def test_summarize_huddle_rejects_naive_timestamps():
    with pytest.raises(ValidationError):
        HuddleDigest(
            tenant_id=_TENANT,
            huddle_id="33333333-3333-4333-8333-333333333333",
            participant_ids=(_ALICE,),
            started_at=datetime(2026, 7, 9, 12, 0, 0),  # naive
            ended_at=datetime(2026, 7, 9, 12, 15, 0),  # naive
            duration_seconds=900,
        )


def test_huddle_digest_is_frozen():
    digest = summarize_huddle(
        tenant_id=_TENANT,
        huddle_id="33333333-3333-4333-8333-333333333333",
        participant_ids=[_ALICE],
        started_at=_NOW,
        ended_at=_NOW + timedelta(minutes=1),
    )
    with pytest.raises(ValidationError):
        digest.duration_seconds = 0  # type: ignore[misc]
