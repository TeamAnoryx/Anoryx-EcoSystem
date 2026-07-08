"""R-005 wire framing — pure unit tests (no DB) for the locked frame shapes + error pairing.

Asserts the error_code -> fixed-message pairing verbatim against the contract (the R-001 LOW-6
discipline, mirrored from R-003's REST envelope test) and that the chat.message / chat.ack /
huddle.update builders emit the locked shapes (archival hashes surfaced verbatim from whatever
the caller passes in — R-009 — inspection narrowed to pass, the ack accepted/blocked invariants).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from rendly.realtime import frames
from rendly.realtime.inspector import InspectionOutcome
from rendly.realtime.message import Message

_CONTRACT = Path(__file__).resolve().parent.parent.parent / "contracts" / "messages.schema.json"


def test_error_message_pairing_matches_contract_verbatim() -> None:
    schema = json.loads(_CONTRACT.read_text(encoding="utf-8"))
    error_frame = schema["$defs"]["ErrorFrame"]["properties"]
    codes = error_frame["error_code"]["enum"]
    messages = error_frame["message"]["enum"]
    # The contract lists code enum and message enum in the SAME order (1:1 pairing).
    contract_pairs = dict(zip(codes, messages, strict=True))
    assert frames.ERROR_MESSAGES == contract_pairs


def test_every_error_code_builds_a_valid_error_frame() -> None:
    for code in frames.ERROR_MESSAGES:
        frame = frames.build_error(error_code=code, request_id="req_test_123")
        assert frame["msg_type"] == "error"
        assert frame["error_code"] == code
        assert frame["message"] == frames.ERROR_MESSAGES[code]
        assert frame["request_id"] == "req_test_123"


def _message() -> Message:
    ts = datetime(2026, 6, 26, 12, 0, 1, tzinfo=timezone.utc)
    return Message(
        message_id="c4d5e6f7-bcde-2345-f012-34567890abcd",
        tenant_id="2a4f8c1e-0012-4b3d-9abc-d1e2f3a4b5c6",
        channel_id="b3c4d5e6-abcd-1234-ef01-234567890abc",
        sender_user_id="7d9e2f3a-1234-5c6b-8def-0123456789ab",
        content="Ship R-001 today.",
        content_type="text",
        seq=42,
        created_at=ts,
        inspection_status="pass",
        inspection_evaluated_at=ts,
    )


def test_chat_message_frame_shape() -> None:
    frame = frames.build_chat_message(_message())
    assert frame["msg_type"] == "chat.message"
    assert frame["message_id"] == "c4d5e6f7-bcde-2345-f012-34567890abcd"
    assert frame["archival"]["schema_version"] == "1"
    assert frame["archival"]["record_id"] == frame["message_id"]
    assert frame["archival"]["seq"] == 42
    # _message() builds a Message with no hash fields (the pre-R-009 / no-chain-yet shape).
    assert frame["archival"]["prev_record_hash"] is None
    assert frame["archival"]["content_hash"] is None
    assert frame["inspection"]["status"] == "pass"


def test_chat_message_frame_surfaces_real_hash_chain_fields() -> None:
    # R-009: a Message carrying real chain values (as chat_repo.insert_message now produces)
    # surfaces them verbatim on the wire — no re-derivation in the frame builder.
    msg = _message().model_copy(
        update={
            "prev_record_hash": "a" * 64,
            "content_hash": "b" * 64,
        }
    )
    frame = frames.build_chat_message(msg)
    assert frame["archival"]["prev_record_hash"] == "a" * 64
    assert frame["archival"]["content_hash"] == "b" * 64


def test_timestamps_use_z_suffix() -> None:
    # The contract examples use the 'Z' UTC form, not '+00:00'.
    assert frames.now_iso().endswith("Z")
    frame = frames.build_chat_message(_message())
    assert frame["archival"]["created_at"].endswith("Z")
    assert frame["inspection"]["evaluated_at"].endswith("Z")


def test_message_record_is_chat_message_minus_msg_type() -> None:
    record = frames.to_message_record(_message())
    assert "msg_type" not in record
    assert record["message_id"] == "c4d5e6f7-bcde-2345-f012-34567890abcd"
    assert record["archival"]["seq"] == 42
    assert record["inspection"]["status"] == "pass"


def test_chat_ack_accepted_has_message_id_no_error_code() -> None:
    ack = frames.build_chat_ack_accepted(
        tenant_id="t", client_msg_id="c-1", channel_id="ch", message_id="m-1"
    )
    assert ack["status"] == "accepted"
    assert ack["message_id"] == "m-1"
    assert "error_code" not in ack


def test_chat_ack_blocked_has_error_code_no_message_id() -> None:
    outcome = InspectionOutcome(status="blocked", evaluated_at=datetime.now(timezone.utc))
    ack = frames.build_chat_ack_blocked(
        tenant_id="t",
        client_msg_id="c-1",
        channel_id="ch",
        error_code="message_blocked",
        inspection=outcome,
    )
    assert ack["status"] == "blocked"
    assert ack["error_code"] == "message_blocked"
    assert "message_id" not in ack
    assert ack["inspection"]["status"] == "blocked"


def test_huddle_update_without_archive_has_no_archival_field() -> None:
    # Matches the ringing/accepted/active/busy/declined posture (R-007): no archive -> no field.
    frame = frames.build_huddle_update(
        huddle_id="d1e2f3a4-0000-1111-2222-333344445555",
        tenant_id="t",
        peer_user_id="u2",
        state="ringing",
    )
    assert "archival" not in frame


def test_huddle_update_with_archive_surfaces_real_hash_chain_fields() -> None:
    from rendly.realtime.huddle import HuddleArchive

    ts = datetime(2026, 7, 7, 10, 0, 0, tzinfo=timezone.utc)
    archive = HuddleArchive(
        huddle_id="d1e2f3a4-0000-1111-2222-333344445555",
        created_at=ts,
        seq=3,
        prev_record_hash="c" * 64,
        content_hash="d" * 64,
    )
    frame = frames.build_huddle_update(
        huddle_id=archive.huddle_id,
        tenant_id="t",
        peer_user_id="u2",
        state="ended",
        archive=archive,
    )
    assert frame["archival"]["schema_version"] == "1"
    assert frame["archival"]["record_id"] == archive.huddle_id
    assert frame["archival"]["seq"] == 3
    assert frame["archival"]["prev_record_hash"] == "c" * 64
    assert frame["archival"]["content_hash"] == "d" * 64
    assert frame["archival"]["created_at"].endswith("Z")
