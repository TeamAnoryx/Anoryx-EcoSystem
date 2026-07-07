"""R-005 wire framing — pure unit tests (no DB) for the locked frame shapes + error pairing.

Asserts the error_code -> fixed-message pairing verbatim against the contract (the R-001 LOW-6
discipline, mirrored from R-003's REST envelope test) and that the chat.message / chat.ack
builders emit the locked shapes (archival hashes null, inspection narrowed to pass, the ack
accepted/blocked invariants).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from rendly.realtime import frames
from rendly.realtime.inspector import InspectionOutcome
from rendly.realtime.message import Message

_CONTRACT = Path(__file__).resolve().parent.parent.parent / "contracts" / "messages.schema.json"


def _catalog_validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(_CONTRACT.read_text(encoding="utf-8")))


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
    assert frame["archival"]["prev_record_hash"] is None  # RESERVED (R-009)
    assert frame["archival"]["content_hash"] is None
    assert frame["inspection"]["status"] == "pass"


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


# --- R-007 huddle/signal framing --------------------------------------------------------

_TENANT = "2a4f8c1e-0012-4b3d-9abc-d1e2f3a4b5c6"
_HUDDLE = "d5e6f7a8-cdef-3456-0123-4567890abcde"
_INVITER = "7d9e2f3a-1234-5c6b-8def-0123456789ab"
_PEER = "9f8e7d6c-5b4a-3210-fedc-ba9876543210"


def test_huddle_invite_frame_channel_id_is_optional() -> None:
    frame = frames.HuddleInviteFrame(msg_type="huddle.invite", peer_user_id=_PEER)
    assert frame.channel_id is None
    with_channel = frames.HuddleInviteFrame(
        msg_type="huddle.invite", peer_user_id=_PEER, channel_id=_HUDDLE
    )
    assert with_channel.channel_id == _HUDDLE


def test_huddle_invite_frame_rejects_extra_keys() -> None:
    with pytest.raises(ValidationError):
        frames.HuddleInviteFrame(msg_type="huddle.invite", peer_user_id=_PEER, extra="nope")


def test_huddle_hangup_frame_requires_huddle_id() -> None:
    with pytest.raises(ValidationError):
        frames.HuddleHangupFrame(msg_type="huddle.hangup")
    frame = frames.HuddleHangupFrame(msg_type="huddle.hangup", huddle_id=_HUDDLE)
    assert frame.huddle_id == _HUDDLE


@pytest.mark.parametrize(
    "signal,expected_type",
    [
        ({"kind": "offer", "sdp": "v=0..."}, frames.SignalOffer),
        ({"kind": "answer", "sdp": "v=0..."}, frames.SignalAnswer),
        (
            {
                "kind": "ice-candidate",
                "candidate": "candidate:1 1 UDP ...",
                "sdp_mid": "0",
                "sdp_mline_index": 0,
            },
            frames.SignalIceCandidate,
        ),
        (
            {"kind": "ice-candidate", "candidate": "candidate:1 1 UDP ..."},
            frames.SignalIceCandidate,
        ),
    ],
)
def test_signal_send_frame_dispatches_by_kind(signal, expected_type) -> None:
    frame = frames.SignalSendFrame(msg_type="signal.send", huddle_id=_HUDDLE, signal=signal)
    assert isinstance(frame.signal, expected_type)


def test_signal_send_frame_rejects_unknown_kind() -> None:
    with pytest.raises(ValidationError):
        frames.SignalSendFrame(
            msg_type="signal.send", huddle_id=_HUDDLE, signal={"kind": "bogus", "sdp": "x"}
        )


def test_signal_send_frame_rejects_oversized_sdp() -> None:
    with pytest.raises(ValidationError):
        frames.SignalSendFrame(
            msg_type="signal.send",
            huddle_id=_HUDDLE,
            signal={"kind": "offer", "sdp": "x" * (frames.MAX_SDP_LEN + 1)},
        )


def test_signal_content_extracts_sdp_or_candidate() -> None:
    offer = frames.SignalOffer(kind="offer", sdp="v=0 offer-body")
    assert frames.signal_content(offer) == "v=0 offer-body"
    candidate = frames.SignalIceCandidate(kind="ice-candidate", candidate="candidate:1 1 UDP ...")
    assert frames.signal_content(candidate) == "candidate:1 1 UDP ..."


def test_build_huddle_update_omits_archival_when_not_given() -> None:
    frame = frames.build_huddle_update(
        huddle_id=_HUDDLE, tenant_id=_TENANT, peer_user_id=_PEER, state="ringing"
    )
    assert "archival" not in frame
    _catalog_validator().validate(frame)


def test_build_huddle_update_carries_archival_on_terminal_state() -> None:
    archival = frames.build_huddle_archival(
        huddle_id=_HUDDLE, seq=7, created_at=datetime(2026, 6, 26, 12, 5, 0, tzinfo=timezone.utc)
    )
    frame = frames.build_huddle_update(
        huddle_id=_HUDDLE, tenant_id=_TENANT, peer_user_id=_PEER, state="ended", archival=archival
    )
    assert frame["archival"]["record_id"] == _HUDDLE
    assert frame["archival"]["seq"] == 7
    assert frame["archival"]["prev_record_hash"] is None  # RESERVED (R-009)
    assert frame["archival"]["content_hash"] is None
    _catalog_validator().validate(frame)


@pytest.mark.parametrize("state", ["ringing", "accepted", "active", "declined", "ended", "busy"])
def test_build_huddle_update_every_wire_state_validates(state) -> None:
    frame = frames.build_huddle_update(
        huddle_id=_HUDDLE, tenant_id=_TENANT, peer_user_id=_PEER, state=state
    )
    _catalog_validator().validate(frame)


def test_build_signal_relay_matches_the_locked_contract() -> None:
    frame = frames.build_signal_relay(
        tenant_id=_TENANT,
        huddle_id=_HUDDLE,
        from_user_id=_PEER,
        signal={"kind": "answer", "sdp": "v=0..."},
    )
    assert frame["msg_type"] == "signal.relay"
    assert frame["from_user_id"] == _PEER
    _catalog_validator().validate(frame)
