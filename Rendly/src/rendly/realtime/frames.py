"""Wire framing for the Rendly real-time catalog (R-005).

Builds the SERVER->client frames R-005 emits and validates the CLIENT->server frames it
handles, byte-for-byte against ``contracts/messages.schema.json`` (Draft 2020-12, closed
objects, bounded fields). Server frames carry the SERVER-RESOLVED ``tenant_id`` from the
verified token; client frames never supply tenant_id/user_id.

The ``error`` frame ``message`` is a FIXED template chosen SOLELY by ``error_code`` (no
request-derived interpolation) so the envelope is structurally incapable of echoing frame
content / field names / PII — mirroring the REST ``Error`` discipline. The 1:1 pairing here is
reproduced verbatim from the locked schema and asserted by a unit test.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from .huddle import HuddleArchive
from .inspector import DetectorFinding, InspectionOutcome
from .message import Message

PROTOCOL_VERSION = "1"

# Wire id shapes (contracts/messages.schema.json $defs). Compiled once; used to validate inbound
# correlation fields before we can build a chat.ack that echoes them.
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_CLIENT_MSG_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

MAX_CONTENT_LEN = 16384  # text_content maxLength
_CONTENT_TYPES = ("text", "markdown")

# --- error frame: the LOCKED error_code -> fixed message pairing (verbatim) -------------

# Real-time error_code enum (contracts/messages.schema.json ErrorFrame.error_code).
ErrorCode = Literal[
    "unauthorized",
    "invalid_message",
    "message_too_large",
    "rate_limit_exceeded",
    "message_blocked",
    "inspection_unavailable",
    "huddle_unavailable",
    "internal_error",
]

ERROR_MESSAGES: dict[str, str] = {
    "unauthorized": "The connection is not authenticated or the token has expired.",
    "invalid_message": "The real-time frame is invalid or violates a field constraint.",
    "message_too_large": "The message exceeds the maximum allowed size.",
    "rate_limit_exceeded": "Rate limit exceeded. Slow down and retry.",
    "message_blocked": "Content was blocked by the safety inspection seam.",
    "inspection_unavailable": "The safety inspection seam is unavailable; the send was blocked.",
    "huddle_unavailable": "The requested huddle is unavailable.",
    "internal_error": "An internal error occurred. The frame was not processed.",
}

# chat.ack error_code enum (a strict subset; the synchronous result of a chat.send).
AckErrorCode = Literal[
    "message_blocked", "message_too_large", "inspection_unavailable", "invalid_message"
]


# --- inbound validation helpers --------------------------------------------------------


def valid_uuid(value: object) -> bool:
    return isinstance(value, str) and _UUID_RE.match(value) is not None


def valid_client_msg_id(value: object) -> bool:
    return isinstance(value, str) and _CLIENT_MSG_ID_RE.match(value) is not None


def valid_content_type(value: object) -> bool:
    return value is None or value in _CONTENT_TYPES


# Inbound Pydantic frames for the simple client->server types (no ack to correlate, so any
# violation is a single ``error`` frame). Closed + bounded, matching the locked schema.

_Uuid = Annotated[str, StringConstraints(pattern=_UUID_RE.pattern, max_length=64)]


class ChatReadFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")
    msg_type: Literal["chat.read"]
    channel_id: _Uuid
    up_to_message_id: _Uuid


class TypingSetFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")
    msg_type: Literal["typing.set"]
    channel_id: _Uuid
    state: Literal["start", "stop"]


class PresenceSetFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")
    msg_type: Literal["presence.set"]
    status: Literal["online", "away", "busy", "offline"]


# --- R-007: huddle / signaling inbound frames (contracts/messages.schema.json) ---------

_MAX_SDP_LEN = 65536  # Signal.offer/answer.sdp maxLength
_MAX_CANDIDATE_LEN = 1024  # Signal.ice-candidate.candidate maxLength
_SdpStr = Annotated[str, StringConstraints(max_length=_MAX_SDP_LEN)]


_ParticipantIds = Annotated[list[_Uuid], Field(min_length=1, max_length=6)]


class HuddleInviteFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")
    msg_type: Literal["huddle.invite"]
    peer_user_id: _Uuid
    channel_id: _Uuid | None = None
    participant_ids: _ParticipantIds | None = None


class HuddleHangupFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")
    msg_type: Literal["huddle.hangup"]
    huddle_id: _Uuid


class SignalOffer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["offer"]
    sdp: _SdpStr


class SignalAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["answer"]
    sdp: _SdpStr


class SignalIceCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["ice-candidate"]
    candidate: Annotated[str, StringConstraints(max_length=_MAX_CANDIDATE_LEN)]
    sdp_mid: Annotated[str, StringConstraints(max_length=64)] | None = None
    sdp_mline_index: Annotated[int, Field(ge=0, le=1024)] | None = None


# Dispatch by the `kind` const (mirrors contracts/messages.schema.json Signal oneOf) — a
# discriminated union so an unknown/mismatched `kind` is a single closed-schema validation error.
SignalPayload = Annotated[
    Union[SignalOffer, SignalAnswer, SignalIceCandidate], Field(discriminator="kind")
]


class SignalSendFrame(BaseModel):
    model_config = ConfigDict(extra="forbid")
    msg_type: Literal["signal.send"]
    huddle_id: _Uuid
    to_user_id: _Uuid | None = None
    signal: SignalPayload


# --- server->client frame builders -----------------------------------------------------


def _iso(value: datetime) -> str:
    """RFC 3339 UTC string ending in 'Z' (the iso_datetime form the contract examples use)."""
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def now_iso() -> str:
    return _iso(datetime.now(timezone.utc))


def build_session_welcome(*, tenant_id: str, user_id: str) -> dict:
    return {
        "msg_type": "session.welcome",
        "tenant_id": tenant_id,
        "user_id": user_id,
        "server_time": now_iso(),
        "protocol_version": PROTOCOL_VERSION,
    }


def _archival_meta(msg: Message) -> dict:
    # FORK C baked-now: record_id = message_id, created_at + seq populated. R-009: the hash
    # fields surface whatever chat_repo.insert_message computed — None only for a Message
    # rebuilt from a row inserted before R-009 shipped (no chain to link into yet).
    return {
        "schema_version": "1",
        "record_id": msg.message_id,
        "created_at": _iso(msg.created_at),
        "seq": msg.seq,
        "prev_record_hash": msg.prev_record_hash,
        "content_hash": msg.content_hash,
    }


def _detector_dicts(detectors: tuple[DetectorFinding, ...]) -> list[dict]:
    return [{"category": f.category, "outcome": f.outcome} for f in detectors]


def _inspection_obj(
    *,
    status: str,
    evaluated_at: datetime,
    detectors: tuple[DetectorFinding, ...] = (),
) -> dict:
    obj: dict = {"status": status, "evaluated_at": _iso(evaluated_at)}
    if detectors:
        obj["detectors"] = _detector_dicts(detectors)
    return obj


def build_chat_message(msg: Message) -> dict:
    """The server->client chat.message frame (the canonical durable envelope)."""
    return {
        "msg_type": "chat.message",
        "message_id": msg.message_id,
        "tenant_id": msg.tenant_id,
        "channel_id": msg.channel_id,
        "sender_user_id": msg.sender_user_id,
        "content": msg.content,
        "content_type": msg.content_type,
        "archival": _archival_meta(msg),
        # On a DELIVERED message the seam status is always pass (fail-closed pre-send); R-008
        # populates the per-category findings evaluated for THIS message (all "pass" by
        # construction — any "block" would have blocked the whole send).
        "inspection": _inspection_obj(
            status="pass", evaluated_at=msg.inspection_evaluated_at, detectors=msg.detectors
        ),
    }


def to_message_record(msg: Message) -> dict:
    """The REST MessageRecord = the chat.message frame minus ``msg_type`` (history payload)."""
    # Build a NEW dict (never mutate the builder's return — the project immutability rule).
    return {k: v for k, v in build_chat_message(msg).items() if k != "msg_type"}


def build_chat_ack_accepted(
    *, tenant_id: str, client_msg_id: str, channel_id: str, message_id: str
) -> dict:
    return {
        "msg_type": "chat.ack",
        "tenant_id": tenant_id,
        "client_msg_id": client_msg_id,
        "channel_id": channel_id,
        "status": "accepted",
        "message_id": message_id,
    }


def build_chat_ack_blocked(
    *,
    tenant_id: str,
    client_msg_id: str,
    channel_id: str,
    error_code: str,
    inspection: InspectionOutcome | None = None,
) -> dict:
    frame = {
        "msg_type": "chat.ack",
        "tenant_id": tenant_id,
        "client_msg_id": client_msg_id,
        "channel_id": channel_id,
        "status": "blocked",
        "error_code": error_code,
    }
    if inspection is not None:
        frame["inspection"] = _inspection_obj(
            status=inspection.status,
            evaluated_at=inspection.evaluated_at,
            detectors=inspection.detectors,
        )
    return frame


def build_typing_update(*, tenant_id: str, channel_id: str, user_id: str, state: str) -> dict:
    return {
        "msg_type": "typing.update",
        "tenant_id": tenant_id,
        "channel_id": channel_id,
        "user_id": user_id,
        "state": state,
    }


def build_presence_update(*, tenant_id: str, user_id: str, status: str) -> dict:
    return {
        "msg_type": "presence.update",
        "tenant_id": tenant_id,
        "user_id": user_id,
        "status": status,
    }


def _huddle_archival_meta(archive: HuddleArchive) -> dict:
    # record_id = huddle_id; R-009 populates real, per-tenant-chained hash fields (the caller
    # only ever passes an `archive` once persistence.huddle_repo.archive_ended_huddle succeeds).
    return {
        "schema_version": "1",
        "record_id": archive.huddle_id,
        "created_at": _iso(archive.created_at),
        "seq": archive.seq,
        "prev_record_hash": archive.prev_record_hash,
        "content_hash": archive.content_hash,
    }


def build_huddle_update(
    *,
    huddle_id: str,
    tenant_id: str,
    participant_ids: list[str],
    state: str,
    archive: HuddleArchive | None = None,
) -> dict:
    """The server->client huddle.update frame. ``participant_ids`` lists every OTHER live (or,
    for a terminal state, just-departed) participant relative to the RECIPIENT (R-011) — 1
    entry for a 1-on-1 session, up to 7 for a group. ``peer_user_id`` is populated as
    ``participant_ids[0]`` for backward compatibility (contracts/messages.schema.json
    HuddleUpdate description).

    ``archival`` is attached IFF ``archive`` is given — the caller only supplies it once the
    huddle reaches its durable ``ended`` state AND the DB archive write succeeds
    (contracts/messages.schema.json HuddleUpdate description), matching the chat.message
    archival posture. A failed archive write degrades to no ``archival`` field, never blocks
    the ``ended`` broadcast itself (see ``realtime/pipeline.py``'s best-effort archiving).
    """
    frame = {
        "msg_type": "huddle.update",
        "huddle_id": huddle_id,
        "tenant_id": tenant_id,
        "peer_user_id": participant_ids[0],
        "participant_ids": list(participant_ids),
        "state": state,
    }
    if archive is not None:
        frame["archival"] = _huddle_archival_meta(archive)
    return frame


def build_signal_relay(
    *, tenant_id: str, huddle_id: str, from_user_id: str, signal: SignalPayload
) -> dict:
    """The server->client signal.relay frame — the peer's Signal payload, relayed verbatim."""
    return {
        "msg_type": "signal.relay",
        "tenant_id": tenant_id,
        "huddle_id": huddle_id,
        "from_user_id": from_user_id,
        "signal": signal.model_dump(mode="json"),
    }


def build_error(*, error_code: str, request_id: str) -> dict:
    """An identity-agnostic protocol error. ``message`` is fixed by ``error_code`` (no echo)."""
    return {
        "msg_type": "error",
        "error_code": error_code,
        "message": ERROR_MESSAGES[error_code],
        "request_id": request_id,
    }
