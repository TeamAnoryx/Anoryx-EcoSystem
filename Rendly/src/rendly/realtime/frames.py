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
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints

from .inspector import InspectionOutcome
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
    # FORK C baked-now: record_id = message_id, created_at + seq populated; the hash fields are
    # RESERVED (always null in R-005 — R-009 computes the chain).
    return {
        "schema_version": "1",
        "record_id": msg.message_id,
        "created_at": _iso(msg.created_at),
        "seq": msg.seq,
        "prev_record_hash": None,
        "content_hash": None,
    }


def _inspection_obj(*, status: str, evaluated_at: datetime) -> dict:
    return {"status": status, "evaluated_at": _iso(evaluated_at)}


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
        # On a DELIVERED message the seam status is always pass (fail-closed pre-send).
        "inspection": _inspection_obj(status="pass", evaluated_at=msg.inspection_evaluated_at),
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
            status=inspection.status, evaluated_at=inspection.evaluated_at
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


def build_error(*, error_code: str, request_id: str) -> dict:
    """An identity-agnostic protocol error. ``message`` is fixed by ``error_code`` (no echo)."""
    return {
        "msg_type": "error",
        "error_code": error_code,
        "message": ERROR_MESSAGES[error_code],
        "request_id": request_id,
    }
