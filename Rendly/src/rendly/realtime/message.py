"""Message — the R-005-owned chat record domain type.

``message_id`` is deliberately NOT defined in R-002's ``identifiers.py`` ("identifies
real-time/archival records owned by the R-005 runtime, not this domain"), so R-005 owns
modeling both the id and the ``Message`` value object. This module is PURE — pydantic +
the R-002 id constraints only, NO persistence / runtime imports — so the persistence layer
(``persistence/chat_repo.py``) can build ``Message`` objects from rows without an import cycle.

A ``Message`` is the durable chat record AND the source for the wire ``chat.message`` frame /
the REST ``MessageRecord`` (the framing lives in ``realtime/frames.py``). It carries the
archival-ready fields R-001 reserves (FORK C, baked-now): the per-channel ``seq`` and
``created_at`` populate ``ArchivalMeta``; the hash fields are NOT modeled here — they are
RESERVED (always null) until R-009 builds the chain. The inspection result on a persisted
message is ALWAYS ``pass`` (a blocked / seam-unavailable send is fail-closed and never
persisted), captured as ``inspection_status`` + ``inspection_evaluated_at``.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

from ..common import require_aware_utc
from ..identifiers import ChannelId, TenantId, UserId, UuidStr

# message_id shares the LOCKED wire UUID shape (dashed hex, case-insensitive, ≤64) — see
# contracts/messages.schema.json #/$defs/message_id. Reuse the R-002 constraint verbatim.
MessageId = UuidStr

# The wire content bound (contracts/messages.schema.json text_content, maxLength 16384).
MessageContent = Annotated[str, StringConstraints(max_length=16384)]


def new_message_id() -> str:
    """Mint a server-assigned message id (canonical dashed-hex UUID v4 — matches the wire)."""
    return str(uuid.uuid4())


class Message(BaseModel):
    """A persisted chat message = the archival record. Immutable (frozen), closed."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    message_id: MessageId
    tenant_id: TenantId
    channel_id: ChannelId
    sender_user_id: UserId
    content: MessageContent
    content_type: Literal["text", "markdown"]
    # archival.seq — monotonic per-channel; the ordering field R-009's hash chain links over.
    seq: int
    created_at: datetime
    # The inspection seam outcome at rest. ALWAYS "pass" for a persisted message in R-005
    # (fail-closed pre-persist), but typed to the full enum so R-008 needs no model change.
    inspection_status: Literal["pass", "blocked", "seam_unavailable"]
    inspection_evaluated_at: datetime

    @field_validator("created_at", "inspection_evaluated_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "timestamp")

    @field_validator("seq")
    @classmethod
    def _seq_nonneg(cls, value: int) -> int:
        if value < 0:
            raise ValueError("seq must be >= 0 (the archival ordering sequence)")
        return value
