"""Pydantic request/response models mirroring contracts/openapi.yaml (F-004).

All request schemas are CLOSED (extra='forbid'): unknown keys are rejected
with 400 invalid_request, never silently forwarded to the upstream model
(ADR-0006 Decision 8, threat #7 upstream-injection defense).

All bounds (maxLength, minItems, maxItems, minimum, maximum) are taken
directly from contracts/openapi.yaml — do NOT relax them.
"""

from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Shared closed-schema base
# ---------------------------------------------------------------------------


class _ClosedModel(BaseModel):
    """Base for all closed-schema request models (extra='forbid')."""

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------------------
# ChatMessage — shared across request and response (closed, bounded)
# ---------------------------------------------------------------------------


class ChatMessage(_ClosedModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str = Field(..., max_length=131_072)
    name: str | None = Field(default=None, max_length=256)


# ---------------------------------------------------------------------------
# CreateChatCompletionRequest — closed schema, all contract bounds enforced
# ---------------------------------------------------------------------------

StopField = Annotated[
    Union[
        Annotated[str, Field(max_length=256)],
        Annotated[list[Annotated[str, Field(max_length=256)]], Field(max_length=4)],
    ],
    Field(default=None),
]


class CreateChatCompletionRequest(_ClosedModel):
    model: str = Field(..., max_length=256)
    messages: list[ChatMessage] = Field(..., min_length=1, max_length=256)
    stream: bool = Field(default=False)
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    top_p: float | None = Field(default=None, ge=0.0, le=1.0)
    n: int = Field(default=1, ge=1, le=8)
    max_tokens: int | None = Field(default=None, ge=1, le=131_072)
    stop: Union[
        Annotated[str, Field(max_length=256)],
        Annotated[list[Annotated[str, Field(max_length=256)]], Field(max_length=4)],
        None,
    ] = None
    user: str | None = Field(default=None, max_length=256)


# ---------------------------------------------------------------------------
# ChatCompletion response shapes (non-stream)
# ---------------------------------------------------------------------------


class ChatCompletionChoice(BaseModel):
    index: int
    message: ChatMessage
    finish_reason: Literal["stop", "length", "content_filter", "tool_calls"]


class UsageBlock(BaseModel):
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)


class ChatCompletionResponse(BaseModel):
    id: str
    object: Literal["chat.completion"]
    created: int
    model: str
    choices: list[ChatCompletionChoice]
    usage: UsageBlock | None = None


# ---------------------------------------------------------------------------
# ChatCompletionChunk — SSE streaming shapes
# ---------------------------------------------------------------------------


class ChunkDelta(BaseModel):
    role: str | None = None
    content: str | None = None


class ChatCompletionChunkChoice(BaseModel):
    index: int
    delta: ChunkDelta
    finish_reason: Literal["stop", "length", "content_filter", "tool_calls"] | None = None


class ChatCompletionChunk(BaseModel):
    id: str
    object: Literal["chat.completion.chunk"]
    created: int
    model: str
    choices: list[ChatCompletionChunkChoice]


# ---------------------------------------------------------------------------
# Error envelope (closed, verbatim from contract)
# ---------------------------------------------------------------------------


class ErrorResponse(BaseModel):
    """Standard error envelope for all non-2xx responses.

    Closed schema; message is a fixed constant from ERROR_TABLE — never
    derived from request content (threat #9 / #12 information-disclosure).
    """

    model_config = ConfigDict(extra="forbid")

    error_code: Literal[
        "missing_required_header",
        "invalid_request",
        "request_too_large",
        "invalid_api_key",
        "id_context_mismatch",
        "policy_blocked",
        "rate_limit_exceeded",
        "internal_error",
    ]
    message: str = Field(..., max_length=200)
    request_id: str = Field(..., max_length=64)


# ---------------------------------------------------------------------------
# Usage event payload (matches contracts/events.schema.json UsageEvent exactly)
# ---------------------------------------------------------------------------


class UsageEventPayload(BaseModel):
    """Internal representation of the usage event before audit append.

    Field names are EXACT matches to contracts/events.schema.json UsageEvent.
    All 12 required fields are present.
    """

    event_type: Literal["usage"] = "usage"
    tenant_id: str
    team_id: str
    project_id: str
    agent_id: str
    event_id: str
    event_timestamp: str  # RFC3339 UTC
    request_id: str
    model: str
    tokens_in: int = Field(ge=0, le=10_000_000)
    tokens_out: int = Field(ge=0, le=10_000_000)
    latency_ms: int = Field(ge=0, le=3_600_000)
    cost_estimate_cents: float = Field(ge=0.0, le=100_000_000.0)
