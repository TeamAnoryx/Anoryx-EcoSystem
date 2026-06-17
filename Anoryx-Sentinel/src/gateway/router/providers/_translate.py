"""Shared OpenAI-shape translation helpers (F-006, ADR-0008 §2.4 / §2.5).

Anthropic and Bedrock responses/streams are translated to the canonical OpenAI
shape INSIDE the adapter, before any bytes leave it (threat #8). These helpers
synthesize the OpenAI envelope fields and map finish/stop reasons uniformly so
the Anthropic and Bedrock adapters stay thin and consistent.

OpenAI finish_reason is a CLOSED enum in models.py:
    stop | length | content_filter | tool_calls
Any unmapped upstream stop reason collapses to "stop" (safe default).
"""

from __future__ import annotations

import json
import time
import uuid

from gateway.models import (
    ChatCompletionChoice,
    ChatCompletionResponse,
    ChatMessage,
    UsageBlock,
)

# Upstream stop-reason -> OpenAI finish_reason. Covers Anthropic (§2.4) and
# Bedrock Converse (§2.5) vocabularies in one table.
_STOP_REASON_MAP: dict[str, str] = {
    # Anthropic Messages API
    "end_turn": "stop",
    "max_tokens": "length",
    "stop_sequence": "stop",
    "tool_use": "tool_calls",
    "refusal": "content_filter",
    "safety": "content_filter",
    # Bedrock Converse API
    "max_tokens ": "length",  # tolerate stray whitespace defensively
    "content_filtered": "content_filter",
    "guardrail_intervened": "content_filter",
}

_VALID_FINISH = {"stop", "length", "content_filter", "tool_calls"}


def map_finish_reason(upstream_reason: str | None) -> str:
    """Map an upstream stop reason to an OpenAI finish_reason (closed enum)."""
    if not upstream_reason:
        return "stop"
    mapped = _STOP_REASON_MAP.get(upstream_reason.strip(), "stop")
    return mapped if mapped in _VALID_FINISH else "stop"


def synth_id() -> str:
    """Synthesize an OpenAI-style completion id: 'chatcmpl-' + uuid4 hex."""
    return "chatcmpl-" + uuid.uuid4().hex


def build_response(
    *,
    model: str,
    content: str,
    finish_reason: str,
    prompt_tokens: int,
    completion_tokens: int,
) -> ChatCompletionResponse:
    """Build a validated OpenAI-shape ChatCompletionResponse (§2.4 / §2.5).

    A real Pydantic model so F-005 non-stream inspection sees a normal OpenAI
    dict. Raises ValidationError on a non-conformant shape — the adapter maps
    that to ProviderError(kind='parse').
    """
    return ChatCompletionResponse(
        id=synth_id(),
        object="chat.completion",
        created=int(time.time()),
        model=model,
        choices=[
            ChatCompletionChoice(
                index=0,
                message=ChatMessage(role="assistant", content=content),
                finish_reason=finish_reason,  # type: ignore[arg-type]
            )
        ],
        usage=UsageBlock(
            prompt_tokens=max(0, prompt_tokens),
            completion_tokens=max(0, completion_tokens),
            total_tokens=max(0, prompt_tokens) + max(0, completion_tokens),
        ),
    )


def chunk_line(
    *,
    chunk_id: str,
    model: str,
    created: int,
    role: str | None = None,
    content: str | None = None,
    finish_reason: str | None = None,
) -> str:
    """Build one OpenAI 'chat.completion.chunk' SSE line ('data: {...}\\n').

    Mirrors the OpenAI chunk shape the F-005 sliding window / _extract_chunk_content
    expects (choices[].delta.content). role-only first chunk, content deltas, and
    a terminal finish_reason chunk are all expressible here.
    """
    delta: dict[str, str] = {}
    if role is not None:
        delta["role"] = role
    if content is not None:
        delta["content"] = content
    payload = {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [
            {
                "index": 0,
                "delta": delta,
                "finish_reason": finish_reason,
            }
        ],
    }
    return "data: " + json.dumps(payload, separators=(",", ":")) + "\n"


DONE_LINE = "data: [DONE]\n"
