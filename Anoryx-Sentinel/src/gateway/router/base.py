"""ProviderAdapter protocol (F-006, ADR-0008 §2.1).

Every provider adapter implements ONE protocol. complete() mirrors
proxy_non_stream's (ChatCompletionResponse, tokens_in, tokens_out) return so the
handler call site changes only its right-hand side. stream() yields OpenAI-shape
SSE lines identical in framing to _proxy_stream_generator.

Translation to OpenAI shape happens INSIDE the adapter, before any bytes leave
it — preserving the F-005 invariant that outbound inspection sees OpenAI-shape
bytes (threat #8). Adapters raise ProviderError (never raw transport errors,
never upstream body text — threat #10).
"""

from __future__ import annotations

from typing import AsyncIterator, Protocol, runtime_checkable

from gateway.models import ChatCompletionResponse, CreateChatCompletionRequest
from gateway.router.context import RoutingContext


@runtime_checkable
class ProviderAdapter(Protocol):
    """Uniform provider interface. name is one of openai|anthropic|bedrock."""

    name: str

    async def complete(
        self,
        validated_body: CreateChatCompletionRequest,
        ctx: RoutingContext,
    ) -> tuple[ChatCompletionResponse, int, int]:
        """Non-stream. Returns (OpenAI-shape response, tokens_in, tokens_out).

        Raises ProviderError(kind=...) on any failure — never a raw transport
        error and never upstream body text.
        """
        ...

    def stream(
        self,
        validated_body: CreateChatCompletionRequest,
        ctx: RoutingContext,
    ) -> AsyncIterator[str]:
        """Stream. Yields OpenAI-shape SSE lines ('data: {chunk-json}\\n'),
        terminal 'data: [DONE]', or an 'event: error\\ndata: {...}\\n\\n' frame
        then close WITHOUT [DONE] — identical framing to _proxy_stream_generator.

        NOTE: returns the async iterator (this is an `async def` generator in the
        concrete adapters); translation to OpenAI shape happens INSIDE the adapter
        before any bytes are yielded.
        """
        ...
