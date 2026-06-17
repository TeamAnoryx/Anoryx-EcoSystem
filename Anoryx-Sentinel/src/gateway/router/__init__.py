"""Multi-provider model router (F-006, ADR-0008).

Turns the single-upstream gateway into a router across OpenAI (Chat
Completions), Anthropic (Messages API), and AWS Bedrock (Converse API). The
router sits INSIDE chat_completions.py at the L307 seam and returns a
TRANSLATED OpenAI-shape response (non-stream) or OpenAI-shape SSE lines
(stream) so the F-005 inspection, audit, and the client all keep seeing the
unchanged OpenAI surface.

Public entry points:
  - route_non_stream(...)  -> (ChatCompletionResponse, tokens_in, tokens_out)
  - route_stream(...)      -> AsyncIterator[str] of OpenAI-shape SSE lines
  - ProviderRegistry       -> per-provider client lifecycle (built in _lifespan)

NEVER logs provider keys / AWS creds / upstream response bodies (threat #1/#10).
"""

from __future__ import annotations

from gateway.router.context import RoutingContext
from gateway.router.exceptions import ProviderError, RoutingBlockedError
from gateway.router.registry import ProviderRegistry
from gateway.router.selection import route_non_stream, route_stream

__all__ = [
    "RoutingContext",
    "ProviderError",
    "RoutingBlockedError",
    "ProviderRegistry",
    "route_non_stream",
    "route_stream",
]
