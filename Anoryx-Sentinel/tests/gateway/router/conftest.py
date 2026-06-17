"""Shared fixtures/helpers for router tests (F-006).

NEVER live calls. Anthropic/OpenAI HTTP is stubbed via pytest-httpx; the Bedrock
aioboto3 client is a hand-rolled async stub injected via session_factory. Keys
are REPLACE_ME placeholders.
"""

from __future__ import annotations

from gateway.models import CreateChatCompletionRequest
from gateway.router.context import RoutingContext

# REPLACE_ME placeholders — never real secrets (CLAUDE.md #4). S105/S106 are
# false positives on these obvious non-secret test stubs.
REPLACE_ME_ANTHROPIC_KEY = "REPLACE_ME-anthropic-test-key"  # noqa: S105
REPLACE_ME_AWS_KEY = "REPLACE_ME-aws-access-key"  # noqa: S105
REPLACE_ME_AWS_SECRET = "REPLACE_ME-aws-secret-key"  # noqa: S105


def make_body(**overrides) -> CreateChatCompletionRequest:
    data = {
        "model": "claude-3-haiku",
        "messages": [{"role": "user", "content": "hello world"}],
    }
    data.update(overrides)
    return CreateChatCompletionRequest(**data)


def make_ctx(
    provider: str, model: str, *, budget: float = 30.0, attempt: int = 0
) -> RoutingContext:
    return RoutingContext(
        request_id="req-router-test",
        resolved_provider=provider,
        resolved_model=model,
        remaining_budget=budget,
        attempt_index=attempt,
    )
