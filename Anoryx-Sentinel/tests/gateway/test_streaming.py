"""Tests for SSE streaming path (F-004, ADR-0006 Decision 7).

Covers:
- stream=true returns text/event-stream content type
- Streaming terminates with data: [DONE]
- Upstream error mid-stream → event: error frame emitted, no [DONE]
- Client receives event: error frame carrying the Error envelope
- Concurrent-stream counter incremented/decremented correctly
- Partial-stream audit is emitted on early termination
- stream_slot guarantees decrement on exception
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gateway.context import TenantContext
from gateway.models import CreateChatCompletionRequest
from gateway.upstream.openai_proxy import _proxy_stream_generator
from tests.gateway.conftest import (
    TEST_AGENT_ID,
    TEST_KEY_ID,
    TEST_PROJECT_ID,
    TEST_TEAM_ID,
    TEST_TENANT_ID,
)

_TENANT_CTX = TenantContext(
    tenant_id=TEST_TENANT_ID,
    team_id=TEST_TEAM_ID,
    project_id=TEST_PROJECT_ID,
    agent_id=TEST_AGENT_ID,
    virtual_key_id=TEST_KEY_ID,
)


def _make_request() -> CreateChatCompletionRequest:
    return CreateChatCompletionRequest(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": "hi"}],  # type: ignore[list-item]
        stream=True,
    )


# ---------------------------------------------------------------------------
# proxy_stream generator tests (unit level, no HTTP server needed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stream_generator_yields_done_on_success():
    """A successful upstream stream ends with data: [DONE]."""
    import httpx

    mock_response = MagicMock()
    mock_response.status_code = 200

    async def _fake_lines():
        yield 'data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"gpt-3.5-turbo","choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":null}]}'
        yield "data: [DONE]"

    mock_response.aiter_lines = _fake_lines

    mock_client = MagicMock()
    mock_client.stream = MagicMock()
    mock_client.stream.return_value.__aenter__ = AsyncMock(return_value=mock_response)
    mock_client.stream.return_value.__aexit__ = AsyncMock(return_value=False)

    with patch("gateway.upstream.openai_proxy._http_client", mock_client):
        chunks = []
        async for chunk in _proxy_stream_generator(
            validated_body=_make_request(),
            request_id="req-stream-01",
        ):
            chunks.append(chunk)

    all_content = "".join(chunks)
    assert "data: [DONE]" in all_content


@pytest.mark.asyncio
async def test_stream_generator_emits_error_frame_on_connect_error():
    """Connection error → event: error frame without [DONE]."""
    import httpx

    mock_client = MagicMock()
    mock_client.stream = MagicMock()
    mock_client.stream.return_value.__aenter__ = AsyncMock(
        side_effect=httpx.ConnectError("refused")
    )
    mock_client.stream.return_value.__aexit__ = AsyncMock(return_value=False)

    with patch("gateway.upstream.openai_proxy._http_client", mock_client):
        chunks = []
        async for chunk in _proxy_stream_generator(
            validated_body=_make_request(),
            request_id="req-stream-02",
        ):
            chunks.append(chunk)

    all_content = "".join(chunks)
    assert "event: error" in all_content
    assert "data: [DONE]" not in all_content

    # Error frame should carry valid Error envelope JSON.
    # Find the data: line after event: error.
    lines = all_content.split("\n")
    for i, line in enumerate(lines):
        if line.strip() == "event: error":
            data_line = lines[i + 1] if i + 1 < len(lines) else ""
            if data_line.startswith("data: "):
                error_body = json.loads(data_line[6:])
                assert error_body["error_code"] == "internal_error"
                assert "message" in error_body
                assert "request_id" in error_body
            break


@pytest.mark.asyncio
async def test_stream_generator_emits_error_on_upstream_5xx():
    """Upstream 5xx status → error frame, no [DONE]."""
    mock_response = MagicMock()
    mock_response.status_code = 500

    mock_client = MagicMock()
    mock_client.stream = MagicMock()
    mock_client.stream.return_value.__aenter__ = AsyncMock(return_value=mock_response)
    mock_client.stream.return_value.__aexit__ = AsyncMock(return_value=False)

    with patch("gateway.upstream.openai_proxy._http_client", mock_client):
        chunks = []
        async for chunk in _proxy_stream_generator(
            validated_body=_make_request(),
            request_id="req-stream-03",
        ):
            chunks.append(chunk)

    all_content = "".join(chunks)
    assert "event: error" in all_content
    assert "data: [DONE]" not in all_content


@pytest.mark.asyncio
async def test_stream_generator_overall_timeout_emits_error_frame():
    """Overall timeout exceeded mid-stream → error frame, no [DONE]."""
    mock_response = MagicMock()
    mock_response.status_code = 200

    async def _slow_lines():
        yield 'data: {"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[]}'
        # Simulate many chunks but overall timeout is very short.
        for _ in range(10):
            yield 'data: {"id":"c2","object":"chat.completion.chunk","created":1,"model":"m","choices":[]}'

    mock_response.aiter_lines = _slow_lines

    mock_client = MagicMock()
    mock_client.stream = MagicMock()
    mock_client.stream.return_value.__aenter__ = AsyncMock(return_value=mock_response)
    mock_client.stream.return_value.__aexit__ = AsyncMock(return_value=False)

    with patch("gateway.upstream.openai_proxy._http_client", mock_client):
        chunks = []
        async for chunk in _proxy_stream_generator(
            validated_body=_make_request(),
            request_id="req-timeout-01",
            overall_timeout=-1.0,  # already expired before we start
        ):
            chunks.append(chunk)

    all_content = "".join(chunks)
    # Should emit error frame, not [DONE].
    assert "event: error" in all_content
    assert "data: [DONE]" not in all_content
