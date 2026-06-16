"""Tests for upstream proxy (F-004, ADR-0006 Decision 8).

Covers:
- Non-stream: successful upstream response parsed to ChatCompletionResponse
- Upstream connect error → GatewayError("internal_error")
- Upstream timeout → GatewayError("internal_error")
- Upstream 5xx → GatewayError("internal_error")
- Upstream 4xx → GatewayError("internal_error") [Sentinel ↔ upstream issue]
- Response parsing error → GatewayError("internal_error")
- Upstream request uses re-serialized Pydantic model (no raw passthrough)
- Unknown fields are NOT forwarded (they were rejected by closed schema upstream)
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from gateway.exceptions import GatewayError
from gateway.models import CreateChatCompletionRequest
from gateway.upstream.openai_proxy import proxy_non_stream


def _make_validated_body(**overrides) -> CreateChatCompletionRequest:
    data = {
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "user", "content": "hello"}],
    }
    data.update(overrides)
    return CreateChatCompletionRequest(**data)


def _make_successful_upstream_response() -> dict:
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1700000000,
        "model": "gpt-3.5-turbo",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "Hello there!"},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": 5,
            "completion_tokens": 3,
            "total_tokens": 8,
        },
    }


# ---------------------------------------------------------------------------
# Non-stream proxy tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_non_stream_success_returns_completion(settings_env):
    """Successful upstream response is parsed and returned as ChatCompletionResponse."""
    upstream_data = _make_successful_upstream_response()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=upstream_data)

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=mock_response)

    with patch("gateway.upstream.openai_proxy._http_client", mock_client):
        completion, tokens_in, tokens_out = await proxy_non_stream(
            validated_body=_make_validated_body(),
            request_id="req-upstream-01",
        )

    assert completion.id == "chatcmpl-test"
    assert completion.object == "chat.completion"
    assert len(completion.choices) == 1
    assert completion.choices[0].message.content == "Hello there!"
    assert tokens_in == 5
    assert tokens_out == 3


@pytest.mark.asyncio
async def test_non_stream_upstream_connect_error_returns_500(settings_env):
    """Upstream connection refused → GatewayError("internal_error")."""
    mock_client = MagicMock()
    mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))

    with patch("gateway.upstream.openai_proxy._http_client", mock_client):
        with pytest.raises(GatewayError) as exc_info:
            await proxy_non_stream(
                validated_body=_make_validated_body(),
                request_id="req-upstream-02",
            )
    assert exc_info.value.error_code == "internal_error"
    assert exc_info.value.status_code == 500


@pytest.mark.asyncio
async def test_non_stream_upstream_timeout_returns_500(settings_env):
    """Upstream timeout → GatewayError("internal_error")."""
    mock_client = MagicMock()
    mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

    with patch("gateway.upstream.openai_proxy._http_client", mock_client):
        with pytest.raises(GatewayError) as exc_info:
            await proxy_non_stream(
                validated_body=_make_validated_body(),
                request_id="req-upstream-03",
            )
    assert exc_info.value.error_code == "internal_error"


@pytest.mark.asyncio
async def test_non_stream_upstream_5xx_returns_500(settings_env):
    """Upstream 5xx status → GatewayError("internal_error") — no 502/504 on wire."""
    mock_response = MagicMock()
    mock_response.status_code = 503

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=mock_response)

    with patch("gateway.upstream.openai_proxy._http_client", mock_client):
        with pytest.raises(GatewayError) as exc_info:
            await proxy_non_stream(
                validated_body=_make_validated_body(),
                request_id="req-upstream-04",
            )
    assert exc_info.value.error_code == "internal_error"
    assert exc_info.value.status_code == 500


@pytest.mark.asyncio
async def test_non_stream_upstream_4xx_returns_500(settings_env):
    """Upstream 4xx (Sentinel→upstream issue) → internal_error, not client error."""
    mock_response = MagicMock()
    mock_response.status_code = 401

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=mock_response)

    with patch("gateway.upstream.openai_proxy._http_client", mock_client):
        with pytest.raises(GatewayError) as exc_info:
            await proxy_non_stream(
                validated_body=_make_validated_body(),
                request_id="req-upstream-05",
            )
    assert exc_info.value.error_code == "internal_error"


@pytest.mark.asyncio
async def test_non_stream_parse_error_returns_500(settings_env):
    """Upstream returns non-parseable JSON → GatewayError("internal_error")."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(side_effect=ValueError("bad json"))

    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=mock_response)

    with patch("gateway.upstream.openai_proxy._http_client", mock_client):
        with pytest.raises(GatewayError) as exc_info:
            await proxy_non_stream(
                validated_body=_make_validated_body(),
                request_id="req-upstream-06",
            )
    assert exc_info.value.error_code == "internal_error"


@pytest.mark.asyncio
async def test_upstream_request_is_typed_reserialization(settings_env):
    """Only allowlisted fields are forwarded to upstream (no raw passthrough)."""
    upstream_data = _make_successful_upstream_response()

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json = MagicMock(return_value=upstream_data)

    captured_payload: dict = {}

    async def _capture_post(url, json=None, headers=None, timeout=None):
        captured_payload.update(json or {})
        return mock_response

    mock_client = MagicMock()
    mock_client.post = _capture_post

    # Make a validated body (closed schema already rejected unknown fields).
    validated = _make_validated_body(temperature=0.7, max_tokens=100)

    with patch("gateway.upstream.openai_proxy._http_client", mock_client):
        await proxy_non_stream(
            validated_body=validated,
            request_id="req-upstream-07",
        )

    # Verify only contract-allowlisted fields are in the upstream payload.
    allowed_fields = {"model", "messages", "stream", "n", "temperature", "top_p",
                      "max_tokens", "stop", "user"}
    for key in captured_payload:
        assert key in allowed_fields, f"Unexpected field forwarded to upstream: {key!r}"
    assert "unknown_extra_field" not in captured_payload
