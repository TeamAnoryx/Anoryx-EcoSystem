"""Upstream OpenAI-compatible proxy (ADR-0006 Decision 8).

Uses a single shared async httpx.AsyncClient with mandatory timeouts.

Upstream request is built by re-serializing the typed Pydantic model
(allowlisted fields ONLY, NO raw body passthrough — threat #7 upstream
injection defense). Unknown keys were rejected by the closed schema before
reaching here.

Upstream failure → contract surface (ADR-0006 Decision 8 reconciliation):
  The contract's public status list for /v1/chat/completions is exactly
  200, 400, 401, 403, 413, 429, 500 — no 502 or 504.
  All upstream connection errors, timeouts, and 5xx responses collapse to
  500 internal_error on the wire. The true cause is logged SERVER-SIDE
  (without request body or PII) and correlated by request_id.

Stream lifecycle (ADR-0006 Decision 7):
  - STREAM_TIMEOUT_SECONDS bounds the idle gap between chunks.
  - REQUEST_TIMEOUT_SECONDS bounds the overall request wall time.
  - On any mid-stream error: emit one terminal `event: error` SSE frame
    carrying the Error envelope, then close WITHOUT `data: [DONE]`.
  - Client disconnect cancels the upstream httpx stream.
  - concurrent-stream counter is managed by the caller via stream_slot().
"""

from __future__ import annotations

import json
import time
from typing import AsyncIterator

import httpx
import structlog

from gateway.exceptions import GatewayError
from gateway.models import ChatCompletionResponse, CreateChatCompletionRequest, ErrorResponse

log = structlog.get_logger(__name__)

# Module-level shared client — initialized once at app startup via lifespan.
_http_client: httpx.AsyncClient | None = None


def get_http_client() -> httpx.AsyncClient:
    """Return the shared async httpx client. Raises if not initialized."""
    if _http_client is None:
        raise RuntimeError(
            "HTTP client not initialized. Call init_http_client() during app startup."
        )
    return _http_client


async def init_http_client(
    base_url: str,
    request_timeout: float,
    stream_timeout: float,
) -> None:
    """Initialize the shared httpx.AsyncClient (called once in app lifespan)."""
    global _http_client
    if _http_client is not None:
        return
    # Timeouts: connect + pool share request_timeout; read uses stream_timeout
    # (idle gap between chunks for streams, overall read for non-stream).
    timeout = httpx.Timeout(
        connect=min(10.0, request_timeout),
        read=stream_timeout,
        write=request_timeout,
        pool=request_timeout,
    )
    _http_client = httpx.AsyncClient(
        base_url=base_url,
        timeout=timeout,
        follow_redirects=False,
    )
    log.info("http_client_initialized", base_url=base_url)


async def close_http_client() -> None:
    """Close the shared httpx.AsyncClient (called once in app lifespan teardown)."""
    global _http_client
    if _http_client is not None:
        await _http_client.aclose()
        _http_client = None
        log.info("http_client_closed")


def _build_upstream_request(
    validated_body: CreateChatCompletionRequest,
    upstream_api_key: str | None = None,
) -> dict:
    """Re-serialize the Pydantic model to a dict for the upstream request.

    ONLY allowlisted fields are included — no raw passthrough.
    This is the typed re-serialization that enforces threat #7 defense:
    unknown keys were already rejected by the closed schema; this step ensures
    no undeclared field can ride along to the upstream provider.
    """
    payload: dict = {
        "model": validated_body.model,
        "messages": [
            {k: v for k, v in msg.model_dump().items() if v is not None}
            for msg in validated_body.messages
        ],
        "stream": validated_body.stream,
        "n": validated_body.n,
    }
    # Optional fields — only include if set (not None).
    if validated_body.temperature is not None:
        payload["temperature"] = validated_body.temperature
    if validated_body.top_p is not None:
        payload["top_p"] = validated_body.top_p
    if validated_body.max_tokens is not None:
        payload["max_tokens"] = validated_body.max_tokens
    if validated_body.stop is not None:
        payload["stop"] = validated_body.stop
    if validated_body.user is not None:
        payload["user"] = validated_body.user

    return payload


def _build_headers(upstream_api_key: str | None) -> dict[str, str]:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if upstream_api_key:
        headers["Authorization"] = f"Bearer {upstream_api_key}"
    return headers


async def proxy_non_stream(
    validated_body: CreateChatCompletionRequest,
    request_id: str,
    upstream_api_key: str | None = None,
    overall_timeout: float = 60.0,
) -> tuple[ChatCompletionResponse, int, int]:
    """Send non-streaming request to upstream. Returns (response, tokens_in, tokens_out).

    Upstream 5xx / timeout / connect-refused → GatewayError("internal_error").
    The true cause is logged server-side; clients receive the generic 500 message.
    """
    client = get_http_client()
    payload = _build_upstream_request(validated_body)
    headers = _build_headers(upstream_api_key)

    try:
        resp = await client.post(
            "/v1/chat/completions",
            json=payload,
            headers=headers,
            timeout=overall_timeout,
        )
    except httpx.ConnectError:
        log.error("upstream_connect_error", request_id=request_id)
        raise GatewayError("internal_error")
    except httpx.TimeoutException:
        log.error("upstream_timeout", request_id=request_id)
        raise GatewayError("internal_error")
    except Exception:
        log.exception("upstream_unexpected_error", request_id=request_id)
        raise GatewayError("internal_error")

    if resp.status_code >= 500:
        log.error(
            "upstream_5xx",
            request_id=request_id,
            upstream_status=resp.status_code,
            # Never log resp.text — may contain PII / upstream secrets
        )
        raise GatewayError("internal_error")

    if resp.status_code != 200:
        # Upstream 4xx (bad request to upstream, auth failure, etc.) → internal_error
        # because the issue is between Sentinel and the upstream, not the client.
        log.error(
            "upstream_non_200",
            request_id=request_id,
            upstream_status=resp.status_code,
        )
        raise GatewayError("internal_error")

    try:
        data = resp.json()
        completion = ChatCompletionResponse(**data)
    except Exception:
        log.exception("upstream_response_parse_error", request_id=request_id)
        raise GatewayError("internal_error")

    tokens_in = 0
    tokens_out = 0
    if completion.usage:
        tokens_in = completion.usage.prompt_tokens
        tokens_out = completion.usage.completion_tokens

    return completion, tokens_in, tokens_out


async def proxy_stream(
    validated_body: CreateChatCompletionRequest,
    request_id: str,
    upstream_api_key: str | None = None,
    idle_timeout: float = 30.0,
    overall_timeout: float = 60.0,
) -> AsyncIterator[str]:
    """Stream SSE chunks from upstream to client.

    Yields raw SSE lines (strings) to be forwarded to the client.
    On any error: yields a single `event: error` frame (with Error envelope)
    and stops WITHOUT yielding `data: [DONE]`.

    This is an async generator. The caller must consume it inside stream_slot()
    to ensure the concurrent-stream counter is decremented on exit.

    Returns (via generator protocol) a tuple (tokens_in, tokens_out) via the
    StopIteration value — callers cannot easily receive it from an async generator,
    so we instead store accumulated counts in request.state or pass a callback.
    Since FastAPI / Starlette's StreamingResponse wraps the generator, we use
    a mutable container pattern: the generator writes to a provided dict.

    Yields string chunks that are raw SSE event lines.
    """
    return _proxy_stream_generator(
        validated_body=validated_body,
        request_id=request_id,
        upstream_api_key=upstream_api_key,
        idle_timeout=idle_timeout,
        overall_timeout=overall_timeout,
    )


async def _proxy_stream_generator(
    validated_body: CreateChatCompletionRequest,
    request_id: str,
    upstream_api_key: str | None = None,
    idle_timeout: float = 30.0,
    overall_timeout: float = 60.0,
) -> AsyncIterator[str]:
    """Inner async generator for streaming proxy."""
    import asyncio

    client = get_http_client()
    payload = _build_upstream_request(validated_body)
    headers = _build_headers(upstream_api_key)
    headers["Accept"] = "text/event-stream"

    overall_start = time.monotonic()

    def _make_error_frame(error_code: str, rid: str) -> str:
        from gateway.exceptions import ERROR_TABLE

        message, _ = ERROR_TABLE.get(error_code, ("An internal error occurred. The request was not processed.", 500))
        err = ErrorResponse(error_code=error_code, message=message, request_id=rid)  # type: ignore[arg-type]
        return f"event: error\ndata: {err.model_dump_json()}\n\n"

    try:
        async with client.stream(
            "POST",
            "/v1/chat/completions",
            json=payload,
            headers=headers,
        ) as resp:
            if resp.status_code >= 400:
                log.error(
                    "upstream_stream_error_status",
                    request_id=request_id,
                    upstream_status=resp.status_code,
                )
                yield _make_error_frame("internal_error", request_id)
                return

            async for line in resp.aiter_lines():
                if not line:
                    yield "\n"
                    continue

                # Check overall timeout BEFORE emitting each content chunk.
                elapsed = time.monotonic() - overall_start
                if elapsed > overall_timeout:
                    log.warning("upstream_stream_overall_timeout", request_id=request_id)
                    yield _make_error_frame("internal_error", request_id)
                    return

                yield line + "\n"

                if line.strip() == "data: [DONE]":
                    return

    except httpx.ConnectError:
        log.error("upstream_stream_connect_error", request_id=request_id)
        yield _make_error_frame("internal_error", request_id)
    except (httpx.TimeoutException, asyncio.TimeoutError):
        log.error("upstream_stream_timeout", request_id=request_id)
        yield _make_error_frame("internal_error", request_id)
    except Exception:
        log.exception("upstream_stream_unexpected_error", request_id=request_id)
        yield _make_error_frame("internal_error", request_id)
