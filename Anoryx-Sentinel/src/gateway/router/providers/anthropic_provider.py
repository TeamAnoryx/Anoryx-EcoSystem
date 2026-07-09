"""Anthropic provider adapter — translate (F-006, ADR-0008 §2.4).

Uses plain httpx against the Messages API (no `anthropic` SDK). Translates the
OpenAI CreateChatCompletionRequest -> Messages API request, and the Messages
response / typed SSE stream -> OpenAI shape, INSIDE the adapter before any bytes
leave it (threat #8). Maps ONLY the allow-listed request fields — no raw
passthrough (threat #12). Raises ProviderError on every failure; never attaches
upstream body text (threat #10).

Auth: x-api-key + anthropic-version: 2023-06-01. base_url is config-pinned
(SSRF defense, threat #9). max_tokens is REQUIRED by Anthropic — if the client
omitted it, the configured default is injected (§2.4).
"""

from __future__ import annotations

import json
import time
from typing import Any, AsyncIterator

import httpx

from gateway.models import ChatCompletionResponse, CreateChatCompletionRequest
from gateway.router.context import RoutingContext
from gateway.router.exceptions import ProviderError
from gateway.router.providers import _translate

_ANTHROPIC_VERSION = "2023-06-01"
_MESSAGES_PATH = "/v1/messages"

# F-007 (ADR-0010 §3): judge-only structured-output forcing via Anthropic tool-use.
# Additive — does NOT touch complete()/stream() or the user-traffic request shape.
_JUDGE_TOOL_NAME = "report_verdict"
_JUDGE_MAX_TOKENS = 256


def _classify_status(status: int) -> str:
    """Map an Anthropic HTTP status to a ProviderError kind (§2.2 / §6)."""
    if status == 429:
        return "rate_limited"
    if status in (401, 403):
        return "auth"
    if status >= 500:
        return "transient"
    # Other 4xx: treat as bad_request (malformed-for-provider / translation).
    # Content-policy is detected separately from the body stop_reason.
    return "bad_request"


def _build_messages_request(
    body: CreateChatCompletionRequest,
    default_max_tokens: int,
) -> dict[str, Any]:
    """Translate OpenAI request -> Anthropic Messages request (allow-list only).

    system messages are concatenated into the top-level `system` string;
    remaining user/assistant messages map 1:1. tool-role messages are not part
    of the F-006 surface and are dropped from the conversation (the closed
    request schema still permits role='tool' but Messages API has no 1:1 slot;
    they are folded into system context defensively).
    """
    system_parts: list[str] = []
    messages: list[dict[str, str]] = []
    for m in body.messages:
        if m.role == "system":
            system_parts.append(m.content)
        elif m.role in ("user", "assistant"):
            messages.append({"role": m.role, "content": m.content})
        else:  # "tool" — no Messages API 1:1 mapping in F-006; fold into system.
            system_parts.append(m.content)

    req: dict[str, Any] = {
        "model": body.model,
        "messages": messages,
        # Anthropic REQUIRES max_tokens; inject the config default if omitted.
        "max_tokens": body.max_tokens if body.max_tokens is not None else default_max_tokens,
        "stream": bool(body.stream),
    }
    if system_parts:
        req["system"] = "\n".join(system_parts)
    if body.temperature is not None:
        req["temperature"] = body.temperature
    if body.top_p is not None:
        req["top_p"] = body.top_p
    if body.stop is not None:
        req["stop_sequences"] = [body.stop] if isinstance(body.stop, str) else list(body.stop)
    return req


def _translate_response(
    data: dict[str, Any], model: str
) -> tuple[ChatCompletionResponse, int, int]:
    """Translate an Anthropic Messages response -> OpenAI shape + token counts."""
    try:
        content_blocks = data.get("content", []) or []
        text = "".join(
            b.get("text", "")
            for b in content_blocks
            if isinstance(b, dict) and b.get("type") == "text"
        )
        finish = _translate.map_finish_reason(data.get("stop_reason"))
        usage = data.get("usage", {}) or {}
        tokens_in = int(usage.get("input_tokens", 0) or 0)
        tokens_out = int(usage.get("output_tokens", 0) or 0)
        resp = _translate.build_response(
            model=model,
            content=text,
            finish_reason=finish,
            prompt_tokens=tokens_in,
            completion_tokens=tokens_out,
        )
        return resp, tokens_in, tokens_out
    except ProviderError:
        raise
    except Exception:
        raise ProviderError(kind="parse") from None


def _extract_tool_input(data: dict[str, Any], tool_name: str) -> dict[str, Any]:
    """Return the input dict of the forced tool_use block, or raise ProviderError(parse).

    Anthropic returns the forced verdict as a `tool_use` content block whose
    `input` is the structured JSON.  A missing block (the model declined to call
    the tool) is a structured-output failure → kind="parse" (the judge invoker maps
    this to classifier_invocation_failed, not degraded).
    """
    for block in data.get("content", []) or []:
        if (
            isinstance(block, dict)
            and block.get("type") == "tool_use"
            and block.get("name") == tool_name
        ):
            inp = block.get("input")
            if isinstance(inp, dict):
                return inp
    raise ProviderError(kind="parse")


class AnthropicAdapter:
    """Anthropic Messages API adapter over a dedicated httpx client."""

    name = "anthropic"

    def __init__(
        self,
        client: httpx.AsyncClient,
        api_key: str,
        default_max_tokens: int,
    ) -> None:
        self._client = client
        self._api_key = api_key
        self._default_max_tokens = default_max_tokens

    def set_api_key(self, api_key: str) -> None:
        """Swap the in-use API key (F-027 runtime rotation, ADR-0033).

        Takes effect on the NEXT call — _headers() reads self._api_key fresh
        per-request rather than caching a header dict at construction, so no
        in-flight request is affected and no client/adapter recreation is
        needed. Never logged (key material).
        """
        self._api_key = api_key

    def _headers(self) -> dict[str, str]:
        return {
            "x-api-key": self._api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "content-type": "application/json",
            "accept": "application/json",
        }

    async def complete(
        self,
        validated_body: CreateChatCompletionRequest,
        ctx: RoutingContext,
    ) -> tuple[ChatCompletionResponse, int, int]:
        # n>1 is unsupported by Messages API -> bad_request TERMINAL (§2.4).
        if validated_body.n > 1:
            raise ProviderError(kind="bad_request")

        payload = _build_messages_request(validated_body, self._default_max_tokens)
        payload["stream"] = False
        try:
            resp = await self._client.post(
                _MESSAGES_PATH,
                json=payload,
                headers=self._headers(),
                timeout=ctx.time_left(),
            )
        except (httpx.ConnectError, httpx.TimeoutException):
            raise ProviderError(kind="transient") from None
        except Exception:
            raise ProviderError(kind="transient") from None

        if resp.status_code != 200:
            # NEVER read resp.text onto the wire/logs (threat #10).
            raise ProviderError(kind=_classify_status(resp.status_code), status=resp.status_code)

        try:
            data = resp.json()
        except Exception:
            raise ProviderError(kind="parse") from None

        # Content-filter / safety refusal surfaced via stop_reason -> TERMINAL.
        if data.get("stop_reason") in ("refusal", "safety"):
            raise ProviderError(kind="content_policy", status=resp.status_code)

        return _translate_response(data, validated_body.model)

    async def stream(
        self,
        validated_body: CreateChatCompletionRequest,
        ctx: RoutingContext,
    ) -> AsyncIterator[str]:
        if validated_body.n > 1:
            raise ProviderError(kind="bad_request")

        payload = _build_messages_request(validated_body, self._default_max_tokens)
        payload["stream"] = True

        created = int(time.time())
        chunk_id = _translate.synth_id()
        model = validated_body.model
        role_sent = False
        finish_reason = "stop"

        try:
            async with self._client.stream(
                "POST",
                _MESSAGES_PATH,
                json=payload,
                headers={**self._headers(), "accept": "text/event-stream"},
                timeout=ctx.time_left(),
            ) as resp:
                if resp.status_code != 200:
                    # Pre-first-byte failure -> raise so the router can fall back.
                    raise ProviderError(
                        kind=_classify_status(resp.status_code), status=resp.status_code
                    )

                async for raw_line in resp.aiter_lines():
                    line = raw_line.strip()
                    if not line or not line.startswith("data:"):
                        continue
                    data_str = line[len("data:") :].strip()
                    if not data_str:
                        continue
                    try:
                        event = json.loads(data_str)
                    except json.JSONDecodeError:
                        continue
                    etype = event.get("type")

                    if etype == "message_start" and not role_sent:
                        role_sent = True
                        yield _translate.chunk_line(
                            chunk_id=chunk_id, model=model, created=created, role="assistant"
                        )
                    elif etype == "content_block_delta":
                        delta = event.get("delta", {}) or {}
                        text = delta.get("text")
                        if text:
                            if not role_sent:
                                role_sent = True
                                yield _translate.chunk_line(
                                    chunk_id=chunk_id,
                                    model=model,
                                    created=created,
                                    role="assistant",
                                )
                            yield _translate.chunk_line(
                                chunk_id=chunk_id, model=model, created=created, content=text
                            )
                    elif etype == "message_delta":
                        sr = (event.get("delta", {}) or {}).get("stop_reason")
                        if sr:
                            finish_reason = _translate.map_finish_reason(sr)
                    elif etype == "message_stop":
                        break
        except ProviderError:
            raise
        except (httpx.ConnectError, httpx.TimeoutException):
            raise ProviderError(kind="transient") from None
        except Exception:
            raise ProviderError(kind="transient") from None

        # Terminal finish chunk + [DONE], OpenAI framing.
        yield _translate.chunk_line(
            chunk_id=chunk_id, model=model, created=created, finish_reason=finish_reason
        )
        yield _translate.DONE_LINE

    async def classify_structured(
        self,
        *,
        system: str,
        user: str,
        schema: dict[str, Any],
        model: str,
        ctx: RoutingContext,
    ) -> tuple[dict[str, Any], int, int]:
        """F-007 judge call: forced structured verdict via Anthropic tool-use (R6).

        Additive judge-only path — does NOT modify complete()/stream(). Reuses the
        config-pinned client (threat #9) and the RoutingContext budget. Returns
        (verdict_dict, tokens_in, tokens_out). Raises ProviderError(kind="parse")
        when no structured tool_use block is present (→ invocation_failed), or
        kind="transient"/status on transport / HTTP failure (→ degraded).
        """
        payload: dict[str, Any] = {
            "model": model,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "max_tokens": _JUDGE_MAX_TOKENS,
            "tools": [
                {
                    "name": _JUDGE_TOOL_NAME,
                    "description": "Report the injection-classification verdict.",
                    "input_schema": schema,
                }
            ],
            "tool_choice": {"type": "tool", "name": _JUDGE_TOOL_NAME},
        }
        try:
            resp = await self._client.post(
                _MESSAGES_PATH,
                json=payload,
                headers=self._headers(),
                timeout=ctx.time_left(),
            )
        except (httpx.ConnectError, httpx.TimeoutException):
            raise ProviderError(kind="transient") from None
        except Exception:
            raise ProviderError(kind="transient") from None

        if resp.status_code != 200:
            raise ProviderError(kind=_classify_status(resp.status_code), status=resp.status_code)

        try:
            data = resp.json()
        except Exception:
            raise ProviderError(kind="parse") from None

        parsed = _extract_tool_input(data, _JUDGE_TOOL_NAME)
        usage = data.get("usage", {}) or {}
        return (
            parsed,
            int(usage.get("input_tokens", 0) or 0),
            int(usage.get("output_tokens", 0) or 0),
        )
