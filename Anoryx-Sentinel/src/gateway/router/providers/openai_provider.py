"""OpenAI provider adapter — thin delegate (F-006, ADR-0008 §2.3).

The OpenAI wire shape IS the canonical shape: no translation. complete()
delegates to the existing proxy_non_stream(); stream() delegates to the existing
_proxy_stream_generator(). Neither openai_proxy.py function is modified — its
public behavior for the existing direct call path is untouched (ADR §12).

STATUS CLASSIFIER (ADR §2.3 / §12 / MEDIUM-1 remediation): openai_proxy.py
collapses ALL non-200 to GatewayError("internal_error") on the wire, but now
attaches the upstream HTTP status ADDITIVELY as `exc.upstream_status` (its public
behavior — error_code, 500 status, message — is unchanged). The adapter reads
that attribute and maps:
  - 401 / 403           -> kind="auth" (TERMINAL, never retried). A key/SigV4
                           rejection must NOT trigger provider-shopping or budget
                           burn (§6 "401/403 TERMINAL", threat #5).
  - 5xx / connect /
    timeout / absent     -> kind="transient" (retryable) — safe disposition for a
                           generic transport failure; a single OpenAI attempt that
                           fails still surfaces 500 with no fallback (parity).
  - 400 (other 4xx)      -> kind="transient". A content-policy 400 is NOT
                           distinguishable here because the body is intentionally
                           discarded server-side (threat #10), so we cannot mark it
                           content_policy without inventing a signal. Conservative
                           default keeps the prior behavior.

The adapter NEVER attaches upstream body text (threat #10) — GatewayError
already carries only the fixed ERROR_TABLE message, and we discard it; only the
numeric status (no PII) is consulted.
"""

from __future__ import annotations

from typing import AsyncIterator

from gateway.exceptions import GatewayError
from gateway.models import ChatCompletionResponse, CreateChatCompletionRequest
from gateway.router.context import RoutingContext
from gateway.router.exceptions import ProviderError
from gateway.upstream.openai_proxy import _proxy_stream_generator, proxy_non_stream


def _classify_gateway_error(exc: GatewayError) -> ProviderError:
    """Map a GatewayError from openai_proxy to a ProviderError kind (MEDIUM-1).

    Reads the ADDITIVE optional `upstream_status` attribute. 401/403 -> auth
    (terminal). Everything else (5xx, connect, timeout, other 4xx, or a missing
    attribute) -> transient (retryable). Never carries upstream body text.
    """
    status = getattr(exc, "upstream_status", None)
    if status in (401, 403):
        return ProviderError(kind="auth", status=status)
    return ProviderError(kind="transient", status=status)


class OpenAiAdapter:
    """Delegates to the existing single-upstream OpenAI proxy."""

    name = "openai"

    def __init__(self, stream_timeout: float) -> None:
        # OpenAI reuses the module-global httpx client built by init_http_client;
        # we only need the stream idle timeout for the stream delegate.
        self._stream_timeout = stream_timeout

    async def complete(
        self,
        validated_body: CreateChatCompletionRequest,
        ctx: RoutingContext,
    ) -> tuple[ChatCompletionResponse, int, int]:
        try:
            return await proxy_non_stream(
                validated_body=validated_body,
                request_id=ctx.request_id,
                upstream_api_key=None,  # Phase 0: no upstream key vaulting yet.
                overall_timeout=ctx.time_left(),
            )
        except GatewayError as exc:
            # openai_proxy.py already logged the true cause server-side without
            # body text. Classify by the additive upstream_status (MEDIUM-1):
            # 401/403 -> auth TERMINAL; everything else -> transient.
            raise _classify_gateway_error(exc) from None

    async def stream(
        self,
        validated_body: CreateChatCompletionRequest,
        ctx: RoutingContext,
    ) -> AsyncIterator[str]:
        # _proxy_stream_generator yields already-OpenAI-shape SSE lines and
        # handles its own mid-stream error framing (event: error, no [DONE]).
        # Connection-establishment failures inside it surface as an error frame
        # rather than a raise; the router's pre-first-byte fallback for OpenAI is
        # therefore limited (matching ADR-0006's streaming caveat in §6).
        async for line in _proxy_stream_generator(
            validated_body=validated_body,
            request_id=ctx.request_id,
            upstream_api_key=None,
            idle_timeout=self._stream_timeout,
            overall_timeout=ctx.time_left(),
        ):
            yield line
