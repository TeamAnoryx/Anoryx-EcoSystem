"""POST /v1/chat/completions route handler (ADR-0006, F-004, F-005).

This is the innermost handler (pipeline step 8). By the time a request reaches
here, steps 2–7 have already run:
  2. Body-size / edge guard (RequestValidationMiddleware)
  3. Header presence / format gate (TenantContextMiddleware)
  4. Auth (AuthMiddleware — virtual_key_row on request.state)
  5. ID cross-check + tenant context (resolve_tenant_context, called here)
  6. Rate limit (check_rate_limit, called here after context is resolved)
  7. Request-body validation (Pydantic model on the route)

AUDIT COVERAGE (honest scope — HIGH-3 / LOW-4):
  - NON-STREAM: emit_terminal_record() is called in all non-streaming paths —
    success, upstream failure, validation failure, etc. (ADR-0006 Decision 3).
    If the audit append fails, the response is forced to 500 internal_error.
    After successful emit we set request.state.audit_emitted = True so the
    outermost TerminalAuditMiddleware skips double-emission.
  - STREAM: 200 headers are committed before the generator runs. Audit is
    emitted in the generator's finally-block. If that emit fails, it is logged
    at ERROR level out-of-band — the committed 200 cannot be changed to 500.
    This is an inherent SSE constraint. See ADR-0006 Decision 3 amendment.

F-005 INSPECTION HOOKS (ADR-0007):
  - PreRequestHooks run AFTER Step 7 body validation, BEFORE upstream proxy.
    Hook order (D1): SecretInbound → Injection → PII.
  - PostResponseHooks (non-stream): run AFTER proxy_non_stream, BEFORE JSONResponse.
    Hook order (D1): SecretOutbound.
  - PostResponseHooks (stream): applied per-chunk via bounded 8 KiB sliding window
    inside _generate(); a finding stops emission and sends SSEErrorEvent.
  - On HookBlockedError → 403 policy_blocked (or 500 for HookFailSafeError).
  - HookRegistry is DI-injectable (tests stub it via build_app_with_hooks()).
    Default registry is built from OrchestrationSettings if none is injected.

MED-3: Uses request.state.request_id (set by TerminalAuditMiddleware, the
outermost layer) instead of generating a new ID here. All middleware layers
and the route handler share the ONE canonical request_id.

The request body is read from request.state.raw_body (set by
RequestValidationMiddleware after the 1 MiB capped read).
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

# F-016: MAX_TOTAL_BYTES cap for the stream accumulation buffer.
# Imported lazily so missing optional does not prevent the module from loading.
try:
    from code_scan.extractor import MAX_TOTAL_BYTES as _CODE_SCAN_MAX_TOTAL_BYTES
except ImportError:
    _CODE_SCAN_MAX_TOTAL_BYTES = 524_288  # mirror the constant as a safe default

import structlog
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import ValidationError

from gateway.config import get_settings
from gateway.context import TenantContext, current_egress_context
from gateway.exceptions import ERROR_TABLE, GatewayError
from gateway.middleware.audit import emit_terminal_record
from gateway.middleware.rate_limit import check_rate_limit, stream_slot
from gateway.middleware.tenant_context import resolve_tenant_context
from gateway.models import (
    CreateChatCompletionRequest,
    ErrorResponse,
)
from gateway.observability.metrics import observe_request_duration, record_request
from gateway.router import cost as _cost
from gateway.router.registry import ProviderRegistry
from gateway.router.selection import StreamRouteResult, route_non_stream, route_stream
from gateway.upstream.openai_proxy import (
    _proxy_stream_generator,  # noqa: F401 — retained for compatibility/tests
    proxy_non_stream,  # noqa: F401 — retained for compatibility/tests
)
from policy.enforcement import BudgetExceeded, evaluate_budget_against

log = structlog.get_logger(__name__)

router = APIRouter()


def _redact_in_place(node: Any, redact_fn) -> Any:
    """Recursively redact secrets from a parsed JSON structure.

    Applies *redact_fn* (a pure str->str function) to every string leaf so
    that structural characters (`"`, `}`, `]`, etc.) are never part of the
    span that gets replaced.  This avoids the corrupted-JSON bug that occurs
    when redaction runs on a serialized JSON string and the entropy tokenizer
    bleeds into adjacent structural chars.

    Returns a new node (immutable traversal — original is not mutated).
    """
    if isinstance(node, str):
        return redact_fn(node)
    if isinstance(node, list):
        return [_redact_in_place(item, redact_fn) for item in node]
    if isinstance(node, tuple):
        return tuple(_redact_in_place(item, redact_fn) for item in node)
    if isinstance(node, dict):
        return {
            (redact_fn(k) if isinstance(k, str) else k): _redact_in_place(v, redact_fn)
            for k, v in node.items()
        }
    return node


_RATE_LIMIT_HEADERS_KEYS = ("x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset")

# ---------------------------------------------------------------------------
# F-005: lazy-import HookRegistry to keep F-004 importable without orchestration deps.
# ---------------------------------------------------------------------------

try:
    from orchestration.config import get_orchestration_settings
    from orchestration.detectors.secret_detector import redact as _secret_redact
    from orchestration.exceptions import HookBlockedError, HookFailSafeError
    from orchestration.registry import HookRegistry

    _HOOKS_AVAILABLE = True
except ImportError:
    _HOOKS_AVAILABLE = False
    HookRegistry = None  # type: ignore[assignment,misc]
    HookBlockedError = None  # type: ignore[assignment,misc]
    HookFailSafeError = None  # type: ignore[assignment,misc]
    get_orchestration_settings = None  # type: ignore[assignment,misc]
    _secret_redact = None  # type: ignore[assignment,misc]


def _get_default_registry():
    """Return the default HookRegistry, or None when hooks are not installed.

    Returns None ONLY when the orchestration package is unavailable (a
    deliberate deployment without F-005). A build *failure* (misconfiguration,
    missing model, etc.) is NOT swallowed — it propagates so the caller can
    fail-safe BLOCK the request (ADR-0007 D3: inspection failure → block, never
    silently pass uninspected traffic upstream).
    """
    if not _HOOKS_AVAILABLE:
        return None
    from orchestration.registry import build_default_registry

    return build_default_registry()


def _error_response(
    error_code: str,
    request_id: str,
    *,
    retry_after: int | None = None,
) -> JSONResponse:
    """Build a contract-conformant JSON error response.

    message is looked up from ERROR_TABLE — never derived from request content.
    request_id is echoed in both the X-Request-Id header and the body.
    """
    message, status = ERROR_TABLE[error_code]
    body = ErrorResponse(
        error_code=error_code,  # type: ignore[arg-type]
        message=message,
        request_id=request_id,
    )
    headers = {"X-Request-Id": request_id}
    if retry_after is not None:
        headers["Retry-After"] = str(retry_after)
    return JSONResponse(
        content=body.model_dump(),
        status_code=status,
        headers=headers,
    )


def _success_headers(
    request_id: str,
    rl_limit: int,
    rl_remaining: int,
    rl_reset: int,
) -> dict[str, str]:
    return {
        "X-Request-Id": request_id,
        "X-RateLimit-Limit": str(rl_limit),
        "X-RateLimit-Remaining": str(rl_remaining),
        "X-RateLimit-Reset": str(rl_reset),
    }


def _make_request_id() -> str:
    """Generate a request_id conforming to events.schema.json pattern ^[A-Za-z0-9._-]{1,64}$.

    Used only as a fallback if request.state.request_id was not set by the
    outermost middleware (e.g. in certain test configurations). Prefer
    request.state.request_id in all normal paths (MED-3).
    """
    return "req-" + uuid.uuid4().hex[:32]


@router.post("/v1/chat/completions", response_model=None)
async def create_chat_completion(
    request: Request,
    hook_registry=None,  # DI seam: tests inject a stub; production uses default.
) -> JSONResponse | StreamingResponse:
    """POST /v1/chat/completions — full pipeline handler (non-stream + stream).

    Pipeline steps executed here (steps 5–8):
      5. ID cross-check + tenant context resolution
      6. Rate limit (post-auth, keyed on resolved key_id + tenant_id)
      7. Body validation (Pydantic, closed schema)
      7b. F-005 PreRequestHooks (after body validation, before upstream)
      8. Upstream proxy (typed re-serialization, no raw passthrough)
      8b. F-005 PostResponseHooks (after upstream, before flush)

    Audit emitted on every terminal outcome for non-stream requests (step 1 /
    Decision 3). Stream audit is emitted in the generator's finally-block;
    see module docstring for the honest scope of the audit guarantee.
    """
    settings = get_settings()
    start_time = time.monotonic()

    # MED-3: use the ONE canonical request_id set by TerminalAuditMiddleware.
    request_id: str = getattr(request.state, "request_id", None) or _make_request_id()

    # These will be populated progressively; used by the finally-block emit.
    tenant_context: TenantContext | None = None
    model: str = ""
    tokens_in: int = 0
    tokens_out: int = 0
    rl_limit: int = settings.rate_limit_rpm
    rl_remaining: int = settings.rate_limit_rpm
    rl_reset: int = 0

    try:
        # Resolve the hook registry inside the try so a build FAILURE fails safe
        # (ADR-0007 D3): a misconfigured / unbuildable inspection layer BLOCKS the
        # request rather than silently forwarding it upstream uninspected. A plain
        # None return (hooks not installed) remains a deliberate pass-through.
        if hook_registry is None:
            try:
                hook_registry = _get_default_registry()
            except Exception:
                log.error("orchestration.registry.build_failed")
                raise GatewayError("internal_error") from None

        # --- Step 5: ID cross-check + tenant context resolution ---
        # F-007: clear any prior egress binding BEFORE tenant resolution so a request
        # that fails before bind_egress_context (e.g. 401/403/rate-limit) can never
        # inherit a stale binding (defensive — the contextvar is task-local anyway).
        current_egress_context.set(None)
        tenant_context = resolve_tenant_context(request)

        # F-007 (ADR-0010 §5): bind the per-request egress context so the outbound
        # httpx hook can flag disallowed-provider egress. Best-effort — the monitor
        # is defense-in-depth and must NEVER block the request on a bind failure.
        try:
            from gateway.middleware.egress_monitor import bind_egress_context

            await bind_egress_context(tenant_context, request_id)
        except Exception:
            log.error("egress_context_bind_failed", request_id=request_id)

        # --- Step 6: Rate limit (keyed on resolved IDs, never IP) ---
        # HIGH-2: pass team_id so the D3 team tier is active in production.
        # TenantContext.team_id is the server-resolved team UUID from the
        # virtual_api_keys row — never a client-supplied value.
        # LOW-2: pass request_id for real attribution in degraded-event payloads.
        is_stream_request = _peek_stream_flag(request)
        rl_limit, rl_remaining, rl_reset = await check_rate_limit(
            virtual_key_id=tenant_context.virtual_key_id,
            tenant_id=tenant_context.tenant_id,
            is_stream=is_stream_request,
            team_id=tenant_context.team_id,
            request_id=request_id,
        )

        # --- Step 7: Body validation ---
        raw_body = getattr(request.state, "raw_body", b"")
        if not raw_body:
            raise GatewayError("invalid_request")

        try:
            body_dict = json.loads(raw_body)
        except (json.JSONDecodeError, ValueError):
            raise GatewayError("invalid_request") from None

        try:
            validated = CreateChatCompletionRequest(**body_dict)
        except (ValidationError, TypeError):
            raise GatewayError("invalid_request") from None

        model = validated.model
        # Store on state so TerminalAuditMiddleware can include it if needed.
        request.state.audit_model = model

        # Enforce MAX_TOKENS_PER_REQUEST cap (threat #4, ADR-0006 step 7).
        if (
            validated.max_tokens is not None
            and validated.max_tokens > settings.max_tokens_per_request
        ):
            raise GatewayError("invalid_request")

        # F-007: resolve the provider registry up-front so the injection detector's
        # LLM-as-judge step can route through the F-006 provider layer (R5). Resolved
        # once here and reused by the Step 8 router dispatch below.
        provider_registry = _get_provider_registry(request, settings)

        # --- Step 7b: F-005 PreRequestHooks (after body validation, before proxy) ---
        # Build HookContext and run the pre-request chain (ADR-0007 D6 integration).
        hook_context = None
        forwarded_content: str | None = None

        if hook_registry is not None and _HOOKS_AVAILABLE:
            # get_orchestration_settings is hoisted to module scope under the
            # _HOOKS_AVAILABLE try/except (L3); build_hook_context stays local.
            from orchestration.context import build_hook_context

            orch_settings = get_orchestration_settings()
            hook_context = build_hook_context(
                tenant_context=tenant_context,
                request_id=request_id,
                validated_messages=validated.messages,
                phase="pre_request",
                events_per_detector_cap=orch_settings.events_per_detector_cap,
                provider_registry=provider_registry,  # F-007: judge routes via F-006
                gateway_settings=settings,
            )

            # Snapshot of user content for forwarding (may be mutated by PII masking).
            user_content_snapshot = hook_context.original_user_content

            try:
                forwarded_content = await hook_registry.run_pre_request(
                    user_content_snapshot, hook_context
                )
            except HookFailSafeError:
                raise GatewayError("internal_error") from None
            except HookBlockedError:
                raise GatewayError("policy_blocked") from None

            # If PII masking mutated the content, apply it back to validated messages.
            if forwarded_content is not None and forwarded_content != user_content_snapshot:
                validated = _apply_masked_user_content(validated, forwarded_content)

        # --- Step 8: Upstream dispatch via the F-006 multi-provider router ---
        # The router wraps BOTH call sites. It returns a TRANSLATED OpenAI-shape
        # response (non-stream) / OpenAI-shape SSE lines (stream) so the F-005
        # post-hook below inspects translated bytes (threat #8) and the client
        # keeps the unchanged OpenAI surface. Behavior is identical to today when
        # the tenant resolves to OpenAI with no fallback.
        upstream_api_key: str | None = None  # Phase 0: no upstream key vaulting yet
        # provider_registry was resolved before the pre-request hooks (F-007) and is
        # reused here for the Step 8 router dispatch.

        if validated.stream:
            # Streaming path (ADR-0006 Decision 7).
            # Note: stream_slot() now only DECREMENTS (MED-1 fix: check_rate_limit
            # already incremented the counter atomically at admission).
            return await _handle_stream(
                validated=validated,
                request_id=request_id,
                tenant_context=tenant_context,
                start_time=start_time,
                rl_limit=rl_limit,
                rl_remaining=rl_remaining,
                rl_reset=rl_reset,
                upstream_api_key=upstream_api_key,
                settings=settings,
                hook_registry=hook_registry,
                hook_context=hook_context,
                provider_registry=provider_registry,
            )
        else:
            # Non-streaming path — router returns a TRANSLATED OpenAI-shape resp.
            completion, tokens_in, tokens_out = await route_non_stream(
                validated_body=validated,
                request_id=request_id,
                tenant_context=tenant_context,
                registry=provider_registry,
                settings=settings,
            )

            # --- Step 8b: F-005 PostResponseHooks (non-stream, before Response) ---
            # F-005 REWORK (SEC-ENT truncation fix):
            #   Detection runs through the existing post-response hook so the
            #   event + defer_emit semantics are fully preserved (HIGH-B).
            #   REDACTION moves to parsed-structure traversal (_redact_in_place)
            #   so structural JSON chars ('"', '}', ']', etc.) are never part of
            #   the replacement span — eliminating the SEC-ENT truncation bug that
            #   corrupted the serialized JSON and caused 500 on every maskable
            #   non-stream response.
            #
            # HIGH-A (preserved): secrets in ANY field (id, tool_calls, etc.) are
            # redacted because _redact_in_place walks the full parsed dict.
            # HIGH-B (preserved): the secret_leaked event is deferred
            # (defer_emit=True in SecretOutboundHook) and emitted here ONLY after
            # json.dumps of the redacted parsed dict succeeds.  If json.dumps
            # raises (non-serializable), we raise internal_error and do NOT emit.
            response_text: str | None = None
            post_hook_context = None
            secret_found: bool = False
            if hook_registry is not None and hook_context is not None and _HOOKS_AVAILABLE:
                # Pass the serialized string to the hook so detection + deferred
                # event storage work exactly as before.
                _completion_dict = completion.model_dump()
                response_text = json.dumps(_completion_dict)
                post_hook_context = _make_post_context(hook_context, is_stream=False)
                # F-016: code-scan must see the RAW assistant message text (real
                # newlines), NOT the JSON-serialized envelope.  json.dumps escapes
                # newlines, so fenced ``` code blocks in response_text would never
                # be extracted (the markdown fence needs real newlines).  Build the
                # scan text from the assistant message content(s) instead.  The
                # outbound-secret hook still scans the full serialized envelope.
                _code_scan_text = "\n\n".join(
                    str((choice.get("message") or {}).get("content") or "")
                    for choice in (_completion_dict.get("choices") or [])
                )
                try:
                    await hook_registry.run_post_response(response_text, post_hook_context)
                    # F-016 (ADR-0019 §4, Vector 10): run code-scan on the assistant
                    # message text AFTER the outbound-secret hook, BEFORE the
                    # JSONResponse is built.  Called unconditionally — a no-op
                    # when code-scan is disabled (default-OFF) or the optional
                    # extra is not installed (registry._code_scan_detector is None).
                    # On BLOCK → HookBlockedError(error_code="policy_blocked") is
                    # raised by run_code_scan; the existing except branch below
                    # converts it to GatewayError("policy_blocked") → 403.
                    # On scanner crash → HookFailSafeError → 500 internal_error.
                    await hook_registry.run_code_scan(_code_scan_text, post_hook_context)
                except HookFailSafeError:
                    raise GatewayError("internal_error") from None
                except HookBlockedError:
                    raise GatewayError("policy_blocked") from None

                # A secret was found iff the hook stored a deferred event.
                secret_found = getattr(post_hook_context, "_deferred_event", None) is not None

            # Determine the body to send to the client.
            if secret_found and post_hook_context is not None:
                # Masking occurred — redact on the PARSED structure so no
                # structural JSON chars are consumed by the replacement.
                _orch = get_orchestration_settings()
                _min_len = _orch.min_token_length_for_entropy
                _threshold = _orch.entropy_threshold

                def _redact_fn(s: str) -> str:
                    return _secret_redact(
                        s,
                        min_token_len=_min_len,
                        entropy_threshold=_threshold,
                    )

                parsed = completion.model_dump()
                redacted_parsed = _redact_in_place(parsed, _redact_fn)

                # json.dumps of a dict round-tripped through model_dump() is
                # always valid JSON; we still guard against non-serializable
                # objects (e.g. custom fields injected by a future hook) so the
                # fail-safe path remains correct.
                try:
                    redacted_text = json.dumps(redacted_parsed)
                except (TypeError, ValueError):
                    # Non-serializable structure — fail safe to 500 and do NOT
                    # emit the secret_leaked event (HIGH-B fail-safe).
                    raise GatewayError("internal_error") from None

                # Redacted body is valid JSON — emit deferred secret_leaked event.
                deferred = getattr(post_hook_context, "_deferred_event", None)
                if deferred is not None:
                    deferred_ev, deferred_slug = deferred
                    await post_hook_context.emit(deferred_ev, detector_slug=deferred_slug)

                # Audit (success path) — must happen before returning.
                await emit_terminal_record(
                    request_id=request_id,
                    tenant_context=tenant_context,
                    model=model,
                    tokens_in=tokens_in,
                    tokens_out=tokens_out,
                    start_time=start_time,
                )
                request.state.audit_emitted = True

                # F-009: record metrics (pure addition, no semantic change — R2).
                # Non-stream path has no StreamRouteResult; provider is 'none' until
                # STEP 3b wires the resolved provider through the response context.
                record_request("none", "2xx")
                observe_request_duration(
                    "/v1/chat/completions",
                    "none",
                    time.monotonic() - start_time,
                )

                headers = _success_headers(request_id, rl_limit, rl_remaining, rl_reset)
                return Response(
                    content=redacted_text,
                    media_type="application/json",
                    status_code=200,
                    headers=headers,
                )

            # No masking — standard success path.
            await emit_terminal_record(
                request_id=request_id,
                tenant_context=tenant_context,
                model=model,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                start_time=start_time,
            )
            # Signal TerminalAuditMiddleware to skip double-emission.
            request.state.audit_emitted = True

            # F-009: record metrics (pure addition, no semantic change — R2).
            # Non-stream path has no StreamRouteResult; provider is 'none' until
            # STEP 3b wires the resolved provider through the response context.
            record_request("none", "2xx")
            observe_request_duration(
                "/v1/chat/completions",
                "none",
                time.monotonic() - start_time,
            )

            headers = _success_headers(request_id, rl_limit, rl_remaining, rl_reset)
            return JSONResponse(
                content=completion.model_dump(),
                status_code=200,
                headers=headers,
            )

    except GatewayError as _orig_exc:
        # Audit on every non-stream rejection (ADR-0006 audit coverage).
        # Keep a mutable reference so inner handlers can upgrade to internal_error.
        active_exc: GatewayError = _orig_exc
        try:
            await emit_terminal_record(
                request_id=request_id,
                tenant_context=tenant_context,
                model=model,
                tokens_in=0,
                tokens_out=0,
                start_time=start_time,
            )
            # Signal TerminalAuditMiddleware to skip double-emission.
            request.state.audit_emitted = True
        except GatewayError:
            # Audit-emit itself failed → already GatewayError("internal_error").
            # Surface the audit-failure 500 (overrides the original error code).
            active_exc = GatewayError("internal_error")
            request.state.audit_emitted = True
        except Exception:
            active_exc = GatewayError("internal_error")
            request.state.audit_emitted = True

        # F-009: record error metrics (pure addition — R2).
        _, _status_code = ERROR_TABLE.get(active_exc.error_code, ("", 500))
        _err_class = f"{_status_code // 100}xx"
        record_request("none", _err_class)
        observe_request_duration(
            "/v1/chat/completions",
            "none",
            time.monotonic() - start_time,
        )

        resp = _error_response(
            active_exc.error_code, request_id, retry_after=active_exc.retry_after
        )
        resp.headers["X-RateLimit-Limit"] = str(rl_limit)
        resp.headers["X-RateLimit-Remaining"] = str(rl_remaining)
        resp.headers["X-RateLimit-Reset"] = str(rl_reset)
        return resp


async def _handle_stream(
    *,
    validated: CreateChatCompletionRequest,
    request_id: str,
    tenant_context: TenantContext,
    start_time: float,
    rl_limit: int,
    rl_remaining: int,
    rl_reset: int,
    upstream_api_key: str | None,
    settings,
    hook_registry=None,
    hook_context=None,
    provider_registry: ProviderRegistry | None = None,
) -> StreamingResponse:
    """Build and return a StreamingResponse for stream: true requests.

    The concurrent-stream slot was already reserved (incremented) atomically
    by check_rate_limit() under the lock (MED-1 fix). stream_slot() here only
    DECREMENTS on exit — guaranteed on close/complete/error/disconnect.

    F-005 PostResponseHooks: applied per-chunk via a bounded 8 KiB sliding
    window (ADR-0007 D2).  On a secret finding → stop content, emit SSEErrorEvent
    (error_code: policy_blocked), close WITHOUT [DONE].

    Partial-stream audit is emitted in the generator's finally block.

    HIGH-3 / honest scope: audit failure in the finally-block logs at ERROR
    level out-of-band. The committed 200 response cannot be retroactively
    changed to 500 once streaming headers are sent. This is an inherent SSE
    constraint documented in ADR-0006 Decision 3 (amended).
    """
    # Token counters for partial-stream audit.
    token_state: dict = {"tokens_in": 0, "tokens_out": 0}

    # Resolve stream inspect buffer size.
    stream_buf_bytes = 8_192
    if _HOOKS_AVAILABLE and hook_registry is not None:
        try:
            from orchestration.config import get_orchestration_settings

            stream_buf_bytes = get_orchestration_settings().stream_inspect_buffer_bytes
        except Exception:
            pass

    # Build the post-response context for streaming phase.
    # FIX-1: mark is_stream=True so SecretOutboundHook returns block (not mask)
    # when a secret is found in a stream chunk — stopping the stream immediately
    # so no raw secret reaches the client.
    post_hook_ctx = None
    if hook_context is not None:
        post_hook_ctx = _make_post_context(hook_context, is_stream=True)

    # HIGH-1: holder the router populates with the COMMITTED (provider, model)
    # and the tenant cost_ceiling_cents once the first byte is established. The
    # chunk loop uses these to enforce the §7.4 stream-time cost ceiling on the
    # accumulating output tokens (the pre-request check alone cannot catch a
    # stream that overruns its estimate at generation time — threat #3).
    route_result = StreamRouteResult()

    # tokens_in proxy is stable for the whole stream (prompt is fixed). Compute
    # once so the running cost estimate has both sides of the ledger.
    prompt_words = sum(len(m.content.split()) for m in validated.messages)
    token_state["tokens_in"] = prompt_words

    async def _generate():
        """Async generator: upstream stream with F-005 windowed inspection + audit."""
        # MED-1: stream_slot() only DECREMENTS now. Counter was already incremented
        # by check_rate_limit() at admission time.
        async with stream_slot(tenant_context.tenant_id):
            carried_tail: str = ""
            stream_blocked = False
            # F-016 (ADR-0019 §4, Vector 11): accumulate the full response text
            # for the post-completion code-scan call.  Hard-capped at
            # MAX_TOTAL_BYTES (512 KiB) — the extractor/scanner handle oversize
            # inputs honestly; we stop appending beyond the cap so memory is
            # bounded even for very long streams.
            _scan_buf: str = ""
            _scan_buf_bytes: int = 0

            try:
                # F-006: the router yields already-TRANSLATED OpenAI-shape SSE
                # lines, so the F-005 8 KiB window below operates on the same
                # bytes it does for the OpenAI path (threat #8). All fallback /
                # terminal decisions happen inside route_stream before the first
                # byte (ADR-0008 §6 streaming caveat).
                _registry = provider_registry or _get_provider_registry(None, settings)
                async for chunk in route_stream(
                    validated_body=validated,
                    request_id=request_id,
                    tenant_context=tenant_context,
                    registry=_registry,
                    settings=settings,
                    result=route_result,
                ):
                    # Accumulate output tokens from content chunks.
                    if chunk.startswith("data: ") and not chunk.startswith("data: [DONE]"):
                        raw = chunk[6:].strip()
                        if raw and raw != "[DONE]":
                            try:
                                parsed = json.loads(raw)
                                choices = parsed.get("choices", [])
                                for c in choices:
                                    content = c.get("delta", {}).get("content") or ""
                                    token_state["tokens_out"] += len(content.split())
                            except (json.JSONDecodeError, KeyError, AttributeError):
                                pass

                    # HIGH-1 (threat #3, ADR §7.4): stream-time cost ceiling.
                    # Once the router has committed a provider+model and the
                    # tenant has a ceiling, recompute a running client-side cost
                    # ESTIMATE from accumulated tokens. On breach: emit the
                    # policy_blocked SSE error frame, a best-effort cost_blocked
                    # routing_decision audit event, and close WITHOUT [DONE] —
                    # mirroring the F-005 streaming-block fail-safe shape.
                    if (
                        not stream_blocked
                        and route_result.cost_ceiling_cents is not None
                        and route_result.resolved_provider is not None
                        and route_result.resolved_model is not None
                    ):
                        running_estimate = _cost.estimate_from_tokens(
                            route_result.resolved_provider,
                            route_result.resolved_model,
                            token_state["tokens_in"],
                            token_state["tokens_out"],
                        )
                        if running_estimate > route_result.cost_ceiling_cents:
                            stream_blocked = True
                            error_msg, _ = ERROR_TABLE["policy_blocked"]
                            yield _build_sse_error_event(
                                error_code="policy_blocked",
                                message=error_msg,
                                request_id=request_id,
                            )
                            # Best-effort cost_blocked audit (observability only;
                            # never converts the outcome — swallowed on failure).
                            try:
                                from gateway.middleware.audit import emit_routing_decision

                                await emit_routing_decision(
                                    request_id=request_id,
                                    tenant_context=tenant_context,
                                    selected_provider=route_result.resolved_provider,
                                    routing_reason="cost-routing",
                                    outcome="cost_blocked",
                                    action_taken="blocked",
                                    attempt_index=0,
                                    requested_model=route_result.resolved_model,
                                )
                            except Exception:
                                log.error("stream_cost_block_audit_failed", request_id=request_id)
                            return  # Close WITHOUT [DONE].

                    # F-008 (ADR-0009 §6, threat #14): stream-time BUDGET ceiling at
                    # the chunk boundary — same primitive as the §7.4 cost ceiling.
                    # Checks baseline (period-used at entry) + this request's running
                    # tokens/cost against each active BudgetLimitPolicy. On breach:
                    # emit policy_decision_deny (best-effort) and close WITHOUT [DONE].
                    if (
                        not stream_blocked
                        and route_result.budgets
                        and route_result.resolved_provider is not None
                        and route_result.resolved_model is not None
                    ):
                        running_cost = _cost.estimate_from_tokens(
                            route_result.resolved_provider,
                            route_result.resolved_model,
                            token_state["tokens_in"],
                            token_state["tokens_out"],
                        )
                        running_tokens = token_state["tokens_in"] + token_state["tokens_out"]
                        budget_decision = evaluate_budget_against(
                            route_result.budgets, running_tokens, running_cost
                        )
                        if isinstance(budget_decision, BudgetExceeded):
                            stream_blocked = True
                            error_msg, _ = ERROR_TABLE["policy_blocked"]
                            yield _build_sse_error_event(
                                error_code="policy_blocked",
                                message=error_msg,
                                request_id=request_id,
                            )
                            try:
                                from policy.audit_events import emit_policy_decision

                                await emit_policy_decision(
                                    tenant_context,
                                    request_id=request_id,
                                    allow=False,
                                    policy_id=budget_decision.policy_id,
                                    requested_model=route_result.resolved_model,
                                    reason=budget_decision.reason,
                                )
                            except Exception:
                                log.error("stream_budget_block_audit_failed", request_id=request_id)
                            return  # Close WITHOUT [DONE].

                    # F-005 PostResponseHook: bounded sliding-window inspection (D2).
                    if (
                        hook_registry is not None
                        and post_hook_ctx is not None
                        and _HOOKS_AVAILABLE
                        and not stream_blocked
                    ):
                        # Extract delta content for inspection.
                        chunk_content = _extract_chunk_content(chunk)
                        if chunk_content:
                            window = carried_tail + chunk_content
                            try:
                                await hook_registry.run_post_response(window, post_hook_ctx)
                            except (HookBlockedError, HookFailSafeError) as exc:
                                stream_blocked = True
                                # Emit SSEErrorEvent (ADR-0007 §7 / ADR-0006 Decision 3).
                                # internal_error for a fail-safe exception (unexpected
                                # hook error); policy_blocked for a clean detection block.
                                error_code = (
                                    "internal_error"
                                    if isinstance(exc, HookFailSafeError)
                                    else "policy_blocked"
                                )
                                error_msg, _ = ERROR_TABLE[error_code]
                                sse_error = _build_sse_error_event(
                                    error_code=error_code,
                                    message=error_msg,
                                    request_id=request_id,
                                )
                                yield sse_error
                                return  # Close WITHOUT [DONE].
                            # Advance sliding window.
                            combined = carried_tail + chunk_content
                            carried_tail = combined[-stream_buf_bytes:]

                    # F-016: accumulate delta content for post-stream code-scan.
                    # Extract the text content from the chunk (same helper used
                    # by the sliding-window inspection above). Only append while
                    # below the cap — once exhausted, subsequent content is
                    # silently skipped (the extractor will see a truncated but
                    # still well-formed accumulated text).
                    _chunk_text = _extract_chunk_content(chunk)
                    if _chunk_text and _scan_buf_bytes < _CODE_SCAN_MAX_TOTAL_BYTES:
                        _remaining = _CODE_SCAN_MAX_TOTAL_BYTES - _scan_buf_bytes
                        _encoded = _chunk_text.encode("utf-8", errors="replace")
                        if len(_encoded) > _remaining:
                            _encoded = _encoded[:_remaining]
                            _chunk_text = _encoded.decode("utf-8", errors="replace")
                        _scan_buf += _chunk_text
                        _scan_buf_bytes += len(_encoded)

                    yield chunk

            finally:
                # Partial-stream audit: emit with tokens accumulated so far.
                # HIGH-3 honest scope: if this emit fails after 200 headers are
                # sent, we CANNOT force 500. Log at ERROR level as out-of-band.
                try:
                    # tokens_in proxy was computed up front (HIGH-1) and is stable.
                    await emit_terminal_record(
                        request_id=request_id,
                        tenant_context=tenant_context,
                        model=validated.model,
                        tokens_in=token_state["tokens_in"],
                        tokens_out=token_state["tokens_out"],
                        start_time=start_time,
                    )
                except Exception:
                    log.error(
                        "stream_audit_failed",
                        request_id=request_id,
                    )

                # F-016 (ADR-0019 §4 / Fork 1, Vector 11): post-completion
                # code-scan on accumulated stream text.  Called unconditionally
                # (no-op when disabled / extra not installed).  The detector
                # detects ctx._is_stream=True and NEVER raises HookBlockedError
                # here (bytes already committed → WARN+audit with
                # block_suppressed_by_streaming=True).  Any unexpected exception
                # is caught and logged at ERROR level — the stream must close
                # cleanly regardless.
                if hook_registry is not None and post_hook_ctx is not None and _HOOKS_AVAILABLE:
                    try:
                        await hook_registry.run_code_scan(_scan_buf, post_hook_ctx)
                    except Exception:
                        log.error(
                            "stream_code_scan_failed",
                            request_id=request_id,
                        )

    headers = _success_headers(request_id, rl_limit, rl_remaining, rl_reset)
    return StreamingResponse(
        _generate(),
        status_code=200,
        media_type="text/event-stream",
        headers=headers,
    )


def _make_post_context(pre_ctx: Any, *, is_stream: bool = False) -> Any:
    """Build a post-response HookContext from the pre-request context.

    The same tenant IDs, request_id, and original_user_content carry over;
    only the phase changes to "post_response".  The event budget is shared so
    the per-detector cap (D4) is enforced across both phases of a request.

    is_stream: when True, the returned context carries _is_stream=True so that
    SecretOutboundHook can choose BLOCK (stop stream) over MASK (redact body).
    This is necessary because the 200 headers are already committed in streaming
    mode and the content cannot be retroactively replaced (FIX-1 / ADR-0007 §5).
    """
    if pre_ctx is None:
        return None
    try:
        from orchestration.context import HookContext

        ctx = HookContext(
            tenant_context=pre_ctx.tenant_context,
            request_id=pre_ctx.request_id,
            original_user_content=pre_ctx.original_user_content,
            phase="post_response",
            _events_per_detector_cap=pre_ctx._events_per_detector_cap,
            _event_budget=pre_ctx._event_budget,  # share budget across phases
        )
        # FIX-1: tag the context so outbound hooks know the streaming phase.
        ctx._is_stream = is_stream  # type: ignore[attr-defined]
        return ctx
    except Exception:
        return None


def _apply_masked_user_content(
    validated: CreateChatCompletionRequest,
    masked_content: str,
) -> CreateChatCompletionRequest:
    """Return a new CreateChatCompletionRequest with user message content replaced.

    Distributes the masked_content back into role="user" messages.  Since
    HookContext concatenates all user messages with "\\n", we replace all user
    message content with the full masked string in the first user message and
    blank the rest.  This is a simple distribution strategy; more precise
    per-message masking is deferred to F-006.
    """
    new_messages = []
    first_user = True
    for msg in validated.messages:
        if msg.role == "user":
            if first_user:
                # Replace with masked content (still bounded by field max_length).
                new_msg = msg.model_copy(update={"content": masked_content[:131_072]})
                first_user = False
            else:
                new_msg = msg.model_copy(update={"content": ""})
        else:
            new_msg = msg
        new_messages.append(new_msg)
    return validated.model_copy(update={"messages": new_messages})


def _extract_chunk_content(chunk: str) -> str:
    """Extract delta.content from an SSE chunk string, or "" if not present."""
    if not chunk.startswith("data: ") or chunk.startswith("data: [DONE]"):
        return ""
    raw = chunk[6:].strip()
    if not raw or raw == "[DONE]":
        return ""
    try:
        parsed = json.loads(raw)
        choices = parsed.get("choices", [])
        parts = []
        for c in choices:
            content = c.get("delta", {}).get("content") or ""
            parts.append(content)
        return "".join(parts)
    except (json.JSONDecodeError, KeyError, AttributeError):
        return ""


def _build_sse_error_event(*, error_code: str, message: str, request_id: str) -> str:
    """Build an SSE error event frame conforming to ADR-0007 §7 / ADR-0006 SSEErrorEvent.

    Format: event: error\\ndata: <Error JSON>\\n\\n
    No [DONE] is appended — the stream closes after this frame.
    """
    import json as _json

    payload = _json.dumps(
        {
            "error_code": error_code,
            "message": message,
            "request_id": request_id,
        }
    )
    return f"event: error\ndata: {payload}\n\n"


# ---------------------------------------------------------------------------
# F-006: provider registry resolution.
# Production builds the registry in _lifespan and stores it on app.state.
# A module-level fallback covers code paths without app.state (the stream
# generator, certain test configs) so the router always has a registry. The
# fallback is built once per process and reused.
# ---------------------------------------------------------------------------

_fallback_registry: ProviderRegistry | None = None


def _get_provider_registry(request: Request | None, settings) -> ProviderRegistry:
    """Return the per-app ProviderRegistry (from app.state), or a process fallback.

    Reusing app.state.provider_registry keeps the per-provider clients shared and
    torn down by _lifespan. The fallback is for paths/tests without a running
    lifespan; it is initialised lazily and cached at module scope.
    """
    if request is not None:
        reg = getattr(getattr(request, "app", None), "state", None)
        candidate = getattr(reg, "provider_registry", None) if reg is not None else None
        if isinstance(candidate, ProviderRegistry):
            return candidate

    global _fallback_registry
    if _fallback_registry is None:
        _fallback_registry = ProviderRegistry()
        _fallback_registry.init(settings)
    return _fallback_registry


def _peek_stream_flag(request: Request) -> bool:
    """Peek at the raw body to determine if stream: true, without full validation.

    Used only to pre-check for the concurrent-stream cap before full body parse.
    Returns False on any parse error (safe default — no stream slot consumed).
    """
    try:
        raw = getattr(request.state, "raw_body", b"")
        if raw:
            data = json.loads(raw)
            return bool(data.get("stream", False))
    except Exception:
        pass
    return False
