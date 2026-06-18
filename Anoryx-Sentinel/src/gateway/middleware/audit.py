"""Audit / terminal-emit helpers (ADR-0006 pipeline step 1, Decision 3).

emit_terminal_record() builds the usage event from server-resolved IDs and
appends it to the audit log via AuditLogRepository on get_privileged_session().

AUDIT COVERAGE (honest scope — HIGH-3 / LOW-4 amendment):
  - emit_terminal_record() is called on every terminal outcome for NON-STREAMING
    requests: 2xx success, every 4xx/5xx rejection. This covers the full
    non-stream lifecycle.
  - For STREAMING requests (text/event-stream), the 200 response headers are
    sent before the generator runs. Audit for the stream body is emitted inside
    the generator's finally-block (chat_completions.py). If that finally-block
    audit fails, the failure is surfaced out-of-band (error-level structured
    log) — the 200 headers cannot be retroactively changed to 500. This is an
    inherent SSE constraint, not a code defect. See ADR-0006 Decision 3 amendment.
  - Pre-route rejections (401, 400, 413) are covered by TerminalAuditMiddleware
    (outermost ASGI wrapper) which calls emit_terminal_record() for every
    direct JSONResponse returned by inner middlewares.
  - On early-rejected requests (4xx before upstream call): tokens_in/out = 0,
    latency_ms = elapsed wall time (records the rejected attempt).
  - On partial streams (disconnect/timeout): tokens_out = count so far,
    latency_ms = elapsed wall time at termination.

AUDIT-FAILURE BEHAVIOR:
  - NON-STREAM: if the audit append fails → raises GatewayError("internal_error")
    so the caller can force 500. A non-stream success that cannot be audited is
    treated as a failure (fail-safe posture, CLAUDE.md non-negotiable #5).
  - STREAM / PRE-ROUTE REJECTION: audit failure is logged at ERROR level as an
    out-of-band signal. The already-committed response cannot be changed.
    This must NOT be swallowed silently — operators must be alerted.

NEVER LOG:
  - DATABASE_URL, APP_DATABASE_URL, SENTINEL_KEY_SECRET
  - virtual API keys (plaintext OR fingerprint)
  - full request bodies (PII risk)
  - raw client-supplied header values
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog

from gateway.context import TenantContext
from gateway.exceptions import GatewayError
from persistence.database import get_privileged_session
from persistence.repositories.audit_log_repository import AuditLogRepository

log = structlog.get_logger(__name__)


def get_tracer(name: str):
    """Module-level wrapper around observability.tracing.get_tracer.

    Defined here so tests can patch gateway.middleware.audit.get_tracer
    without needing to import gateway.observability.tracing in test code.
    This wrapper is the sole entry point for obtaining a tracer in this module;
    all three emitters call it via the module-level reference.
    Returns None if OTel is unavailable (caller falls back to untraced path).
    """
    try:
        from gateway.observability.tracing import get_tracer as _real_get_tracer

        return _real_get_tracer(name)
    except Exception:
        return None


def _span_kind_internal():
    """Return SpanKind.INTERNAL, or None if OTel is unavailable (R8 safe)."""
    try:
        from opentelemetry.trace import SpanKind

        return SpanKind.INTERNAL
    except Exception:
        return None


# Schema-bounded clamps (contracts/events.schema.json UsageEvent).
_MAX_TOKENS = 10_000_000
_MAX_LATENCY_MS = 3_600_000
_MAX_COST_CENTS = 100_000_000.0

# Cost rate: placeholder estimate (cents per token, input and output).
# This is a CLIENT-SIDE COST ESTIMATE, not an authoritative bill.
# Will be replaced by model-specific pricing table in F-006/F-010.
_COST_PER_TOKEN_IN_CENTS: float = 0.0015 / 1000  # ~GPT-3.5 input tier placeholder
_COST_PER_TOKEN_OUT_CENTS: float = 0.002 / 1000  # ~GPT-3.5 output tier placeholder


def _clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, value))


def _clamp_float(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def _estimate_cost(tokens_in: int, tokens_out: int) -> float:
    """Client-side cost estimate in cents. Estimate only; not an authoritative bill."""
    raw = tokens_in * _COST_PER_TOKEN_IN_CENTS + tokens_out * _COST_PER_TOKEN_OUT_CENTS
    return _clamp_float(raw, 0.0, _MAX_COST_CENTS)


def build_usage_event(
    *,
    request_id: str,
    tenant_context: TenantContext | None,
    model: str,
    tokens_in: int,
    tokens_out: int,
    start_time: float,  # time.monotonic() at request start
) -> dict[str, Any]:
    """Build the usage event dict conforming to events.schema.json UsageEvent.

    All 12 required fields are present. Uses server-resolved IDs from
    TenantContext — never client-supplied values (ADR-0006 Decision 4).

    If tenant_context is None (rejected before auth resolved), the four IDs
    are set to the zero UUID and 'gateway-core' agent slug as safe sentinel
    values. The event is still appended so the audit trail records the attempt.
    """
    elapsed_ms = int((time.monotonic() - start_time) * 1000)
    now_utc = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    if tenant_context is not None:
        tenant_id = tenant_context.tenant_id
        team_id = tenant_context.team_id
        project_id = tenant_context.project_id
        agent_id = tenant_context.agent_id
    else:
        # Pre-auth rejection: no resolved context yet.
        # Use safe sentinel values so the required fields are present.
        # Sentinel IDs: all-zeros UUID; agent slug 'gateway-core'.
        tenant_id = "00000000-0000-0000-0000-000000000000"
        team_id = "00000000-0000-0000-0000-000000000000"
        project_id = "00000000-0000-0000-0000-000000000000"
        agent_id = "gateway-core"

    # Enforce schema bounds on all numeric fields.
    safe_tokens_in = _clamp(tokens_in, 0, _MAX_TOKENS)
    safe_tokens_out = _clamp(tokens_out, 0, _MAX_TOKENS)
    safe_latency_ms = _clamp(elapsed_ms, 0, _MAX_LATENCY_MS)
    safe_cost = _estimate_cost(safe_tokens_in, safe_tokens_out)

    return {
        "event_type": "usage",
        "tenant_id": tenant_id,
        "team_id": team_id,
        "project_id": project_id,
        "agent_id": agent_id,
        "event_id": str(uuid.uuid4()),
        "event_timestamp": now_utc,
        "request_id": request_id,
        "model": model[:256] if model else "unknown",
        "tokens_in": safe_tokens_in,
        "tokens_out": safe_tokens_out,
        "latency_ms": safe_latency_ms,
        "cost_estimate_cents": safe_cost,
    }


def build_routing_decision_event(
    *,
    request_id: str,
    tenant_context: TenantContext | None,
    selected_provider: str,
    routing_reason: str,
    outcome: str,
    action_taken: str,
    attempt_index: int,
    requested_model: str,
) -> dict[str, Any]:
    """Build a routing_decision event dict (F-006, ADR-0008 §5).

    agent_id is the EMITTING COMPONENT slug 'gateway-core' (the router runs
    inside the gateway), never a provider/model name — the provider is carried
    in selected_provider. Carries NO provider credential or upstream body text
    (threat #1 / #10). All strings are bounded by the schema; attempt_index is
    capped at 16.
    """
    now_utc = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    if tenant_context is not None:
        tenant_id = tenant_context.tenant_id
        team_id = tenant_context.team_id
        project_id = tenant_context.project_id
    else:
        tenant_id = "00000000-0000-0000-0000-000000000000"
        team_id = "00000000-0000-0000-0000-000000000000"
        project_id = "00000000-0000-0000-0000-000000000000"

    return {
        "event_type": "routing_decision",
        "tenant_id": tenant_id,
        "team_id": team_id,
        "project_id": project_id,
        # agent_id is the component slug, NOT the provider (ADR §5.3).
        "agent_id": "gateway-core",
        "event_id": str(uuid.uuid4()),
        "event_timestamp": now_utc,
        "request_id": request_id,
        "selected_provider": selected_provider,
        "routing_reason": routing_reason[:64],
        "outcome": outcome,
        "action_taken": action_taken,
        "attempt_index": _clamp(attempt_index, 0, 16),
        "requested_model": (requested_model or "unknown")[:256],
    }


async def emit_routing_decision(
    *,
    request_id: str,
    tenant_context: TenantContext | None,
    selected_provider: str,
    routing_reason: str,
    outcome: str,
    action_taken: str,
    attempt_index: int,
    requested_model: str,
) -> None:
    """Append a routing_decision event via the privileged-session audit path.

    BEST-EFFORT OBSERVABILITY: a routing_decision is observability, not the
    terminal usage record. If the append fails it is logged at ERROR level
    out-of-band and SWALLOWED — a failed routing-decision emit must NOT convert
    a successful (or already-failing) request into a different outcome. The
    terminal usage event (emit_terminal_record) remains the fail-safe gate.
    """
    event_data = build_routing_decision_event(
        request_id=request_id,
        tenant_context=tenant_context,
        selected_provider=selected_provider,
        routing_reason=routing_reason,
        outcome=outcome,
        action_taken=action_taken,
        attempt_index=attempt_index,
        requested_model=requested_model,
    )
    try:
        # F-009 D5: INTERNAL span around routing_decision audit append.
        # get_tracer is the module-level wrapper — patchable in tests (M2).
        _tracer = get_tracer("sentinel.audit_emit")

        async def _do_routing_append() -> None:
            async with get_privileged_session() as session:
                async with session.begin():
                    repo = AuditLogRepository(session)
                    await repo.append(event_data)

        if _tracer is not None:
            # M2 guard: only re-run the append when span SETUP failed before
            # the append ran. If the append itself raised, propagate — the
            # outer except in emit_routing_decision swallows it (best-effort).
            _routing_append_ran = False
            try:
                _kind = _span_kind_internal()
                with _tracer.start_as_current_span("audit_emit", kind=_kind) as _span:
                    _span.set_attribute("request_id", request_id)
                    _routing_append_ran = True
                    await _do_routing_append()
            except Exception:
                if not _routing_append_ran:
                    await _do_routing_append()
                else:
                    raise
        else:
            await _do_routing_append()

        log.info(
            "routing_decision_appended",
            request_id=request_id,
            outcome=outcome,
            selected_provider=selected_provider,
            attempt_index=event_data["attempt_index"],
        )
    except Exception:
        log.error(
            "routing_decision_append_failed",
            request_id=request_id,
            outcome=outcome,
        )


_WILDCARD_UUID = "00000000-0000-0000-0000-000000000000"
_RATE_LIMITER_AGENT_ID = "rate-limiter"


async def emit_rate_limit_event(
    event_type: str,
    *,
    request_id: str,
    tenant_id: str | None = None,
    team_id: str | None = None,
    project_id: str | None = None,
    agent_id: str | None = None,
    redis_error_class: str | None = None,
    redis_error_module: str | None = None,
) -> None:
    """Append a rate_limit_degraded / rate_limit_recovered / rate_limit_redis_error event.

    Mirrors emit_routing_decision: uses get_privileged_session() + AuditLogRepository.append().
    Best-effort observability: exceptions are swallowed and logged at ERROR level.

    ID convention (ADR-0011 §7 / D6):
      - rate_limit_recovered + health-loop-emitted degraded/redis_error:
          tenant_id = WILDCARD_UUID, team_id = WILDCARD_UUID,
          project_id = WILDCARD_UUID, agent_id = 'rate-limiter'.
      - In-request degraded/redis_error: real four IDs from the failing request's
          TenantContext are passed by the caller.

    redis_error_class: type(exc).__name__ — short exception class name, bounded [:64].
    redis_error_module: type(exc).__module__ — the module the exception class lives in,
        bounded [:128]. Both go in the event payload ONLY (Redis Streams JSON / OTel span).
        They are NEVER written to an events_audit_log column (ADR-0011 §7 forensic note).
        We NEVER use str(exc) — it may contain host/port/credentials.

    NOTE: new variants are not yet in VALID_EVENT_TYPES until migration 0011 runs.
    The append is best-effort; if the CHECK constraint rejects it we log at ERROR.
    """
    now_utc = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    resolved_tenant_id = tenant_id if tenant_id is not None else _WILDCARD_UUID
    resolved_team_id = team_id if team_id is not None else _WILDCARD_UUID
    resolved_project_id = project_id if project_id is not None else _WILDCARD_UUID
    resolved_agent_id = agent_id if agent_id is not None else _RATE_LIMITER_AGENT_ID

    event_data: dict[str, Any] = {
        "event_type": event_type,
        "tenant_id": resolved_tenant_id,
        "team_id": resolved_team_id,
        "project_id": resolved_project_id,
        "agent_id": resolved_agent_id,
        "event_id": str(uuid.uuid4()),
        "event_timestamp": now_utc,
        "request_id": request_id,
        "action_taken": "logged",
    }

    # redis_error_class and redis_error_module are forensic metadata in the
    # event payload only — never in an audit-log column (ADR-0011 §7).
    if redis_error_class is not None:
        event_data["redis_error_class"] = redis_error_class[:64]
    if redis_error_module is not None:
        event_data["redis_error_module"] = redis_error_module[:128]

    try:
        # F-009 D5: INTERNAL span around rate-limit event audit append.
        # get_tracer is the module-level wrapper — patchable in tests (M2).
        _tracer = get_tracer("sentinel.audit_emit")

        async def _do_rl_append() -> None:
            async with get_privileged_session() as session:
                async with session.begin():
                    repo = AuditLogRepository(session)
                    await repo.append(event_data)

        if _tracer is not None:
            # M2 guard: only re-run the append when span SETUP failed before
            # the append ran. If the append itself raised, propagate — the
            # outer except in emit_rate_limit_event swallows it (best-effort).
            _rl_append_ran = False
            try:
                _kind = _span_kind_internal()
                with _tracer.start_as_current_span("audit_emit", kind=_kind) as _span:
                    _span.set_attribute("request_id", request_id)
                    _rl_append_ran = True
                    await _do_rl_append()
            except Exception:
                if not _rl_append_ran:
                    await _do_rl_append()
                else:
                    raise
        else:
            await _do_rl_append()

        log.info(
            "rate_limit_event_appended",
            event_type=event_type,
            request_id=request_id,
        )
    except Exception:
        log.error(
            "rate_limit_event_append_failed",
            event_type=event_type,
            request_id=request_id,
        )


async def emit_terminal_record(
    *,
    request_id: str,
    tenant_context: TenantContext | None,
    model: str,
    tokens_in: int,
    tokens_out: int,
    start_time: float,
) -> None:
    """Append a usage event to the audit log.

    AUDIT-FAILURE BEHAVIOR (ADR-0006 Decision 3):
    - For NON-STREAM callers: if the audit append fails → raises
      GatewayError("internal_error") so the caller can force 500.
      A non-stream success that cannot be audited is treated as a failure.
    - For STREAM / pre-route-rejection callers: the caller catches all
      exceptions and logs at ERROR level out-of-band. The already-committed
      response cannot be changed. See TerminalAuditMiddleware and
      chat_completions._handle_stream for handling.
    - Uses get_privileged_session() for the chain append (audit is a chain op
      that requires global visibility — ADR-0005).
    """
    event_data = build_usage_event(
        request_id=request_id,
        tenant_context=tenant_context,
        model=model,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        start_time=start_time,
    )

    try:
        # F-009 D5: INTERNAL span around the audit append (ADR-0011 §6).
        # Attributes per R9: request_id only — no tenant PII, no event content.
        # R8: span failure never propagates; append runs untraced on span error.
        #
        # M2 guard: _append_ran tracks whether _do_append() has been invoked.
        # The outer except re-runs the append ONLY when the span SETUP failed
        # before the append ran (_append_ran is False). If the append itself
        # raised, we do NOT re-run it — a failed audit append must not be
        # retried silently (it surfaces to the caller as GatewayError below).
        #
        # get_tracer is the module-level wrapper — patchable in tests (M2).
        _tracer = get_tracer("sentinel.audit_emit")

        async def _do_append() -> None:
            async with get_privileged_session() as session:
                async with session.begin():
                    repo = AuditLogRepository(session)
                    await repo.append(event_data)

        if _tracer is not None:
            _append_ran = False
            try:
                _kind = _span_kind_internal()
                with _tracer.start_as_current_span("audit_emit", kind=_kind) as _span:
                    _span.set_attribute("request_id", request_id)
                    _append_ran = True
                    await _do_append()
            except Exception:
                if not _append_ran:
                    # Span setup failed before append ran — run untraced.
                    await _do_append()
                else:
                    # Append itself raised (or raised after running) — propagate.
                    raise
        else:
            await _do_append()

        log.info(
            "audit_appended",
            request_id=request_id,
            event_id=event_data["event_id"],
            latency_ms=event_data["latency_ms"],
        )
    except Exception:
        log.exception(
            "audit_append_failed",
            request_id=request_id,
            # Never log event_data — may contain tenant IDs bound to the request.
        )
        raise GatewayError("internal_error") from None
