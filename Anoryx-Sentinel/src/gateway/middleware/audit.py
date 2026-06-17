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
        async with get_privileged_session() as session:
            async with session.begin():
                repo = AuditLogRepository(session)
                await repo.append(event_data)
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
        async with get_privileged_session() as session:
            async with session.begin():
                repo = AuditLogRepository(session)
                await repo.append(event_data)
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
