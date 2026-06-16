"""Audit / terminal-emit wrapper (ADR-0006 pipeline step 1, Decision 3).

emit_terminal_record() builds the usage event from server-resolved IDs and
appends it to the audit log via AuditLogRepository on get_privileged_session().

AUDIT GUARANTEE:
  - Called on EVERY terminal outcome: 2xx success, every 4xx/5xx rejection.
  - If the audit append itself fails → the request outcome is forced to
    500 internal_error (an un-auditable success is a failure, ADR-0006 §Audit-
    guarantee, fail-safe posture from CLAUDE.md non-negotiable #5).
  - On early-rejected requests (4xx before upstream call): tokens_in/out = 0,
    latency_ms = elapsed wall time (records the rejected attempt).
  - On partial streams (disconnect/timeout): tokens_out = count so far,
    latency_ms = elapsed wall time at termination.

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
    are set to the zero UUID and empty slug as safe sentinel values.
    The event is still appended so the audit trail records the attempt.
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
        tenant_id = "00000000-0000-0000-0000-000000000000"
        team_id = "00000000-0000-0000-0000-000000000000"
        project_id = "00000000-0000-0000-0000-000000000000"
        agent_id = "unknown"

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

    AUDIT GUARANTEE (ADR-0006 Decision 3):
    - Called on every terminal outcome (success and failure).
    - Uses get_privileged_session() for the chain append (audit is a chain op
      that requires global visibility — ADR-0005).
    - If the audit append fails → raises GatewayError("internal_error") so
      the caller can force 500. An un-auditable success is treated as a failure.
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
        raise GatewayError("internal_error")
