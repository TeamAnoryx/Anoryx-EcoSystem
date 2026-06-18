"""Gateway observability package (F-009, ADR-0011 §5-§6).

Exports the stable public API that orchestration hooks will call via lazy import
in STEP 3b:
  - record_event(event_type, *, tenant_id=None, policy_type=None, preset=None, outcome=None)
  - record_audit_write_failure(component)

Tracing API (D5):
  - get_tracer(name)         — returns an OTel Tracer (no-op when OTel disabled)
  - add_trace_context(...)   — structlog processor; injects trace_id / span_id
  - init_tracing(app, settings) — wires FastAPI + httpx auto-instrumentation

All other public names are stable but intended for gateway-internal wiring only.
"""

from gateway.observability.metrics import (
    log_cardinality_warning,
    observe_judge_latency,
    observe_request_duration,
    record_audit_write_failure,
    record_event,
    record_rate_limit_decision,
    record_request,
    render,
    set_redis_health,
)
from gateway.observability.tracing import (
    add_trace_context,
    get_tracer,
    init_tracing,
)

__all__ = [
    "log_cardinality_warning",
    "observe_judge_latency",
    "observe_request_duration",
    "record_audit_write_failure",
    "record_event",
    "record_rate_limit_decision",
    "record_request",
    "render",
    "set_redis_health",
    # Tracing
    "add_trace_context",
    "get_tracer",
    "init_tracing",
]
