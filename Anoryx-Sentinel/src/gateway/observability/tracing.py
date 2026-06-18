"""OpenTelemetry tracing configuration (F-009, ADR-0011 §6 Decision D5).

TracerProvider is configured with NO export backend in F-009. Spans are emitted
to a no-op sink; OTLP export, collector, and sampling are F-010 (deployment)
concerns. The instrumentation hooks ship here so F-010 is configuration-only.

Auto-instrumentation:
  FastAPIInstrumentor().instrument_app(app) — wraps FastAPI request/response.
  HTTPXClientInstrumentor().instrument()    — injects W3C traceparent on outbound
                                             httpx requests (vector #12).

Manual INTERNAL spans (context managers inside existing function bodies, not new
middleware; ADR-0011 R2 — no order change):
  rate_limit_check  — in rate_limit.py check_rate_limit
  provider_call     — in router/registry.py dispatch
  audit_emit        — in middleware/audit.py emit_* helpers

Span hygiene (R9):
  Attributes: tier / result / tenant_id (UUID) / request_id / provider ONLY.
  NEVER: virtual_key_id in plaintext, prompt content, secrets, PII.
  If correlation by key is needed: sha256(virtual_key_id)[:12] only.

R8 — failure safety:
  A span/export failure MUST NOT propagate into the request path. Every OTel
  call in this module is wrapped so exceptions are swallowed (logged at WARNING).

Idempotency:
  init_tracing() is safe to call multiple times. A module-level flag prevents
  double-instrumentation of FastAPI or httpx.
"""

from __future__ import annotations

import hashlib
import logging
import os
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from fastapi import FastAPI

    from gateway.config import GatewaySettings

_otel_log = logging.getLogger(__name__)
log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level idempotency guard — set to True after init_tracing() runs once.
# This prevents double-instrumentation on test re-imports.
# ---------------------------------------------------------------------------
_initialized: bool = False


def init_tracing(app: "FastAPI", settings: "GatewaySettings") -> None:
    """Configure OTel tracing and wire auto-instrumentation into the FastAPI app.

    MUST be called AFTER all middleware has been added to *app* (create_app in
    main.py calls us at the end of the factory, after add_middleware chain).

    When settings.enable_otel is False, this function is a no-op — the gateway
    continues to operate without any OTel dependency (R8: disable path is safe).

    Idempotent: a second call is a no-op.
    """
    global _initialized

    if not settings.enable_otel:
        return

    if _initialized:
        return

    try:
        _configure_provider()
        _instrument_fastapi(app)
        _instrument_httpx()
        _initialized = True
        log.info("otel_tracing_initialized", enable_otel=True)
    except Exception as exc:
        # R8: OTel setup failure must never crash the gateway.
        log.warning("otel_tracing_init_failed", error_class=type(exc).__name__)


def _configure_provider() -> None:
    """Set up the TracerProvider, wiring an OTLP exporter ONLY when configured.

    F-010 (ADR-0012 §5, R1 Deviation 1) completes the F-009 handoff: when the
    OTel-standard env var OTEL_EXPORTER_OTLP_ENDPOINT is set, a BatchSpanProcessor
    with an OTLP/gRPC exporter is attached so spans flow to the bundled OTel
    Collector (or any OTLP backend). When the env var is UNSET, no SpanProcessor
    is added — behavior is byte-identical to F-009 (spans exist in-process for
    W3C context propagation but are never exported).

    R8: any failure wiring the exporter (e.g. the exporter package missing, or a
    malformed endpoint) is swallowed — tracing degrades to the no-op sink and the
    request path is never affected.
    """
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider

    provider = TracerProvider()

    if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
        # Transport is chosen by the OTel-standard OTEL_EXPORTER_OTLP_PROTOCOL:
        #   "http/protobuf" (default) → the lightweight HTTP exporter, a CORE dep.
        #   "grpc"                    → the heavier gRPC exporter, the [otlp-grpc] extra.
        # The exporter reads OTEL_EXPORTER_OTLP_ENDPOINT itself — nothing hardcoded.
        protocol = os.environ.get("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf").lower()
        try:
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            if protocol == "grpc":
                from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                    OTLPSpanExporter,
                )
            else:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                    OTLPSpanExporter,
                )
            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
            log.info("otel_otlp_exporter_wired", protocol=protocol)
        except ImportError as exc:
            # grpc transport requested but the [otlp-grpc] extra is not installed.
            # R8: degrade to the no-op sink; never break startup.
            log.warning(
                "otel_otlp_exporter_unavailable",
                protocol=protocol,
                hint="install 'anoryx-sentinel[otlp-grpc]' for gRPC OTLP transport",
                error_class=type(exc).__name__,
            )
        except Exception as exc:
            # R8: never let exporter wiring break startup; fall back to no-op sink.
            log.warning("otel_otlp_exporter_wire_failed", error_class=type(exc).__name__)

    trace.set_tracer_provider(provider)


def _instrument_fastapi(app: "FastAPI") -> None:
    """Instrument the FastAPI app for automatic request/response tracing."""
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        inst = FastAPIInstrumentor()
        if not inst.is_instrumented_by_opentelemetry:
            inst.instrument_app(app)
    except Exception as exc:
        log.warning("otel_fastapi_instrument_failed", error_class=type(exc).__name__)


def _instrument_httpx() -> None:
    """Instrument httpx to inject W3C traceparent on outbound provider requests.

    This is what makes vector #12 work: W3C traceparent is injected on every
    outbound httpx request, propagating trace context to providers.
    """
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

        inst = HTTPXClientInstrumentor()
        if not inst.is_instrumented_by_opentelemetry:
            inst.instrument()
    except Exception as exc:
        log.warning("otel_httpx_instrument_failed", error_class=type(exc).__name__)


def get_tracer(name: str):
    """Return an OTel Tracer by name.

    Safe to call regardless of enable_otel state — when OTel is not initialized,
    the global tracer provider is the no-op provider and this returns a no-op
    tracer that produces NonRecordingSpan instances (zero overhead, no side effects).

    Orchestration code imports this via lazy import in STEP 4b for
    policy_evaluation and judge_invocation spans.
    """
    try:
        from opentelemetry import trace

        return trace.get_tracer(name)
    except Exception:
        # Absolute last-resort: return a no-op tracer that never raises.
        return _NoOpTracer()


def add_trace_context(logger: Any, method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """Structlog processor: inject trace_id and span_id into every log event.

    Reads the current OTel span context. When a span is recording:
      - trace_id: 32-char lowercase hex string (W3C format).
      - span_id:  16-char lowercase hex string.

    When no span is active or OTel is unavailable, this is a strict no-op —
    the event_dict is returned unchanged. Never raises (R8).

    Insert this processor BEFORE JSONRenderer and AFTER merge_contextvars
    in the structlog processor chain (logging.py configure_logging).
    """
    try:
        from opentelemetry import trace

        span = trace.get_current_span()
        if span.is_recording():
            ctx = span.get_span_context()
            event_dict["trace_id"] = format(ctx.trace_id, "032x")
            event_dict["span_id"] = format(ctx.span_id, "016x")
    except Exception:
        pass  # R8: never let OTel failure affect request/log emission.
    return event_dict


def key_fingerprint(virtual_key_id: str) -> str:
    """Return a 12-char SHA-256 prefix of virtual_key_id for span correlation.

    NEVER put virtual_key_id in plaintext on a span (it is an auth credential).
    Use this fingerprint when correlation by key is operationally needed (R9).
    """
    return hashlib.sha256(virtual_key_id.encode()).hexdigest()[:12]


def reset_for_testing() -> None:
    """Reset the initialization flag (test helper only).

    Allows test suites to call init_tracing() more than once with different
    settings. Production code never calls this.
    """
    global _initialized
    _initialized = False

    # Also reset the OTel global provider to the no-op default so that
    # tests that did not call init_tracing don't accidentally inherit a
    # real TracerProvider from a prior test.
    try:
        from opentelemetry import trace
        from opentelemetry.trace import ProxyTracerProvider

        # Set a fresh no-op provider so subsequent get_tracer calls return
        # NonRecordingSpans (zero overhead, never raises).
        trace.set_tracer_provider(ProxyTracerProvider())
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Fallback no-op tracer (used only if OTel import itself fails at get_tracer)
# ---------------------------------------------------------------------------


class _NoOpSpan:
    """Minimal no-op span that satisfies the context-manager protocol."""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def is_recording(self) -> bool:
        return False

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def record_exception(self, exc: Exception) -> None:
        pass

    def set_status(self, *args, **kwargs) -> None:
        pass


class _NoOpTracer:
    """Fallback tracer returned when OTel is completely unavailable."""

    def start_as_current_span(self, name: str, **kwargs):
        return _NoOpSpan()

    def start_span(self, name: str, **kwargs):
        return _NoOpSpan()
