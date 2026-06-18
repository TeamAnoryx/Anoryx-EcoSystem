"""OTLP exporter wiring test (F-010, ADR-0012 §5 / §9 vector 13, R1 Deviation 1).

Proves the env-gated app→collector OTLP export:
  - When OTEL_EXPORTER_OTLP_ENDPOINT is SET, _configure_provider attaches a
    span processor (the OTLP export pipeline).
  - When UNSET, NO span processor is attached — behavior is byte-identical to
    F-009 (in-process no-op sink), preserving the failure-safe default.

ISOLATION: the OTel global TracerProvider can only be set once per process, so
these tests neutralise trace.set_tracer_provider (autouse) — _configure_provider
is exercised for its span-processor wiring WITHOUT mutating global state that the
F-009 tracing tests depend on. No network I/O occurs (the OTLP/gRPC exporter
connects lazily on first export, not at construction).
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

import gateway.observability.tracing as tracing


@pytest.fixture(autouse=True)
def _isolate_global_provider(monkeypatch):
    """Prevent any global TracerProvider mutation from leaking across test files."""
    monkeypatch.setattr("opentelemetry.trace.set_tracer_provider", lambda *a, **k: None)
    yield


def test_otlp_exporter_wired_when_endpoint_set(monkeypatch):
    """Vector 13: endpoint configured ⇒ OTLP export pipeline attached."""
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317")
    with patch("opentelemetry.sdk.trace.TracerProvider.add_span_processor") as add_proc:
        tracing._configure_provider()
    assert add_proc.called, "OTLP span processor must be attached when endpoint is set"


def test_no_exporter_when_endpoint_unset(monkeypatch):
    """Vector 13: endpoint unset ⇒ no processor (F-009 no-op sink preserved)."""
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    with patch("opentelemetry.sdk.trace.TracerProvider.add_span_processor") as add_proc:
        tracing._configure_provider()
    assert not add_proc.called, "no exporter must be wired when endpoint is unset"


def test_exporter_wire_failure_is_swallowed(monkeypatch):
    """R8: a failure constructing the exporter must not propagate (no-op fallback)."""
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://otel-collector:4317")
    with patch(
        "opentelemetry.exporter.otlp.proto.grpc.trace_exporter.OTLPSpanExporter",
        side_effect=RuntimeError("boom"),
    ):
        # Must not raise — the except branch logs and falls back to the no-op sink.
        tracing._configure_provider()
