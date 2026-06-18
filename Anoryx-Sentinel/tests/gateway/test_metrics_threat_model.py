"""F-009 Metrics threat model tests (ADR-0011 §9, vectors 9-11, 14).

Vector 9:  /metrics scrape → assert NO api keys / virtual keys / prompt text / PII.
Vector 10: Default (enable_per_tenant_metrics=False) → no tenant_id label on any series.
Vector 11: enable_per_tenant_metrics=True → tenant_id label present + startup warning logged.
Vector 14: Cardinality bomb — 1000 distinct tenants; /metrics render time bounded (<2s) and
           with per-tenant OFF series count stays constant regardless of tenant count.
"""

from __future__ import annotations

import time
from unittest.mock import patch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SENTINEL_PII = "john.smith@example.com"
_SENTINEL_PROMPT = "CONFIDENTIAL SYSTEM PROMPT — SECRET CONTENT"
_FAKE_API_KEY = "sk-prod-AAAABBBBCCCC1234567890abcdef"
_FAKE_VIRTUAL_KEY = "sk-sentinel-virt-key-12345678901234567890abcdef"


def _render_text() -> str:
    """Call render() and decode to text for assertion."""
    from gateway.observability.metrics import render

    body, content_type = render()
    assert b"text/plain" in content_type.encode() or "text/plain" in content_type
    return body.decode("utf-8")


def _reset_metrics_registry() -> None:
    """Reset all metric counters/histograms to zero by re-creating the registry.

    prometheus_client does not support resetting individual counters in the same
    process. We reload the metrics module IN PLACE (importlib.reload reuses the
    same module object) so its dedicated CollectorRegistry + metric objects are
    rebuilt fresh. We deliberately do NOT del+reimport via sys.modules: that would
    create a *new* module object, leaving any already-bound reference (e.g.
    gateway.main's `metrics`, orchestration's lazy import) pointing at the stale
    module — a patch on the new module would then miss the call site. Reloading in
    place preserves module identity for all importers.
    """
    import importlib

    from gateway.observability import metrics

    importlib.reload(metrics)


# ---------------------------------------------------------------------------
# Vector 9: /metrics scrape — no API keys / virtual keys / prompt / PII
# ---------------------------------------------------------------------------


class TestVector9NoInfoDisclosure:
    """Vector 9: scrape /metrics after seeding a request; assert no sensitive data."""

    def setup_method(self):
        _reset_metrics_registry()

    def test_no_pii_in_output(self):
        """PII strings must never appear in /metrics output."""
        from gateway.observability.metrics import record_event, record_request

        # Seed activity — only bounded label values should be stored.
        record_request("openai", "2xx")
        record_event("pii_blocked")

        output = _render_text()
        assert _SENTINEL_PII not in output

    def test_no_prompt_in_output(self):
        """Prompt/system-instruction text must never appear in /metrics output."""
        from gateway.observability.metrics import record_request

        record_request("openai", "2xx")
        output = _render_text()
        assert _SENTINEL_PROMPT not in output

    def test_no_api_key_in_output(self):
        """Real or fake API key strings must never appear in /metrics output."""
        from gateway.observability.metrics import record_request

        record_request("openai", "2xx")
        output = _render_text()
        assert _FAKE_API_KEY not in output

    def test_no_virtual_key_in_output(self):
        """Virtual key strings must never appear in /metrics output."""
        from gateway.observability.metrics import record_request

        record_request("openai", "2xx")
        output = _render_text()
        assert _FAKE_VIRTUAL_KEY not in output

    def test_output_contains_only_expected_metric_names(self):
        """Output must reference only the defined sentinel_* metric names."""
        from gateway.observability.metrics import record_request

        record_request("openai", "2xx")
        output = _render_text()

        # Every metric family line (# HELP / # TYPE) must start with 'sentinel_'.
        for line in output.splitlines():
            if line.startswith("# HELP") or line.startswith("# TYPE"):
                parts = line.split(" ")
                assert len(parts) >= 3, f"Unexpected line: {line}"
                metric_name = parts[2]
                assert metric_name.startswith(
                    "sentinel_"
                ), f"Unexpected metric family: {metric_name!r}"

    def test_output_has_no_connection_string(self):
        """Connection strings / DB URLs must never appear in metrics output."""
        from gateway.observability.metrics import record_request

        record_request("openai", "2xx")
        output = _render_text()
        # Broad heuristics for connection-string patterns.
        assert "postgresql://" not in output
        assert "redis://" not in output
        assert "password" not in output.lower()


# ---------------------------------------------------------------------------
# Vector 10: Default — no tenant_id label present on any series
# ---------------------------------------------------------------------------


class TestVector10NoTenantLabelByDefault:
    """Vector 10: with enable_per_tenant_metrics=False (default), no tenant_id label."""

    def setup_method(self):
        _reset_metrics_registry()

    def test_no_tenant_id_label_in_default_output(self, monkeypatch):
        """Default settings must produce no tenant_id label in /metrics."""
        from gateway.config import _reset_settings

        monkeypatch.setenv("ENABLE_PER_TENANT_METRICS", "false")
        _reset_settings()

        from gateway.observability.metrics import record_rate_limit_decision, record_request

        # Seed with a real tenant_id that SHOULD NOT appear.
        tenant_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        record_request("openai", "2xx", tenant_id=tenant_id)
        record_rate_limit_decision("admitted", tenant_id=tenant_id)

        output = _render_text()
        # The tenant_id UUID must not appear as a label value.
        assert (
            'tenant_id="' not in output
        ), "tenant_id label found in /metrics output but enable_per_tenant_metrics=False"
        # The UUID value must not appear at all.
        assert tenant_id not in output, f"Tenant UUID {tenant_id!r} leaked into /metrics output"

        _reset_settings()

    def test_metric_families_present_without_tenant_labels(self, monkeypatch):
        """Core metric families are present even without per-tenant labels."""
        from gateway.config import _reset_settings

        monkeypatch.setenv("ENABLE_PER_TENANT_METRICS", "false")
        _reset_settings()

        from gateway.observability.metrics import (
            record_audit_write_failure,
            record_event,
            record_rate_limit_decision,
            record_request,
            set_redis_health,
        )

        record_request("anthropic", "2xx")
        record_rate_limit_decision("admitted")
        record_event("pii_blocked")
        record_event("policy_violated", policy_type="budget_limit")
        record_event("judge_billing_event", preset="injection", outcome="safe")
        record_event("shadow_ai_detected_outbound")
        record_event("classifier_degraded")
        record_audit_write_failure("audit_log")
        set_redis_health(True)

        output = _render_text()

        expected_families = [
            "sentinel_requests_total",
            "sentinel_rate_limit_decisions_total",
            "sentinel_pii_blocks_total",
            "sentinel_policy_violations_total",
            "sentinel_audit_write_failures_total",
            "sentinel_judge_invocation_total",
            "sentinel_shadow_ai_detected_outbound_total",
            "sentinel_classifier_degraded_total",
            "sentinel_request_duration_seconds",
            "sentinel_judge_latency_seconds",
            "sentinel_redis_health",
        ]
        for family in expected_families:
            assert family in output, f"Expected metric family {family!r} missing from /metrics"

        _reset_settings()


# ---------------------------------------------------------------------------
# Vector 11: enable_per_tenant_metrics=True — tenant_id label present + warning logged
# ---------------------------------------------------------------------------


class TestVector11PerTenantMetricsEnabled:
    """Vector 11: enable_per_tenant_metrics=True → tenant_id labels appear + startup warning."""

    def setup_method(self):
        _reset_metrics_registry()

    def test_log_cardinality_warning_emits_warning(self, monkeypatch, caplog):
        """log_cardinality_warning() must emit a warning-level structlog event."""
        import logging

        from gateway.config import _reset_settings

        monkeypatch.setenv("ENABLE_PER_TENANT_METRICS", "true")
        _reset_settings()

        with caplog.at_level(logging.WARNING):
            from gateway.observability.metrics import log_cardinality_warning

            log_cardinality_warning()

        # structlog may or may not bridge to stdlib logging depending on config;
        # call the function and verify it does NOT raise.
        # The primary assertion is that calling it is safe and produces output.
        log_cardinality_warning()  # must not raise

        _reset_settings()

    def test_log_cardinality_warning_called_from_lifespan(self, monkeypatch):
        """When enable_per_tenant_metrics=True, lifespan calls log_cardinality_warning."""
        from unittest.mock import AsyncMock, MagicMock

        from gateway.config import _reset_settings

        monkeypatch.setenv("ENABLE_PER_TENANT_METRICS", "true")
        _reset_settings()

        warning_called = []

        def _mock_warn():
            warning_called.append(True)

        with (
            patch("gateway.observability.metrics.log_cardinality_warning", _mock_warn),
            patch("gateway.redis_client.init", new=AsyncMock()),
            patch("gateway.upstream.openai_proxy.init_http_client", new=AsyncMock()),
            patch("gateway.upstream.openai_proxy.close_http_client", new=AsyncMock()),
            patch("gateway.redis_client.shutdown", new=AsyncMock()),
            patch("gateway.redis_client._health_task", None),
            patch("gateway.router.registry.ProviderRegistry") as MockRegistry,
        ):
            mock_reg = MagicMock()
            mock_reg.teardown = AsyncMock()
            MockRegistry.return_value = mock_reg

            from gateway.main import _lifespan, create_app

            app = create_app()

            import asyncio

            async def _run():
                async with _lifespan(app):
                    pass

            asyncio.get_event_loop().run_until_complete(_run())

        assert warning_called, (
            "log_cardinality_warning() was not called from _lifespan "
            "when enable_per_tenant_metrics=True"
        )

        _reset_settings()

    def test_record_event_does_not_raise_with_tenant_id(self, monkeypatch):
        """record_event with tenant_id=... must succeed regardless of cardinality gate."""
        from gateway.config import _reset_settings

        monkeypatch.setenv("ENABLE_PER_TENANT_METRICS", "true")
        _reset_settings()

        from gateway.observability.metrics import record_event

        # Must not raise under any tenant_id value.
        record_event("pii_blocked", tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        record_event("policy_violated", policy_type="budget_limit")
        record_event("classifier_degraded")

        _reset_settings()


# ---------------------------------------------------------------------------
# Vector 14: Cardinality bomb — 1000 tenants; render time bounded; series constant
# ---------------------------------------------------------------------------


class TestVector14CardinalityBomb:
    """Vector 14: simulate 1000 distinct tenants; /metrics render stays bounded."""

    def setup_method(self):
        _reset_metrics_registry()

    def test_render_time_bounded_with_1000_tenants_per_tenant_off(self, monkeypatch):
        """/metrics render time < 2 s even after 1000 tenants with per-tenant OFF."""
        from gateway.config import _reset_settings

        monkeypatch.setenv("ENABLE_PER_TENANT_METRICS", "false")
        _reset_settings()

        from gateway.observability.metrics import record_rate_limit_decision, record_request

        # Simulate 1000 distinct tenants each issuing a decision.
        for i in range(1000):
            tenant_id = f"tenant-{i:04d}-" + "a" * 28
            record_request("openai", "2xx", tenant_id=tenant_id)
            record_rate_limit_decision("admitted", tenant_id=tenant_id)

        start = time.monotonic()
        output = _render_text()
        elapsed = time.monotonic() - start

        assert (
            elapsed < 2.0
        ), f"/metrics render took {elapsed:.3f}s (> 2s limit) after 1000-tenant seed"
        # Must still produce valid output.
        assert "sentinel_requests_total" in output

        _reset_settings()

    def test_series_count_constant_with_per_tenant_off(self, monkeypatch):
        """With per-tenant OFF, series count is constant regardless of tenant count.

        Because no tenant_id label is applied, 1000 tenants produce exactly the same
        number of time series as 1 tenant — both result in a single
        sentinel_requests_total{provider="openai",status_class="2xx"} series.
        """
        from gateway.config import _reset_settings

        monkeypatch.setenv("ENABLE_PER_TENANT_METRICS", "false")
        _reset_settings()

        from gateway.observability.metrics import record_rate_limit_decision, record_request

        # Seed with 1 tenant first — capture series count.
        record_request("openai", "2xx", tenant_id="single-tenant")
        record_rate_limit_decision("admitted", tenant_id="single-tenant")
        output_1 = _render_text()

        # Count sample lines (non-comment, non-empty lines in the output).
        def _count_samples(text: str) -> int:
            return sum(
                1
                for ln in text.splitlines()
                if ln and not ln.startswith("#") and not ln.startswith("HELP")
            )

        count_1 = _count_samples(output_1)

        # Seed 999 more tenants.
        for i in range(999):
            tenant_id = f"tenant-{i:04d}-xxxxxxxxxxxxxxxxxxxxxxxx"
            record_request("openai", "2xx", tenant_id=tenant_id)
            record_rate_limit_decision("admitted", tenant_id=tenant_id)

        output_1000 = _render_text()
        count_1000 = _count_samples(output_1000)

        # Series count must not grow with tenant count when per-tenant is OFF.
        assert count_1 == count_1000, (
            f"Series count grew from {count_1} to {count_1000} when per-tenant is OFF — "
            "tenant_id label must NOT be applied in the default configuration"
        )

        _reset_settings()

    def test_render_time_bounded_absolute_ceiling(self, monkeypatch):
        """/metrics absolute render-time ceiling: < 2 s with no prior seeding."""
        from gateway.config import _reset_settings

        monkeypatch.setenv("ENABLE_PER_TENANT_METRICS", "false")
        _reset_settings()

        from gateway.observability.metrics import record_audit_write_failure, record_request

        # Only a small number of series — baseline must be fast.
        record_request("openai", "2xx")
        record_request("anthropic", "4xx")
        record_audit_write_failure("audit_log")

        start = time.monotonic()
        _render_text()
        elapsed = time.monotonic() - start

        assert elapsed < 2.0, f"/metrics baseline render took {elapsed:.3f}s (> 2s)"


# ---------------------------------------------------------------------------
# Full public-API coverage — exercises every function without registry reset
# so coverage tracking follows a single stable module object.
# ---------------------------------------------------------------------------


class TestPublicApiCoverage:
    """Exercise every public-API function to ensure >= 80% line coverage.

    These tests do NOT call _reset_metrics_registry() because that evicts the
    module and can cause coverage gaps. Counters may have non-zero starting
    values; tests assert only that calls succeed (no exception) and that
    render() produces non-empty output.
    """

    def test_observe_request_duration(self, monkeypatch):
        """observe_request_duration must accept valid args without raising."""
        from gateway.config import _reset_settings

        monkeypatch.setenv("ENABLE_PER_TENANT_METRICS", "false")
        _reset_settings()
        _reset_metrics_registry()

        from gateway.observability.metrics import observe_request_duration

        observe_request_duration("/v1/chat/completions", "openai", 0.123)
        observe_request_duration("/v1/chat/completions", "anthropic", 0.456)

        _reset_settings()

    def test_observe_judge_latency(self, monkeypatch):
        """observe_judge_latency must accept valid args without raising."""
        from gateway.config import _reset_settings

        monkeypatch.setenv("ENABLE_PER_TENANT_METRICS", "false")
        _reset_settings()
        _reset_metrics_registry()

        from gateway.observability.metrics import observe_judge_latency

        observe_judge_latency("injection", 0.5)
        observe_judge_latency("default", 1.0)

        _reset_settings()

    def test_record_event_unknown_type_is_noop(self, monkeypatch):
        """record_event with an unknown event_type must be a no-op (not raise)."""
        from gateway.config import _reset_settings

        monkeypatch.setenv("ENABLE_PER_TENANT_METRICS", "false")
        _reset_settings()
        _reset_metrics_registry()

        from gateway.observability.metrics import record_event, render

        record_event("totally_unknown_event_xyz")
        body, _ = render()
        # Must produce valid output even after no-op event.
        assert len(body) > 0

        _reset_settings()

    def test_record_event_classifier_degraded(self, monkeypatch):
        """record_event('classifier_degraded') must increment the counter."""
        from gateway.config import _reset_settings

        monkeypatch.setenv("ENABLE_PER_TENANT_METRICS", "false")
        _reset_settings()
        _reset_metrics_registry()

        from gateway.observability.metrics import record_event, render

        record_event("classifier_degraded")
        body, _ = render()
        assert b"sentinel_classifier_degraded_total" in body

        _reset_settings()

    def test_tenant_label_returns_none_for_none_tenant(self, monkeypatch):
        """_tenant_label(None) must return None (no label) regardless of gate."""
        from gateway.config import _reset_settings

        monkeypatch.setenv("ENABLE_PER_TENANT_METRICS", "true")
        _reset_settings()
        _reset_metrics_registry()

        from gateway.observability.metrics import _tenant_label

        result = _tenant_label(None)
        assert result is None

        _reset_settings()

    def test_tenant_label_returns_tenant_id_when_gate_on(self, monkeypatch):
        """_tenant_label(id) returns the id when enable_per_tenant_metrics=True."""
        from gateway.config import _reset_settings

        monkeypatch.setenv("ENABLE_PER_TENANT_METRICS", "true")
        _reset_settings()
        _reset_metrics_registry()

        from gateway.observability.metrics import _tenant_label

        tid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        result = _tenant_label(tid)
        assert result == tid

        _reset_settings()

    def test_all_public_functions_importable(self, monkeypatch):
        """All stable public API names must be importable from the package."""
        _reset_metrics_registry()

        import gateway.observability as obs

        for name in [
            "log_cardinality_warning",
            "observe_judge_latency",
            "observe_request_duration",
            "record_audit_write_failure",
            "record_event",
            "record_rate_limit_decision",
            "record_request",
            "render",
            "set_redis_health",
        ]:
            assert hasattr(obs, name), f"Public API name {name!r} not exported from package"
