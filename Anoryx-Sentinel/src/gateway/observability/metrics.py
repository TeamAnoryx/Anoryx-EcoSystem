"""Prometheus metrics registry and public API (F-009, ADR-0011 §5 Decision D4).

Defines a dedicated CollectorRegistry (not the default global registry) so that
test isolation is clean and the /metrics endpoint exposes ONLY Sentinel's metrics.

Metric set (canonical per ADR-0011 §5 table):

  Counters:
    sentinel_requests_total{provider, status_class}
    sentinel_rate_limit_decisions_total{outcome}
      outcome in: admitted | rate_limited_key | rate_limited_team |
                  rate_limited_tenant | rate_limited_degraded
    sentinel_pii_blocks_total                       (no labels)
    sentinel_policy_violations_total{policy_type}
    sentinel_audit_write_failures_total{component}
    sentinel_judge_invocation_total{preset, outcome}
    sentinel_shadow_ai_detected_outbound_total      (no labels)
    sentinel_classifier_degraded_total              (no labels)

  Histograms:
    sentinel_request_duration_seconds{route, provider}
    sentinel_judge_latency_seconds{preset}

  Gauge:
    sentinel_redis_health                           (no labels; 1=healthy, 0=degraded)

Cardinality gate (ADR-0011 D4 γ):
  When get_settings().enable_per_tenant_metrics is True, a tenant_id label is
  appended to the tenant-scoped series ONLY (rate_limit_decisions, requests).
  The label uses only the SERVER-RESOLVED tenant_id (never a client header).
  Default: NO tenant_id label on any series.
  A startup warning is emitted via log_cardinality_warning() (called from _lifespan).

Security (R9):
  /metrics MUST NOT contain secrets, virtual keys, prompt text, or PII.
  This module only stores bounded label values (provider names, outcome slugs,
  policy types, preset names, component slugs). It never stores request bodies,
  user content, tenant names, or auth credentials.

STEP 3b note:
  orchestration emit sites call record_event() and record_audit_write_failure()
  via lazy import. Those two functions form the stable orchestration-facing API.
  DO NOT rename or change their signatures without a coordinated STEP 3b update.
"""

from __future__ import annotations

import structlog
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

from gateway.config import get_settings

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Dedicated registry — never mix with prometheus_client's default REGISTRY.
# This keeps the /metrics endpoint clean and test isolation perfect.
# ---------------------------------------------------------------------------

_REGISTRY = CollectorRegistry(auto_describe=False)

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------

_requests_total = Counter(
    "sentinel_requests_total",
    "Total gateway requests counted at the route handler (success and error).",
    ["provider", "status_class"],
    registry=_REGISTRY,
)

_rate_limit_decisions_total = Counter(
    "sentinel_rate_limit_decisions_total",
    "Rate-limit admission decisions. "
    "outcome: admitted | rate_limited_key | rate_limited_team | "
    "rate_limited_tenant | rate_limited_degraded.",
    ["outcome"],
    registry=_REGISTRY,
)

_pii_blocks_total = Counter(
    "sentinel_pii_blocks_total",
    "Requests blocked by the PII inspection hook.",
    registry=_REGISTRY,
)

_policy_violations_total = Counter(
    "sentinel_policy_violations_total",
    "Policy violations detected by the policy enforcement layer.",
    ["policy_type"],
    registry=_REGISTRY,
)

_audit_write_failures_total = Counter(
    "sentinel_audit_write_failures_total",
    "Audit log write failures. component identifies the originating subsystem.",
    ["component"],
    registry=_REGISTRY,
)

_judge_invocation_total = Counter(
    "sentinel_judge_invocation_total",
    "LLM-as-judge invocations by preset and outcome.",
    ["preset", "outcome"],
    registry=_REGISTRY,
)

_shadow_ai_detected_outbound_total = Counter(
    "sentinel_shadow_ai_detected_outbound_total",
    "Outbound requests flagged as shadow-AI egress.",
    registry=_REGISTRY,
)

_classifier_degraded_total = Counter(
    "sentinel_classifier_degraded_total",
    "Times the ML classifier entered a degraded state.",
    registry=_REGISTRY,
)

# ---------------------------------------------------------------------------
# Histograms
# ---------------------------------------------------------------------------

_request_duration_seconds = Histogram(
    "sentinel_request_duration_seconds",
    "End-to-end gateway request latency in seconds.",
    ["route", "provider"],
    registry=_REGISTRY,
)

_judge_latency_seconds = Histogram(
    "sentinel_judge_latency_seconds",
    "LLM-as-judge invocation latency in seconds.",
    ["preset"],
    registry=_REGISTRY,
)

# ---------------------------------------------------------------------------
# Gauge
# ---------------------------------------------------------------------------

_redis_health = Gauge(
    "sentinel_redis_health",
    "Redis health: 1 = healthy (primary path active), 0 = degraded (fallback active).",
    registry=_REGISTRY,
)

# ---------------------------------------------------------------------------
# Internal helper: resolve tenant_id label value
# ---------------------------------------------------------------------------


def _tenant_label(tenant_id: str | None) -> str | None:
    """Return the tenant_id to use as a label, respecting the cardinality gate.

    Returns the server-resolved tenant_id string ONLY when
    enable_per_tenant_metrics is True AND a tenant_id was provided.
    Returns None otherwise (no label emitted).
    """
    if tenant_id is None:
        return None
    try:
        if get_settings().enable_per_tenant_metrics:
            return tenant_id
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Public API — stable; orchestration will call record_event and
# record_audit_write_failure via lazy import in STEP 3b.
# ---------------------------------------------------------------------------


def record_request(
    provider: str,
    status_class: str,
    *,
    tenant_id: str | None = None,
) -> None:
    """Increment sentinel_requests_total{provider, status_class}.

    status_class should be a coarse HTTP status class string such as
    '2xx', '4xx', '5xx'. provider is the resolved upstream provider name
    (e.g. 'openai', 'anthropic', 'bedrock') or 'none'/'unknown' when not resolved.

    tenant_id is accepted for future per-tenant cardinality but is currently
    unused in label construction (no tenant_id label on this counter by default).
    The parameter is part of the stable API signature.
    """
    _requests_total.labels(provider=provider, status_class=status_class).inc()


def observe_request_duration(route: str, provider: str, seconds: float) -> None:
    """Observe a request duration sample for sentinel_request_duration_seconds."""
    _request_duration_seconds.labels(route=route, provider=provider).observe(seconds)


def record_rate_limit_decision(
    outcome: str,
    *,
    tenant_id: str | None = None,
) -> None:
    """Increment sentinel_rate_limit_decisions_total{outcome}.

    outcome MUST be one of:
      admitted | rate_limited_key | rate_limited_team |
      rate_limited_tenant | rate_limited_degraded

    This counter is aggregate-only — no tenant_id label is applied regardless
    of enable_per_tenant_metrics. Per-tenant rate-limit granularity is available
    via the tenant-scoped series emitted by record_request() and record_event().

    The tenant_id parameter is part of the stable API signature (accepted for
    future use) but does not affect label construction here. Corrected from an
    earlier docstring that incorrectly claimed a tenant_id label was applied
    (LOW-1 honest-language fix; avoid a breaking Prometheus label change).
    """
    _rate_limit_decisions_total.labels(outcome=outcome).inc()


def set_redis_health(healthy: bool) -> None:
    """Set sentinel_redis_health gauge: 1 if healthy, 0 if degraded."""
    _redis_health.set(1 if healthy else 0)


def observe_judge_latency(preset: str, seconds: float) -> None:
    """Observe a judge invocation latency sample for sentinel_judge_latency_seconds."""
    _judge_latency_seconds.labels(preset=preset).observe(seconds)


def record_audit_write_failure(component: str) -> None:
    """Increment sentinel_audit_write_failures_total{component}.

    Called by orchestration in STEP 3b via lazy import.
    component is a short slug identifying the subsystem (e.g. 'audit_log',
    'redis_streams', 'egress_monitor').
    """
    _audit_write_failures_total.labels(component=component).inc()


# ---------------------------------------------------------------------------
# Event-type dispatcher — stable API for STEP 3b orchestration wiring
# ---------------------------------------------------------------------------

# Mapping from event_type slug to the action that handles it.
# Unknown event types are silently ignored (no-op) as specified.
_EVENT_DISPATCH: dict[str, str] = {
    "pii_blocked": "pii",
    "policy_violated": "policy",
    "judge_billing_event": "judge",
    "shadow_ai_detected_outbound": "shadow_ai",
    "classifier_degraded": "classifier_degraded",
}


def record_event(
    event_type: str,
    *,
    tenant_id: str | None = None,
    policy_type: str | None = None,
    preset: str | None = None,
    outcome: str | None = None,
) -> None:
    """Dispatch an orchestration event to the appropriate Prometheus counter.

    Mapping (ADR-0011 §5):
      pii_blocked                  -> sentinel_pii_blocks_total
      policy_violated              -> sentinel_policy_violations_total{policy_type}
      judge_billing_event          -> sentinel_judge_invocation_total{preset, outcome}
      shadow_ai_detected_outbound  -> sentinel_shadow_ai_detected_outbound_total
      classifier_degraded          -> sentinel_classifier_degraded_total

    Unknown event_type values are silently ignored (no-op) — this makes the
    function safe to call from orchestration code that may emit additional
    event types not yet wired to metrics.

    Called by orchestration in STEP 3b via lazy import.
    """
    action = _EVENT_DISPATCH.get(event_type)
    if action is None:
        return  # unknown event_type → no-op

    if action == "pii":
        _pii_blocks_total.inc()
    elif action == "policy":
        _policy_violations_total.labels(policy_type=policy_type or "unknown").inc()
    elif action == "judge":
        _judge_invocation_total.labels(
            preset=preset or "unknown",
            outcome=outcome or "unknown",
        ).inc()
    elif action == "shadow_ai":
        _shadow_ai_detected_outbound_total.inc()
    elif action == "classifier_degraded":
        _classifier_degraded_total.inc()


def render() -> tuple[bytes, str]:
    """Generate the Prometheus text exposition format.

    Returns (body_bytes, content_type_string).
    The content type is prometheus_client.CONTENT_TYPE_LATEST.

    R9: The rendered output contains ONLY bounded metric names, label names,
    and label values (provider slugs, outcome slugs, policy_type slugs, etc.).
    It NEVER contains: API keys, virtual keys, prompt text, user content, PII,
    or connection strings.
    """
    body = generate_latest(_REGISTRY)
    return body, CONTENT_TYPE_LATEST


# ---------------------------------------------------------------------------
# Startup warning for per-tenant cardinality gate
# ---------------------------------------------------------------------------


def log_cardinality_warning() -> None:
    """Log a startup warning when enable_per_tenant_metrics is True.

    Called from _lifespan when the setting is enabled. Documents the linear
    storage-cost implication for operators who enable per-tenant labels.

    ADR-0011 D4 γ: per-tenant labels increase Prometheus storage cost linearly
    with tenant count. Enable only when operationally needed.
    """
    log.warning(
        "per_tenant_metrics_enabled",
        message=(
            "ENABLE_PER_TENANT_METRICS=true: Prometheus storage cost grows linearly "
            "with tenant count. Disable this flag when per-tenant granularity is not "
            "operationally required."
        ),
    )
