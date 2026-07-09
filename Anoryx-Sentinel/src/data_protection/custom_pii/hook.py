"""CustomPiiHook — per-tenant custom PII PreRequestHook (F-028, ADR-0034).

Inserted into the F-005 pre-request chain AFTER the built-in PIIHook (order:
SecretInbound -> Injection -> PII -> CustomPII). Loads the calling tenant's
active custom regex patterns (hot-reload TTL cache), scans the current content
with the ReDoS-safe engine, and masks / tokenizes / blocks — emitting the SAME
contract-conformant `pii_blocked` event type the built-in detector uses (no new
events.schema.json type needed, so no contracts/ change).

Fail posture (deliberate, ADR-0034 "fail-degraded, not fail-closed"): custom
PII is an OPTIONAL, additive, per-tenant augmentation that runs AFTER the
MANDATORY fail-closed F-005 layer (secret/injection/PII), which already
inspected and can block this same content. So if the tenant's pattern STORE is
transiently unreachable, this hook DEGRADES to pass-through (loud ERROR log +
metric) rather than fail-closed-blocking 100% of the tenant's traffic — a
custom-table blip must not be a self-inflicted gateway outage. A genuine
pattern MATCH still fails closed (mask/block). A per-pattern match timeout is
isolated (one pathological pattern is skipped + logged; the request survives).
"""

from __future__ import annotations

from typing import Any

import structlog

from data_protection.custom_pii.engine import scan
from data_protection.custom_pii.loader import CustomPiiPatternLoader
from data_protection.custom_pii.masking import apply_masks
from orchestration.hooks.base import DetectorResult, PreRequestHook

log = structlog.get_logger(__name__)

# Process-wide loader singleton so the per-tenant TTL cache persists across
# requests. Reset via _reset_loader_for_testing().
_loader: CustomPiiPatternLoader | None = None


def _get_loader(ttl_seconds: float) -> CustomPiiPatternLoader:
    global _loader
    if _loader is None:
        _loader = CustomPiiPatternLoader(ttl_seconds=ttl_seconds)
    return _loader


def _reset_loader_for_testing(loader: CustomPiiPatternLoader | None = None) -> None:
    global _loader
    _loader = loader


def _record_load_failure_metric(tenant_id: str) -> None:
    """Emit a metric on a custom-PII pattern-store load failure (best-effort).

    Isolated + swallow-all so instrumentation never affects the pass-through
    decision (mirrors HookContext.emit's metric discipline)."""
    try:
        from gateway.observability import metrics as _metrics  # noqa: PLC0415

        _metrics.record_audit_write_failure(component="custom-pii-load")
    except Exception:
        pass


def _confidence_to_severity(score: float) -> str:
    """Same mapping as the built-in PII detector (events.schema.json severity)."""
    if score >= 0.90:
        return "critical"
    if score >= 0.80:
        return "high"
    if score >= 0.70:
        return "medium"
    return "low"


def _action_taken_for(action: str) -> str:
    return {"mask": "masked", "tokenize": "tokenized", "block": "blocked"}.get(action, "masked")


def _pattern_name_safe(name: str) -> str:
    import re  # noqa: PLC0415

    return re.sub(r"[^a-zA-Z0-9_]", "_", name).lower()[:128]


class CustomPiiHook(PreRequestHook):
    """Pre-request hook applying a tenant's client-defined custom PII patterns."""

    detector_slug = "data-protection"

    def __init__(self, settings: Any) -> None:
        # settings is the CustomPiiSettings object.
        self._settings = settings

    async def inspect(self, content: str, context: Any) -> DetectorResult:
        if not content:
            return DetectorResult(action="pass")

        tenant_id = context.tenant_context.tenant_id
        loader = _get_loader(self._settings.custom_pii_cache_ttl_seconds)

        try:
            patterns = await loader.load(tenant_id)
        except Exception:
            # Fail-DEGRADED (NOT fail-closed): the MANDATORY F-005 layer already
            # ran and can block; blocking all of this tenant's traffic because
            # the OPTIONAL custom-pattern store had a transient error would be a
            # self-inflicted outage. Log loudly + emit a metric, then pass
            # through (built-in coverage still applied). A genuine match below
            # still fails closed.
            log.error("custom_pii.pattern_load_failed", tenant_id=tenant_id)
            _record_load_failure_metric(tenant_id)
            return DetectorResult(action="pass")

        if not patterns:
            return DetectorResult(action="pass")

        inspected = content[: self._settings.custom_pii_max_inspect_chars]
        spans, timed_out = scan(
            inspected, patterns, timeout_seconds=self._settings.custom_pii_match_timeout_seconds
        )
        if timed_out:
            log.warning("custom_pii.pattern_match_timeout", tenant_id=tenant_id, patterns=timed_out)
        if not spans:
            return DetectorResult(action="pass")

        default_action = self._settings.custom_pii_action
        # Resolve each span's effective action (per-pattern override > default).
        # A security control fails STRICT: if ANY matched pattern resolves to
        # "block", the whole request blocks regardless of other matches.
        span_actions = {(s.action or default_action) for s in spans}
        block_triggered = "block" in span_actions

        # Primary finding = highest score (drives the emitted event's severity /
        # reported pattern_name).
        primary = max(spans, key=lambda s: s.score)
        effective_action = "block" if block_triggered else default_action

        event = {
            "event_type": "pii_blocked",
            "pattern_name": _pattern_name_safe(primary.name),
            "severity": _confidence_to_severity(primary.score),
            "action_taken": _action_taken_for(effective_action),
        }

        if block_triggered:
            return DetectorResult(action="block", event=event, modified_payload=None)

        # No block: mask or tokenize ALL spans with the default action. (Mixed
        # mask/tokenize overrides collapse to the tenant default here — a
        # per-span mask-vs-tokenize distinction is not worth the offset-tracking
        # complexity; block is the only override that changes the outcome.)
        masked = apply_masks(inspected, spans, action=default_action)
        if len(content) > self._settings.custom_pii_max_inspect_chars:
            masked = masked + content[self._settings.custom_pii_max_inspect_chars :]
        return DetectorResult(action="mask", event=event, modified_payload=masked)
