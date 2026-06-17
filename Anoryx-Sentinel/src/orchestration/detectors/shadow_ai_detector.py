"""Shadow-AI event-emission primitives (F-005 seam, F-007 wired, ADR-0010 §5).

This module provides the emission primitives for the shadow-AI event variants.
It does NOT itself detect traffic — DETECTION lives in the egress monitor
(`gateway/middleware/egress_monitor.py`), which observes Sentinel's outbound
httpx calls and calls `emit_shadow_ai_outbound_event` here on a disallowed-provider
egress (F-007).

HONEST SCOPE STATEMENT (ADR-0010 §12.1)
---------------------------------------
F-007 detection covers egress through Sentinel's OWN httpx clients (OpenAI,
Anthropic) to the well-known provider hosts. It does NOT cover Bedrock/aioboto3
egress (deferred), custom proxy base_urls outside the host table, or traffic that
bypasses Sentinel entirely (network-layer — out of scope). The monitor detects +
audits; it does not block.

The F-005 `SHADOW_AI_EMISSION_ENABLED` opt-in gate has been REMOVED (F-007): the
detection seam is wired and production-ready. Both emit functions validate the
endpoint format (host/path only — no query/fragment/userinfo, D7) and append a
contract-valid, hash-chained event via the privileged session.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

import structlog

log = structlog.get_logger(__name__)

# Schema pattern for detected_endpoint: ^[^?#@\s]+$ (no query/fragment/userinfo).
_ENDPOINT_RE = re.compile(r"^[^?#@\s]+$")


def _strip_unsafe_url_components(raw: str) -> str:
    """Strip query string, fragment, and userinfo from a URL-like string.

    Defense-in-depth before schema validation.  The schema structurally forbids
    '?', '#', '@', and whitespace, but we strip them at the emitter level too
    (ADR-0007 §12 D7: "emitter strips before emission anyway").

    Returns only the scheme+host+path portion.
    """
    # Strip fragment
    raw = raw.split("#")[0]
    # Strip query string
    raw = raw.split("?")[0]
    # Strip userinfo (user:pass@host → host) — only in the authority component.
    # Simple heuristic: if '@' appears before any '/' in the path, strip up to '@'.
    if "@" in raw:
        at_pos = raw.index("@")
        slash_pos = raw.find("/", raw.find("//") + 2 if raw.startswith("//") else 0)
        if slash_pos == -1 or at_pos < slash_pos:
            raw = raw[at_pos + 1 :]
    return raw.strip()


async def emit_shadow_ai_event(
    *,
    context: Any,
    detected_endpoint: str,
    traffic_volume: int,
    first_seen_at: str | None = None,
) -> bool:
    """Emit a shadow_ai_detected event (the F-005 locked variant).

    This is an emission primitive: it does NOT detect anything; it only formats
    and appends the event.  Detection lives in the egress monitor (see module
    docstring) which calls emit_shadow_ai_outbound_event below.

    Parameters
    ----------
    context:
        HookContext for the request (provides tenant IDs, request_id, emit()).
    detected_endpoint:
        Host and optional path of the alleged shadow-AI endpoint.  Must not
        contain query params, fragments, or userinfo (enforced here + by schema).
    traffic_volume:
        Observed request count (integer, 0 ≤ n ≤ 1e9).
    first_seen_at:
        RFC3339 UTC timestamp of first observation.  Defaults to now.

    Returns True if the event was emitted, False if the endpoint is invalid.
    """
    # Strip unsafe URL components before validation.
    safe_endpoint = _strip_unsafe_url_components(detected_endpoint)

    # Validate endpoint format (schema pattern: ^[^?#@\s]+$).
    if not safe_endpoint or not _ENDPOINT_RE.match(safe_endpoint):
        log.warning(
            "orchestration.shadow_ai.invalid_endpoint",
            request_id=getattr(context, "request_id", "unknown"),
            # Never log the raw endpoint — may contain credentials in userinfo.
        )
        return False

    # Bound to schema maxLength 256.
    safe_endpoint = safe_endpoint[:256]

    # Validate traffic_volume bounds (schema: 0 ≤ n ≤ 1e9).
    safe_volume = max(0, min(int(traffic_volume), 1_000_000_000))

    # Build first_seen_at (RFC3339 UTC).
    if first_seen_at is None:
        first_seen_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    event = {
        "event_type": "shadow_ai_detected",
        "detected_endpoint": safe_endpoint,
        "traffic_volume": safe_volume,
        "first_seen_at": first_seen_at,
    }

    # The agent_id slug for shadow_ai emission (out-of-band, not a gateway hook).
    detector_slug = "defense"

    emitted = await context.emit(event, detector_slug=detector_slug)
    return emitted


async def emit_shadow_ai_outbound_event(
    *,
    egress: Any,
    provider: str,
    endpoint: str,
    traffic_volume: int = 1,
    first_seen_at: str | None = None,
) -> bool:
    """Emit a shadow_ai_detected_outbound event (F-007 egress detection, ADR-0010 §5).

    Called by the egress monitor when an outbound httpx call targets a provider
    that is NOT in the request's tenant allow-list. Builds a HookContext from the
    EgressContext so the event is stamped, hash-chained, and appended on the
    privileged session exactly like every other inspection event (R12). The same
    endpoint sanitization as emit_shadow_ai_event applies (host/path only, D7).

    Returns True if emitted, False if the endpoint is invalid.
    """
    from orchestration.context import HookContext

    safe_endpoint = _strip_unsafe_url_components(endpoint)
    if not safe_endpoint or not _ENDPOINT_RE.match(safe_endpoint):
        log.warning("orchestration.shadow_ai.invalid_outbound_endpoint", provider=provider)
        return False
    safe_endpoint = safe_endpoint[:256]
    safe_volume = max(0, min(int(traffic_volume), 1_000_000_000))
    if first_seen_at is None:
        first_seen_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")

    event = {
        "event_type": "shadow_ai_detected_outbound",
        "action_taken": "logged",
        "detected_endpoint": safe_endpoint,
        "traffic_volume": safe_volume,
        "first_seen_at": first_seen_at,
        # The disallowed provider the egress targeted (reuses the selected_provider column).
        "selected_provider": provider,
    }

    ctx = HookContext(
        tenant_context=egress.tenant_context,
        request_id=egress.request_id,
        original_user_content="",
        phase="post_response",
    )
    return await ctx.emit(event, detector_slug="defense")
