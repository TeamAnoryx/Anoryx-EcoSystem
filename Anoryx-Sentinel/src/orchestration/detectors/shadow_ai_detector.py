"""Shadow-AI event-emission primitive (F-005, ADR-0007 §13, threat #10).

HONEST SCOPE STATEMENT
-----------------------
F-005 does NOT detect shadow-AI traffic.  This module provides ONLY the event-
emission primitive for a shadow_ai_detected event.  In F-005:
  - There is no network egress monitoring.
  - There is no DNS inspection.
  - There is no traffic analysis to endpoints that bypass the gateway.
  - The primitive is gated behind SHADOW_AI_EMISSION_ENABLED (default false).

When the flag is enabled, an out-of-band caller (NOT wired in F-005) can invoke
emit_shadow_ai_event() with a host/path endpoint, a traffic volume, and a
first_seen_at timestamp.  The function validates the endpoint format
(ADR-0007 D7 — host/path only, no query/fragment/userinfo) and appends a
contract-valid shadow_ai_detected event to the audit log.

Real shadow-AI detection (network egress monitoring) is deferred to F-007.
Operators MUST NOT interpret this module's presence as evidence that shadow-AI
traffic is being detected.  It is not.  F-005 delivers the event shape and the
emission seam only.
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
    """Emit a shadow_ai_detected event (gated on SHADOW_AI_EMISSION_ENABLED).

    This is an out-of-band primitive: it does NOT detect anything; it only
    formats and appends the event.  F-005 contains no detection logic for
    shadow-AI traffic (see module docstring).

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

    Returns True if the event was emitted, False if gated off or invalid.
    """
    from orchestration.config import get_orchestration_settings

    settings = get_orchestration_settings()
    if not settings.shadow_ai_emission_enabled:
        log.debug(
            "orchestration.shadow_ai.emission_gated_off",
            request_id=getattr(context, "request_id", "unknown"),
        )
        return False

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
