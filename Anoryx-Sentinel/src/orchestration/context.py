"""HookContext — per-request inspection state and event-emit helper (F-005, ADR-0007 D8).

HookContext is created once per request inside create_chat_completion, passed to
every hook in the chain, and discarded after the request completes.

Key responsibilities:
  1. Carry the four server-resolved stable IDs (never from client headers).
  2. Hold the immutable original_user_content snapshot taken before any masking
     (ADR-0007 D1 masking-vs-injection rule, threat #7).
  3. Enforce the per-detector event budget (ADR-0007 D4, threat #9).
  4. Provide emit() — appends a contract-valid event via get_privileged_session()
     and stamps all required fields automatically.

The phase field indicates whether we are in the pre-request or post-response
phase, so hooks can assert they are called in the correct context.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

import structlog

from gateway.context import TenantContext
from persistence.database import get_privileged_session
from persistence.repositories.audit_log_repository import AuditLogRepository

log = structlog.get_logger(__name__)

# Slug for the data-protection component (PII / secret detector).
AGENT_DATA_PROTECTION = "data-protection"
# Slug for the defense component (injection detector).
AGENT_DEFENSE = "defense"


@dataclass
class HookContext:
    """Per-request inspection context passed to each hook.

    Fields
    ------
    tenant_context:
        The four server-resolved stable IDs + virtual_key_id.  IMMUTABLE.
    request_id:
        The one canonical request_id from request.state.request_id.
    original_user_content:
        Immutable snapshot of all role="user" messages joined with "\\n",
        captured BEFORE any PII masking.  Injection always scores this snapshot
        (ADR-0007 D1 / threat #7).
    phase:
        "pre_request" or "post_response".
    _event_budget:
        Per-detector remaining event allowance (D4).  Keys are detector slugs.
    _events_per_detector_cap:
        Cap value; set at construction time from OrchestrationSettings.
    """

    tenant_context: TenantContext
    request_id: str
    original_user_content: str
    phase: Literal["pre_request", "post_response"]
    _events_per_detector_cap: int = field(default=10)
    _event_budget: dict[str, int] = field(default_factory=dict)
    # F-007 (ADR-0010 §2): optional judge wiring threaded by the gateway so the
    # injection detector's LLM-as-judge step can route through the F-006 provider
    # layer (R5). None when the classifier is disabled or in non-gateway/test paths
    # → the detector falls back to regex (fail-safe, R9).
    provider_registry: Any = None
    gateway_settings: Any = None

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _budget_for(self, detector_slug: str) -> int:
        """Return remaining event budget for a detector, initialising on first call."""
        if detector_slug not in self._event_budget:
            self._event_budget[detector_slug] = self._events_per_detector_cap
        return self._event_budget[detector_slug]

    def _decrement_budget(self, detector_slug: str) -> None:
        if detector_slug not in self._event_budget:
            self._event_budget[detector_slug] = self._events_per_detector_cap
        self._event_budget[detector_slug] = max(0, self._event_budget[detector_slug] - 1)

    def budget_exhausted(self, detector_slug: str) -> bool:
        """Return True if the event budget for this detector is exhausted (D4)."""
        return self._budget_for(detector_slug) <= 0

    # -------------------------------------------------------------------------
    # Event stamping and emission
    # -------------------------------------------------------------------------

    def _stamp_event(self, event: dict[str, Any], *, detector_slug: str) -> dict[str, Any]:
        """Return a new event dict with all required envelope fields stamped.

        Stamps: tenant_id, team_id, project_id, agent_id (detector_slug),
        event_id (uuid4), event_timestamp (RFC3339 UTC), request_id.

        Per ADR-0007 D8: agent_id is the emitting component slug, NOT the model
        name.  The caller must pass detector_slug (e.g. "data-protection",
        "defense").

        Returns a new dict (immutable pattern — original is not mutated).
        """
        now_utc = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        stamped = dict(event)
        stamped["tenant_id"] = self.tenant_context.tenant_id
        stamped["team_id"] = self.tenant_context.team_id
        stamped["project_id"] = self.tenant_context.project_id
        stamped["agent_id"] = detector_slug
        stamped["event_id"] = str(uuid.uuid4())
        stamped["event_timestamp"] = now_utc
        stamped["request_id"] = self.request_id
        return stamped

    async def emit(self, event: dict[str, Any], *, detector_slug: str) -> bool:
        """Stamp and append an inspection event to the audit log.

        Enforces the per-detector event budget (D4, threat #9).  If the budget
        is exhausted for this detector the event is DROPPED (not appended) but
        the action (mask/block) is always applied — only the event volume is
        bounded.

        Returns True if the event was appended, False if it was coalesced
        (budget exhausted).

        NEVER raises: any append failure is logged at ERROR level and swallowed
        so a DB hiccup does not convert a detection into a pass-through.
        """
        if self.budget_exhausted(detector_slug):
            log.warning(
                "orchestration.event_cap_reached",
                detector=detector_slug,
                request_id=self.request_id,
            )
            return False

        stamped = self._stamp_event(event, detector_slug=detector_slug)
        self._decrement_budget(detector_slug)

        try:
            async with get_privileged_session() as session:
                async with session.begin():
                    await AuditLogRepository(session).append(stamped)

            log.info(
                "orchestration.event_appended",
                event_type=stamped.get("event_type"),
                event_id=stamped.get("event_id"),
                request_id=self.request_id,
            )
            return True
        except Exception:
            log.error(
                "orchestration.event_append_failed",
                detector=detector_slug,
                request_id=self.request_id,
                # Never log event content — may contain tenant context.
            )
            return False


def build_hook_context(
    *,
    tenant_context: TenantContext,
    request_id: str,
    validated_messages: list[Any],
    phase: Literal["pre_request", "post_response"],
    events_per_detector_cap: int = 10,
    provider_registry: Any = None,
    gateway_settings: Any = None,
) -> HookContext:
    """Factory: build a HookContext from gateway request state.

    Extracts and joins all role="user" message content into the immutable
    original_user_content snapshot (ADR-0007 D1 / threat #3 — concatenate all
    user messages so split-across-messages injection is scored together).
    """
    user_parts: list[str] = []
    for msg in validated_messages:
        if getattr(msg, "role", None) == "user":
            content = getattr(msg, "content", "") or ""
            # FIX-5: guard against non-string content (future OpenAI content-array
            # format returns list/dict instead of str).  Coerce defensively so the
            # snapshot is always a clean string and downstream hooks can run.
            # We serialize (not drop) non-string content so adversarial payloads
            # embedded in structured content are still inspected (fail-safe).
            if not isinstance(content, str):
                content = str(content)
            user_parts.append(content)
    original_user_content = "\n".join(user_parts)

    return HookContext(
        tenant_context=tenant_context,
        request_id=request_id,
        original_user_content=original_user_content,
        phase=phase,
        _events_per_detector_cap=events_per_detector_cap,
        provider_registry=provider_registry,
        gateway_settings=gateway_settings,
    )
