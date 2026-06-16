"""Abstract base classes / protocols for inspection hooks (F-005, ADR-0007 §2).

Two hook phases exist:
  PreRequestHook   — runs after body validation, BEFORE the upstream proxy call.
  PostResponseHook — runs after upstream returns (or per chunk in streaming),
                     BEFORE the response is flushed to the client.

Each hook's inspect() method returns a DetectorResult carrying:
  action         — "pass" | "mask" | "block"
  event          — dict conforming to events.schema.json (None if no finding).
  modified_payload — the mutated content string (None if action != "mask").

The hook is responsible for ONLY building the result.  The registry executor
applies the action, emits the event via HookContext.emit(), and handles
sequencing/short-circuit/fail-safe.

Design note: we use abstract base classes rather than Protocol so that
subclasses benefit from isinstance() checks in the registry, which is useful
for introspection in tests.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Literal


@dataclass
class DetectorResult:
    """Result returned by a hook's inspect() call.

    action:
        "pass"  — no finding; forward content unchanged.
        "mask"  — finding detected; modified_payload carries the redacted content.
        "block" — finding detected; request must be blocked (no forward).
    event:
        Contract-valid event dict (without envelope fields — those are stamped by
        HookContext.emit()).  None if no event should be emitted (e.g. action="pass").
    modified_payload:
        The content after masking/redaction.  Only meaningful when action="mask".
        None for "pass" and "block" (blocked content is never forwarded).
    defer_emit:
        When True, the registry skips the normal context.emit() call for this
        result and stores (event, detector_slug) in context._deferred_event so
        the calling handler can emit AFTER validating the redacted output.
        Used exclusively by SecretOutboundHook non-stream/mask to prevent a
        dishonest secret_leaked event being recorded when the redacted body
        later fails json.loads and the handler raises internal_error instead.
    """

    action: Literal["pass", "mask", "block"]
    event: dict[str, Any] | None = None
    modified_payload: str | None = None
    defer_emit: bool = False


class PreRequestHook(ABC):
    """Abstract base for hooks that run before the upstream proxy call.

    inspect() receives the *current* request body content (which may have been
    mutated by an earlier hook in the chain) and the HookContext.

    IMPORTANT: Injection detection MUST score original_user_content from the
    context, NOT the content parameter, to avoid the mask-hides-injection
    vulnerability (ADR-0007 D1 / threat #7).
    """

    @property
    @abstractmethod
    def detector_slug(self) -> str:
        """Stable identifier for this detector (used as the event-budget key).

        Must match the agent_id slug pattern: ^[a-z0-9]+(-[a-z0-9]+)*$ ≤64 chars.
        """

    @abstractmethod
    async def inspect(self, content: str, context: Any) -> DetectorResult:
        """Inspect request content and return a DetectorResult.

        Parameters
        ----------
        content:
            The current (possibly already-mutated) user message content string.
            For injection: ALWAYS score context.original_user_content, not this.
        context:
            HookContext for this request.
        """


class PostResponseHook(ABC):
    """Abstract base for hooks that run on the upstream response before flush.

    For non-stream responses, inspect() receives the full response text.
    For stream responses, inspect() is called per-chunk via a bounded sliding
    window; content is (carried_tail + current_chunk) up to STREAM_INSPECT_BUFFER_BYTES.
    """

    @property
    @abstractmethod
    def detector_slug(self) -> str:
        """Stable identifier for this detector (used as the event-budget key)."""

    @abstractmethod
    async def inspect(self, content: str, context: Any) -> DetectorResult:
        """Inspect response content and return a DetectorResult.

        Parameters
        ----------
        content:
            The response text (full for non-stream; windowed buffer for stream).
        context:
            HookContext for this request.
        """
