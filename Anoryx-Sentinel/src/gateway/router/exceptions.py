"""Router exception taxonomy (F-006, ADR-0008 §2.2 / §6).

Adapters NEVER raise raw httpx errors, raw botocore errors, or GatewayError.
They raise ProviderError(kind, *, status=None). The router's fallback loop maps
the kind to a retry/terminal disposition (the §6 matrix) and finally to a wire
ERROR_TABLE code. No ProviderError ever carries upstream body text (threat #10).

RoutingBlockedError is raised by the router itself (not an adapter) for the two
policy terminals that are NOT provider failures: allow-list deny and cost-ceiling
breach. Both collapse to policy_blocked (403) + a routing_decision audit event.
"""

from __future__ import annotations

from typing import Literal

# ADR-0008 §2.2 kinds. Retryability is decided by the router (§6), not here.
ProviderErrorKind = Literal[
    "transient",  # 5xx / connect / read-idle / overall timeout      -> RETRY
    "rate_limited",  # provider 429                                   -> RETRY
    "auth",  # provider 401/403 (our key/SigV4 rejected)             -> TERMINAL
    "content_policy",  # provider safety/content-filter 4xx          -> TERMINAL
    "bad_request",  # malformed-for-provider (e.g. n>1, translation) -> TERMINAL
    "parse",  # response/stream un-translatable to OpenAI shape      -> TERMINAL
]

# The kinds the router is permitted to retry against the next provider (§6).
RETRYABLE_KINDS: frozenset[str] = frozenset({"transient", "rate_limited"})


class ProviderError(Exception):
    """Raised by a provider adapter on any transport/HTTP/translation failure.

    kind drives the §6 fallback matrix. status (when known) is the upstream
    HTTP status for server-side logging ONLY — it is never returned to the
    client and the upstream BODY is never attached (threat #10).

    retry_after (seconds) is carried for rate_limited so the router can honor
    Retry-After capped to the remaining budget. It is advisory; the router caps
    it and never blocks longer than the shared deadline.
    """

    def __init__(
        self,
        kind: ProviderErrorKind,
        *,
        status: int | None = None,
        retry_after: float | None = None,
    ) -> None:
        self.kind = kind
        self.status = status
        self.retry_after = retry_after
        # Deliberately a generic message — NO upstream body text.
        super().__init__(f"ProviderError(kind={kind!r}, status={status!r})")

    @property
    def is_retryable(self) -> bool:
        return self.kind in RETRYABLE_KINDS


class RoutingBlockedError(Exception):
    """Raised by the router for a TERMINAL policy block (NOT a provider failure).

    reason is one of:
      - "allowlist": provider not in the tenant allow-list (§6, vector #2)
      - "cost": pre-request or stream-time cost-ceiling breach (§6, vector #3)

    Both map to wire policy_blocked (403) + a routing_decision audit event.
    The router NEVER silently falls back past an allow-list deny or cost block.
    """

    def __init__(self, reason: Literal["allowlist", "cost"], *, detail: str = "") -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(f"RoutingBlockedError(reason={reason!r})")
