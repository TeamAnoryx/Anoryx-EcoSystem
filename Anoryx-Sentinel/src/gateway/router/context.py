"""RoutingContext — router-internal carrier (F-006, ADR-0008 §2.1).

NOT a wire type. Carries the per-attempt context an adapter needs:
  - request_id          : the ONE canonical request_id (correlation)
  - resolved_provider   : provider name for THIS attempt
  - resolved_model      : the model the client asked for (echoed; never a secret)
  - remaining_budget    : seconds left in the ONE shared request_timeout_seconds
                          wall-clock budget (decremented per attempt, §6)
  - attempt_index       : 0 = primary, 1 = first fallback, ...

LOW-3 (remediation): the former `client` field was always None — every adapter
holds its own client (OpenAI/Anthropic via the module-global httpx client built
by init_http_client; Bedrock builds a config-pinned aioboto3 client per attempt).
The dead field has been removed rather than populated; adapters never read it.

deadline() exposes the monotonic wall-clock deadline so an adapter can pass a
correct overall_timeout to its transport without re-deriving it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class RoutingContext:
    """Per-attempt routing context handed to a provider adapter."""

    request_id: str
    resolved_provider: str
    resolved_model: str
    remaining_budget: float
    attempt_index: int = 0
    # Monotonic start of THIS attempt; used to compute the live deadline.
    _attempt_start: float = 0.0

    def __post_init__(self) -> None:
        if not self._attempt_start:
            self._attempt_start = time.monotonic()

    def time_left(self) -> float:
        """Seconds left in this attempt's slice of the shared budget (>= 0)."""
        elapsed = time.monotonic() - self._attempt_start
        return max(0.0, self.remaining_budget - elapsed)
