"""Budget-engine configuration — fail-loud secret resolution (no secret ever logged).

The engine publishes to the O-004 distribution seam:
``POST {distribution_url}/v1/policies/distributions`` authenticated with a Bearer
service token (``ORCH_SERVICE_TOKEN``; O-001 / ADR-0004 §interim — mTLS deferred to
O-008). When the engine is enabled, the URL + token are required and the loader fails
loud without them. When disabled (``DELTA_BUDGET_ENGINE_ENABLED=0``) the engine is inert
and neither is needed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# The O-004 receive-policy seam (ADR-0004 §C). Delta sends sign_on_behalf=false; O-004
# never signs (it is pass-through) — Delta is the signer.
DISTRIBUTION_PATH = "/v1/policies/distributions"

# Soft-threshold percentages (of the hard cap) at which an advisory warning is emitted.
# Advisory only — never enforcement (CONFIRM B, ADR-0005 §3.6).
_DEFAULT_WARNING_PCTS = (80, 95)


def _env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class EngineSettings:
    """Resolved engine settings. Constructed via :func:`load_settings` (fail-loud)."""

    enabled: bool
    distribution_url: str  # O-004 base URL (no trailing slash); "" when disabled
    service_token: str  # Bearer ORCH_SERVICE_TOKEN; "" when disabled
    distribution_path: str = DISTRIBUTION_PATH
    max_publish_attempts: int = 8
    publish_timeout_seconds: float = 5.0
    # Backoff base (seconds); attempt N waits base * 2**(N-1), capped.
    backoff_base_seconds: float = 2.0
    backoff_cap_seconds: float = 300.0
    soft_warning_pcts: tuple[int, ...] = _DEFAULT_WARNING_PCTS

    def distribution_endpoint(self) -> str:
        return self.distribution_url.rstrip("/") + self.distribution_path


def load_settings() -> EngineSettings:
    """Resolve engine settings from the environment.

    Fail-loud: when the engine is enabled, ``DELTA_ORCH_DISTRIBUTION_URL`` and
    ``ORCH_SERVICE_TOKEN`` MUST be set or this raises (a misconfigured enforcement path
    is a deployment error, not a silent degrade). Neither value is ever logged.
    """
    enabled = _env_flag("DELTA_BUDGET_ENGINE_ENABLED", True)
    url = os.environ.get("DELTA_ORCH_DISTRIBUTION_URL", "").strip()
    token = os.environ.get("ORCH_SERVICE_TOKEN", "").strip()

    if enabled:
        if not url:
            raise RuntimeError(
                "DELTA_ORCH_DISTRIBUTION_URL is not set. This is the O-004 base URL the "
                "budget engine publishes enforcement policies to. Set it, or disable the "
                "engine with DELTA_BUDGET_ENGINE_ENABLED=0. See Delta/.env.example."
            )
        if not token:
            raise RuntimeError(
                "ORCH_SERVICE_TOKEN is not set. This is the Bearer token authenticating the "
                "Delta->O-004 distribution seam. Delta refuses to enforce without it "
                "(fail-closed). See Delta/.env.example."
            )

    return EngineSettings(enabled=enabled, distribution_url=url, service_token=token)
