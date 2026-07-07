"""Kill-switch configuration — fail-loud secret resolution (no secret ever logged).

Publishes to the SAME O-004 distribution seam as the D-005 budget engine
(``POST {distribution_url}/v1/policies/distributions``, Bearer ``ORCH_SERVICE_TOKEN``) —
it is one seam, two independent decision sources. When the kill-switch is enabled, the
URL + token are required and the loader fails loud without them, exactly like
``budget_engine.config``. When disabled (``DELTA_KILL_SWITCH_ENABLED=0``) the kill-switch
is inert and neither is needed.

The anomalous-single-transaction ceiling (``DELTA_KILL_SWITCH_MAX_TX_COST_CENTS``) is
OPTIONAL and unset by default: with no ceiling configured, the anomaly trigger never
fires (opt-in, never a silent new restriction on an existing tenant — ADR-0006 §2 fork 2).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# The O-004 receive-policy seam — identical path to the D-005 budget engine (one seam).
DISTRIBUTION_PATH = "/v1/policies/distributions"


def _env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class KillSwitchSettings:
    """Resolved kill-switch settings. Constructed via :func:`load_settings` (fail-loud)."""

    enabled: bool
    distribution_url: str  # O-004 base URL (no trailing slash); "" when disabled
    service_token: str  # Bearer ORCH_SERVICE_TOKEN; "" when disabled
    distribution_path: str = DISTRIBUTION_PATH
    max_publish_attempts: int = 8
    publish_timeout_seconds: float = 5.0
    backoff_base_seconds: float = 2.0
    backoff_cap_seconds: float = 300.0
    # None = the anomalous-single-transaction trigger is disabled (opt-in).
    max_single_tx_cost_cents: int | None = None

    def distribution_endpoint(self) -> str:
        return self.distribution_url.rstrip("/") + self.distribution_path


def load_settings() -> KillSwitchSettings:
    """Resolve kill-switch settings from the environment.

    Fail-loud: when enabled, ``DELTA_ORCH_DISTRIBUTION_URL`` and ``ORCH_SERVICE_TOKEN``
    MUST be set (same requirement, same seam, as the D-005 budget engine) or this raises.
    ``DELTA_KILL_SWITCH_MAX_TX_COST_CENTS``, if set, must be a non-negative integer;
    an invalid value is a config error (fail-loud), never silently ignored.
    """
    enabled = _env_flag("DELTA_KILL_SWITCH_ENABLED", True)
    url = os.environ.get("DELTA_ORCH_DISTRIBUTION_URL", "").strip()
    token = os.environ.get("ORCH_SERVICE_TOKEN", "").strip()

    if enabled:
        if not url:
            raise RuntimeError(
                "DELTA_ORCH_DISTRIBUTION_URL is not set. This is the O-004 base URL the "
                "kill-switch publishes emergency-block policies to (the same seam the D-005 "
                "budget engine uses). Set it, or disable the kill-switch with "
                "DELTA_KILL_SWITCH_ENABLED=0. See Delta/.env.example."
            )
        if not token:
            raise RuntimeError(
                "ORCH_SERVICE_TOKEN is not set. This is the Bearer token authenticating the "
                "Delta->O-004 distribution seam. The kill-switch refuses to enforce without "
                "it (fail-closed). See Delta/.env.example."
            )

    raw_ceiling = os.environ.get("DELTA_KILL_SWITCH_MAX_TX_COST_CENTS", "").strip()
    max_single_tx_cost_cents: int | None = None
    if raw_ceiling:
        try:
            max_single_tx_cost_cents = int(raw_ceiling)
        except ValueError as exc:
            raise RuntimeError(
                "DELTA_KILL_SWITCH_MAX_TX_COST_CENTS is set but is not an integer "
                f"({raw_ceiling!r}). Unset it to disable the anomalous-single-transaction "
                "trigger, or set it to a non-negative integer cent ceiling."
            ) from exc
        if max_single_tx_cost_cents < 0:
            raise RuntimeError("DELTA_KILL_SWITCH_MAX_TX_COST_CENTS must be non-negative.")

    return KillSwitchSettings(
        enabled=enabled,
        distribution_url=url,
        service_token=token,
        max_single_tx_cost_cents=max_single_tx_cost_cents,
    )
