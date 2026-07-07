"""Allocation-admin configuration — fail-loud secret resolution (no secret ever logged).

Mirrors the Sentinel F-012a break-glass pattern (``Anoryx-Sentinel/src/admin/auth.py``):
a single deploy-injected bearer token, constant-time compared, no tenant fallback. No
SSO/operator-session tier is built here (Sentinel's ADR-0017 tier) — a lean, single
break-glass credential is the right STEP-0 fork for a first admin surface with no
existing operator-identity system in Delta to federate with (banked rule #13).
"""

from __future__ import annotations

import os
from dataclasses import dataclass

ADMIN_TOKEN_ENV = "DELTA_ADMIN_TOKEN"  # noqa: S105 — env var NAME, not a secret

# Reserved actor slug for admin-attributed change-history rows when the caller
# supplies no more specific ``actor`` (contracts/ids.md-style honest attribution).
ADMIN_PRINCIPAL = "delta-admin"


@dataclass(frozen=True)
class AllocationAdminSettings:
    """Resolved allocation-admin settings. Constructed via :func:`load_settings`."""

    admin_token: str


def load_settings() -> AllocationAdminSettings:
    """Resolve allocation-admin settings from the environment. Fail-loud when unset.

    No admin surface without a configured token (fail-closed auth) — mirrors
    ``delta.ingest.config.load_settings`` and ``delta.kill_switch.config.load_settings``.
    """
    token = os.environ.get(ADMIN_TOKEN_ENV, "")
    if not token:
        raise RuntimeError(
            f"{ADMIN_TOKEN_ENV} is not set. This is the break-glass bearer token that "
            "authenticates the Delta budget-allocation admin API. The admin app refuses "
            "to start without it (fail-closed). See Delta/.env.example."
        )
    return AllocationAdminSettings(admin_token=token)
