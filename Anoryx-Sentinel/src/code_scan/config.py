"""Per-tenant code-scan configuration loader (F-016, ADR-0019 §9).

Loads the ``code_scan`` policy via
``PolicyRepository.get_active_policies_for_scope(tenant_id, "code_scan")``
using the caller's existing RLS-scoped session (no new bypass, no parallel
config system — reuses F-008 ADR-0009 infrastructure exactly).

Policy payload JSON shape (ADR-0019 §9)::

    {
        "enabled": true,
        "thresholds": {"warn": "low", "block": "high"},
        "actions":    {"warn": "audit", "block": "reject"}
    }

Absent policy ⇒ ``CodeScanConfig.enabled = False`` (default-OFF, Fork 4).
Malformed / partial payload ⇒ safe defaults applied field by field.

``thresholds.warn``  : one of "low", "medium", "high", "critical"  (default "low")
``thresholds.block`` : one of "low", "medium", "high", "critical"  (default "high")
``actions.warn``     : one of "audit", "reject"                     (default "audit")
``actions.block``    : one of "audit", "reject"                     (default "reject")
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import structlog

from persistence.database import get_tenant_session
from persistence.repositories.policy_repository import PolicyRepository

log = structlog.get_logger(__name__)

# Valid values for threshold fields.
_VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})
# Valid values for action fields.
_VALID_ACTIONS = frozenset({"audit", "reject"})

# Defaults applied when the field is missing or invalid.
_DEFAULT_WARN_THRESHOLD = "low"
_DEFAULT_BLOCK_THRESHOLD = "high"
_DEFAULT_WARN_ACTION = "audit"
_DEFAULT_BLOCK_ACTION = "reject"


@dataclass(frozen=True)
class CodeScanConfig:
    """Resolved per-tenant code-scan configuration.

    Attributes
    ----------
    enabled:
        Whether code scanning is active for this tenant.  False when no
        ``code_scan`` policy row exists (default-OFF, ADR-0019 Fork 4).
    warn_threshold:
        Minimum severity (inclusive) for a WARN verdict.
    block_threshold:
        Minimum severity (inclusive) for a BLOCK verdict.
    warn_action:
        "audit"  — WARN produces an event, response passes unchanged.
        "reject" — not used for WARN (reserved for consistency).
    block_action:
        "reject" — BLOCK rejects the non-streamed response (policy_blocked 403).
        "audit"  — downgrades BLOCK to WARN+audit (no rejection) for tenants
                   that want signal without disruption.
    """

    enabled: bool
    warn_threshold: str = _DEFAULT_WARN_THRESHOLD
    block_threshold: str = _DEFAULT_BLOCK_THRESHOLD
    warn_action: str = _DEFAULT_WARN_ACTION
    block_action: str = _DEFAULT_BLOCK_ACTION


# A pre-built disabled config returned cheaply when no policy exists.
_DISABLED_CONFIG = CodeScanConfig(enabled=False)


def _safe_severity(value: Any, default: str) -> str:
    """Return *value* if it is a valid severity string, else *default*."""
    if isinstance(value, str) and value.lower() in _VALID_SEVERITIES:
        return value.lower()
    return default


def _safe_action(value: Any, default: str) -> str:
    """Return *value* if it is a valid action string, else *default*."""
    if isinstance(value, str) and value.lower() in _VALID_ACTIONS:
        return value.lower()
    return default


def _parse_payload(payload_str: str) -> CodeScanConfig:
    """Parse a policy_payload JSON string into a ``CodeScanConfig``.

    Malformed JSON or missing fields fall back to safe defaults field by field.
    Never raises — a broken payload is treated as disabled (fail-safe).
    """
    try:
        payload: dict[str, Any] = json.loads(payload_str)
    except (ValueError, TypeError):
        log.warning("code_scan.config_parse_error", payload_preview="<unparseable>")
        return _DISABLED_CONFIG

    enabled = bool(payload.get("enabled", False))
    if not enabled:
        return _DISABLED_CONFIG

    thresholds = payload.get("thresholds", {}) or {}
    actions = payload.get("actions", {}) or {}

    return CodeScanConfig(
        enabled=True,
        warn_threshold=_safe_severity(thresholds.get("warn"), _DEFAULT_WARN_THRESHOLD),
        block_threshold=_safe_severity(thresholds.get("block"), _DEFAULT_BLOCK_THRESHOLD),
        warn_action=_safe_action(actions.get("warn"), _DEFAULT_WARN_ACTION),
        block_action=_safe_action(actions.get("block"), _DEFAULT_BLOCK_ACTION),
    )


async def load_code_scan_config(tenant_id: str) -> CodeScanConfig:
    """Load the active ``code_scan`` policy for *tenant_id* and return a config.

    Opens its own RLS-scoped tenant session via ``get_tenant_session(tenant_id)``
    so the caller (CodeScanDetector) does NOT need to smuggle a session through
    the HookContext — production HookContext objects never carry ``_db_session``
    (CRIT-1 fix: the old signature accepted a session from the context, which was
    always None in production, making the detector a permanent no-op).

    Returns ``_DISABLED_CONFIG`` (enabled=False) when:
    - ``tenant_id`` is empty or whitespace (fail-closed guard in get_tenant_session).
    - No active ``code_scan`` policy row exists for the tenant.
    - The policy exists but ``enabled`` is false.
    - The policy payload cannot be parsed (fail-safe).
    - Any DB/session error occurs (fail-safe: treat as disabled, not crash).

    Never raises.  Fail-safe: any error → disabled config, never crashes the
    response path.
    """
    if not tenant_id or not tenant_id.strip():
        return _DISABLED_CONFIG

    try:
        # get_tenant_session autobegins (it executes set_config(app.current_tenant_id)
        # before yielding), so the session is already in a transaction — do NOT call
        # session.begin() again (it raises InvalidRequestError, which the except below
        # would swallow into a silent no-op: CRIT-2 load-path bug). This is a read; the
        # autobegun transaction is sufficient, matching the other get_tenant_session
        # readers (e.g. the SSO tenant-isolation tests).
        async with get_tenant_session(tenant_id) as session:
            repo = PolicyRepository(session)
            policies = await repo.get_active_policies_for_scope(tenant_id, "code_scan")
    except Exception:
        log.warning(
            "code_scan.config_load_error",
            # Never log tenant_id — avoid PII/tenant identity in logs (LOW-1).
        )
        return _DISABLED_CONFIG

    if not policies:
        return _DISABLED_CONFIG

    # Use the first (and typically only) active policy row.
    policy = policies[0]
    return _parse_payload(policy.policy_payload or "")
