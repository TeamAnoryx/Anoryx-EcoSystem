"""Per-tenant data_lock config loader (F-017, ADR-0020 §4/§6).

Reuses the F-008 policy store exactly like ``code_scan/config.py``:
``get_active_policies_for_scope(tenant_id, "data_lock")`` over an RLS-scoped
``get_tenant_session(tenant_id)`` — no parallel config system, no new bypass.

THE CRITICAL DIFFERENCE vs code_scan (ADR-0020 §4, R1 — fail-CLOSED inversion):

  code_scan swallows any load/parse error to a *disabled* config (fail-OPEN is
  acceptable there because its fail-safe is WARN).  data_lock MUST NOT: if the
  ruleset cannot be ENUMERATED we cannot know which fields are locked, so the
  only safe outcome is to block the whole response.  Therefore this loader
  **raises ``DataLockConfigError``** on any DB/session/parse failure; the
  detector converts that raise into a whole-response fail-closed block (tier 2).

The empty-result vs exception distinction is load-bearing:
  - ``get_active_policies_for_scope`` returns ``[]``  → SUCCESSFUL load, tenant
    never opted in → ``DataLockConfig(armed=False)`` → cheap pass.
  - the call (or the parse) RAISES                    → ``DataLockConfigError``
    → detector blocks the whole response.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import structlog

from data_lock.rules import DataLockRule, DataLockRuleError, parse_rules
from persistence.database import get_tenant_session
from persistence.repositories.policy_repository import PolicyRepository

log = structlog.get_logger(__name__)


class DataLockConfigError(Exception):
    """Raised when the data_lock ruleset cannot be enumerated (fail-closed).

    The detector treats this as ADR-0020 §4 tier-2: block the whole response,
    because the set of locked fields is unknown and releasing would be fail-open.
    """


@dataclass(frozen=True)
class DataLockConfig:
    """Resolved per-tenant data_lock configuration.

    ``armed`` is True only when a parsed, enabled policy with rules exists.  An
    absent policy (default-OFF) yields ``armed=False`` (cheap pass).
    """

    armed: bool
    rules: tuple[DataLockRule, ...] = ()


_NOT_ARMED = DataLockConfig(armed=False, rules=())


async def load_data_lock_config(tenant_id: str) -> DataLockConfig:
    """Load the active ``data_lock`` policy for *tenant_id*.

    Returns ``DataLockConfig(armed=False)`` ONLY for a successful load that finds
    no active/enabled policy (default-OFF).  Raises ``DataLockConfigError`` for
    any failure that leaves the ruleset unknowable — empty/blank tenant_id, DB or
    session error, unparseable payload, or a malformed rule (fail-closed, R1).
    """
    if not tenant_id or not tenant_id.strip():
        # No tenant scope → cannot enumerate rules → fail closed (do not pass).
        raise DataLockConfigError("data_lock load called without a tenant_id")

    try:
        # get_tenant_session autobegins (set_config(app.current_tenant_id) before
        # yield); this is a read, so do NOT call session.begin() again (the
        # code_scan CRIT-2 load-path lesson — double-begin raises InvalidRequestError).
        async with get_tenant_session(tenant_id) as session:
            repo = PolicyRepository(session)
            policies = await repo.get_active_policies_for_scope(tenant_id, "data_lock")
    except Exception as exc:
        log.warning("data_lock.config_load_error")  # never log tenant_id (LOW-1 pattern)
        raise DataLockConfigError("data_lock config load failed") from exc

    if not policies:
        # Successful load, no opt-in → not armed → cheap pass (NOT an error).
        return _NOT_ARMED

    if len(policies) > 1:
        # Ambiguous: more than one active data_lock policy for the tenant. We will
        # not silently apply only one and risk a dropped lock rule → fail closed.
        log.warning("data_lock.multiple_active_policies", count=len(policies))
        raise DataLockConfigError("multiple active data_lock policies for tenant")

    # Parse the single active policy row.  A malformed payload is fail-closed: we
    # will not guess which fields a broken rule meant to lock.
    raw_payload: Any = policies[0].policy_payload or ""
    try:
        payload = json.loads(raw_payload)
        armed, rules = parse_rules(payload)
    except (ValueError, TypeError, DataLockRuleError) as exc:
        log.warning("data_lock.config_parse_error")
        raise DataLockConfigError("data_lock payload could not be parsed") from exc

    return DataLockConfig(armed=armed, rules=tuple(rules))
