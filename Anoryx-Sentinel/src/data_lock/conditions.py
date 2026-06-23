"""Server-authoritative lock-condition evaluation (F-017, ADR-0020 §7).

Two condition kinds in v1 (Fork 4 deferred approval):

  TIME       — released once the SERVER clock reaches ``unlock_at``.  The unlock
               instant comes from the tenant's signed policy; the *current* time
               is ALWAYS ``datetime.now(timezone.utc)``.  No caller-supplied time
               is ever read (threat vector 3).

  PERMISSION — released iff the caller's SERVER-RESOLVED identity matches the
               rule's allow-list.  The identity attributes (team_id / project_id
               / agent_id) come from ``HookContext.tenant_context`` (resolved from
               the virtual API key), never from a header / body / claim
               (threat vector 2).

FAIL-CLOSED: ``evaluate`` returns ``True`` only when the condition is positively
satisfied.  A malformed/unknown condition object reaching ``evaluate`` returns
``False`` (withhold).  Malformed specs are normally rejected earlier by
``parse_condition`` (→ ``ConditionError`` → the whole ruleset fails closed).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Union

# Identity attributes a PERMISSION rule may match against.  These are the only
# server-resolved, non-forgeable discriminators available on the data plane
# (tenant_id is trivially the caller's own — policies are already tenant-scoped).
_VALID_PERMISSION_ATTRS = frozenset({"team_id", "project_id", "agent_id"})

# Bound the allow-list size to keep policy payloads small (R7).
_MAX_ALLOW_VALUES_PER_ATTR = 256


class ConditionError(ValueError):
    """Raised when a condition spec is malformed/unparseable.

    The caller (rule parser) treats this as a fail-closed signal: a tenant whose
    policy contains an unparseable condition has its whole ruleset rejected, and
    the detector blocks the response rather than guessing.
    """


@dataclass(frozen=True)
class TimeCondition:
    """Locked until the server clock reaches ``unlock_at`` (tz-aware UTC)."""

    unlock_at: datetime


@dataclass(frozen=True)
class PermissionCondition:
    """Locked unless the caller matches the allow-list.

    ``allow_pairs`` is a frozenset of ``(attribute, value)`` tuples.  The field is
    released iff the caller's resolved ``(attr, value)`` for ANY of team_id /
    project_id / agent_id appears in this set (OR across attributes — a rule may
    grant access by any one dimension).
    """

    allow_pairs: frozenset[tuple[str, str]]


LockCondition = Union[TimeCondition, PermissionCondition]


def _parse_unlock_at(value: Any) -> datetime:
    """Parse an ISO-8601 instant into a tz-aware UTC datetime, or raise."""
    if not isinstance(value, str) or not value:
        raise ConditionError("time condition requires a non-empty 'unlock_at' string")
    raw = value.strip()
    # Python 3.11+ datetime.fromisoformat accepts a trailing 'Z'.
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ConditionError(f"unlock_at is not a valid ISO-8601 instant: {raw!r}") from exc
    if parsed.tzinfo is None:
        # Reject naive timestamps — an ambiguous local time must not silently
        # become a release decision (fail-closed clarity).
        raise ConditionError("unlock_at must be timezone-aware (e.g. end with 'Z')")
    return parsed.astimezone(timezone.utc)


def _parse_permission_allow(value: Any) -> frozenset[tuple[str, str]]:
    """Parse the permission ``allow`` map into a frozenset of (attr, value) pairs."""
    if not isinstance(value, dict) or not value:
        raise ConditionError("permission condition requires a non-empty 'allow' object")
    pairs: set[tuple[str, str]] = set()
    for attr, values in value.items():
        if attr not in _VALID_PERMISSION_ATTRS:
            raise ConditionError(
                f"permission allow attribute {attr!r} not in {sorted(_VALID_PERMISSION_ATTRS)}"
            )
        if not isinstance(values, list) or not values:
            raise ConditionError(f"permission allow[{attr!r}] must be a non-empty list")
        if len(values) > _MAX_ALLOW_VALUES_PER_ATTR:
            raise ConditionError(
                f"permission allow[{attr!r}] exceeds {_MAX_ALLOW_VALUES_PER_ATTR} values"
            )
        for v in values:
            if not isinstance(v, str) or not v:
                raise ConditionError(f"permission allow[{attr!r}] values must be non-empty strings")
            pairs.add((attr, v))
    return frozenset(pairs)


def parse_condition(raw: Any) -> LockCondition:
    """Parse a raw condition dict into a typed ``LockCondition``, or raise.

    Raises ``ConditionError`` for any malformed/unknown condition so the ruleset
    fails closed (the detector blocks rather than releasing an unverified field).
    """
    if not isinstance(raw, dict):
        raise ConditionError("condition must be an object")
    kind = raw.get("type")
    if kind == "time":
        return TimeCondition(unlock_at=_parse_unlock_at(raw.get("unlock_at")))
    if kind == "permission":
        return PermissionCondition(allow_pairs=_parse_permission_allow(raw.get("allow")))
    # 'approval' is explicitly deferred (Fork 4); anything else is unknown.
    raise ConditionError(f"unsupported condition type: {kind!r} (v1 supports 'time', 'permission')")


def evaluate(
    condition: LockCondition,
    *,
    team_id: str,
    project_id: str,
    agent_id: str,
) -> bool:
    """Return True iff the condition is met (the field may be RELEASED).

    Server-authoritative: TIME compares against ``datetime.now(timezone.utc)``
    only; PERMISSION compares against the passed server-resolved identity only.
    None of these arguments may be a caller-supplied value — the gateway passes
    the IDs resolved from the virtual API key (R2).

    A condition object of an unexpected type returns False (withhold) — defensive
    fail-closed; well-formed inputs never reach this branch.
    """
    if isinstance(condition, TimeCondition):
        return datetime.now(timezone.utc) >= condition.unlock_at
    if isinstance(condition, PermissionCondition):
        caller = {
            ("team_id", team_id),
            ("project_id", project_id),
            ("agent_id", agent_id),
        }
        return bool(caller & condition.allow_pairs)
    return False
