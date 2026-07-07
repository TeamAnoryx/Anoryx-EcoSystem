"""Model-policy decision cache (F-023, ADR-0029).

evaluate_model_policies() (policy/enforcement.py) issues 2-4 sequential SELECTs
against the app DB on every request (deny-list, allow-list, optionally
approval-list + model_inventory). Under load this is the largest single DB cost
on the hot path (gateway/router/selection.py::_enforce_policies_pre_request).
Model policies change rarely (an operator action through F-008 intake)
relative to request volume, so the DECISION is cacheable.

Budget "used" totals (policy/enforcement.py::load_active_budgets) are
DELIBERATELY NEVER cached here — they change on every usage event, and caching
them would let a tenant burn past its budget_limit before the ceiling caught
up. Only the model allow/deny/approval decision is cached.

Design:
  - Redis-backed (shared across gateway replicas, ADR-0011's pool), namespaced
    "sentinel:polcache:".
  - Keyed by a per-tenant VERSION counter, not a policy hash: any accepted
    policy write for a tenant (policy/intake.py Accepted path) bumps the
    tenant's version via INCR, which orphans every previously-cached decision
    for that tenant in O(1) — no pattern SCAN/DEL (ADR-0011 already ruled out
    blocking Redis commands on the hot path).
  - A short TTL (`policy_eval_cache_ttl_seconds`, default 5s) is a fail-safe
    BACKSTOP only, bounding staleness even if the invalidating INCR is somehow
    missed (e.g. a direct DB write outside intake.py). It is not the primary
    invalidation mechanism.
  - Fail-safe posture matches redis_client.py / rate_limit.py (ADR-0011 gamma):
    any Redis error (connection, timeout, decode) is a CACHE MISS, never a
    synthesized ALLOW. A write/invalidate error is logged and swallowed — it
    never fails the request or the policy write. The security-relevant
    DENY/ALLOW decision always still comes from evaluate_model_policies()'s
    existing fail-closed logic; this module only ever short-circuits a repeat
    of the SAME decision it already computed once.
  - When redis_client.is_degraded() is already True (health loop's verdict),
    every function here short-circuits without attempting a Redis round trip —
    on the request hot path, blocking on a doomed call up to the pool's
    socket timeout would itself violate the p95 budget this cache exists to
    protect (CLAUDE.md fail-safe still holds: short-circuiting means "compute
    live", not "assume allow").
"""

from __future__ import annotations

import json

import structlog
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError

import gateway.redis_client as redis_client
from policy.enforcement import ModelAllow, ModelDecision, ModelDeny, RequestScope

log = structlog.get_logger(__name__)

_VERSION_PREFIX = "sentinel:polcache:v:"
_DECISION_PREFIX = "sentinel:polcache:d:"

# Errors treated as "cache unavailable" — never as a decision.
_REDIS_ERRORS = (RedisConnectionError, RedisTimeoutError, RuntimeError)


def _version_key(tenant_id: str) -> str:
    return f"{_VERSION_PREFIX}{tenant_id}"


def _decision_key(scope: RequestScope, model_id: str, version: int) -> str:
    return (
        f"{_DECISION_PREFIX}{scope.tenant_id}:{version}:"
        f"{scope.team_id}:{scope.project_id}:{scope.agent_id}:{model_id}"
    )


def _encode(decision: ModelDecision) -> str:
    if isinstance(decision, ModelDeny):
        return json.dumps({"k": "deny", "policy_id": decision.policy_id, "reason": decision.reason})
    return json.dumps({"k": "allow", "policy_id": decision.policy_id})


def _decode(raw: str) -> ModelDecision | None:
    try:
        obj = json.loads(raw)
        if obj.get("k") == "deny":
            return ModelDeny(policy_id=obj["policy_id"], reason=obj["reason"])
        if obj.get("k") == "allow":
            return ModelAllow(policy_id=obj.get("policy_id"))
    except (TypeError, ValueError, KeyError):
        log.warning("policy_eval_cache_decode_error")
    return None


async def get_cached_decision(
    scope: RequestScope, model_id: str
) -> tuple[ModelDecision | None, int]:
    """Return (cached decision or None, version used for this lookup).

    The caller MUST pass the returned version to set_cached_decision on a
    miss, so the write lands under the exact version this read observed
    (avoids a second round trip to re-fetch it).
    """
    if redis_client.is_degraded():
        return None, 0
    try:
        client = await redis_client.get_client()
    except _REDIS_ERRORS:
        return None, 0
    try:
        raw_version = await client.get(_version_key(scope.tenant_id))
        version = int(raw_version) if raw_version else 0
        raw_decision = await client.get(_decision_key(scope, model_id, version))
        if raw_decision is None:
            return None, version
        return _decode(raw_decision), version
    except _REDIS_ERRORS as exc:
        log.warning("policy_eval_cache_read_error", redis_error_class=type(exc).__name__)
        return None, 0
    except (TypeError, ValueError):
        return None, 0
    finally:
        await client.aclose()


async def set_cached_decision(
    scope: RequestScope,
    model_id: str,
    decision: ModelDecision,
    version: int,
    *,
    ttl_seconds: float,
) -> None:
    """Best-effort cache write. Never raises — a write failure just means the
    next request recomputes (identical to a cold cache), not a wrong decision."""
    if redis_client.is_degraded() or ttl_seconds <= 0:
        return
    try:
        client = await redis_client.get_client()
    except _REDIS_ERRORS:
        return
    try:
        await client.set(_decision_key(scope, model_id, version), _encode(decision), ex=ttl_seconds)
    except _REDIS_ERRORS as exc:
        log.warning("policy_eval_cache_write_error", redis_error_class=type(exc).__name__)
    finally:
        await client.aclose()


async def invalidate_tenant(tenant_id: str) -> None:
    """Bump the tenant's cache version, orphaning every previously-cached
    decision for it in O(1). Called from policy/intake.py on every Accepted
    policy write. Best-effort: a failure here is bounded by the TTL backstop,
    never by raising into the intake pipeline."""
    if redis_client.is_degraded():
        return
    try:
        client = await redis_client.get_client()
    except _REDIS_ERRORS:
        return
    try:
        await client.incr(_version_key(tenant_id))
    except _REDIS_ERRORS as exc:
        log.warning("policy_eval_cache_invalidate_error", redis_error_class=type(exc).__name__)
    finally:
        await client.aclose()
