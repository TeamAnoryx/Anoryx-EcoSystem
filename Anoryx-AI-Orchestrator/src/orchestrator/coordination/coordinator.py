"""Coordinated push (O-005, ADR-0005, Fork B1).

`coordinate_push()` fans O-004's per-target distribution across all REGISTERED + HEALTHY +
CAPABLE Sentinel targets. It CONSUMES O-004's `drive_distribution` UNCHANGED: it selects the
targets from the registry, persists the parent + per-target distribution rows exactly as the
O-004 router does, builds a `DistributionSettings` whose `.targets` is the registry's
{sentinel_id: endpoint} for the selected set, then calls `drive_distribution`. The registry is
the dynamic resolver O-004 reserved for O-005; the distribution semantics are untouched.

Targeting (Fork B1) skips, with a per-target reason, any target that is disabled, unhealthy
(incl. stale-health, via effective_health_status), incapable (policy_type not in declared
capabilities), or whose endpoint no longer validates (SSRF re-check). The push is best-effort
per-target (O-004 semantics): the parent aggregates honestly to distributed / partial / failed.

The CALLER (the router) validates the signed policy (schema + NUL + identity) before calling;
this module trusts `signed_policy` is a validated, byte-identical signed record.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import uuid
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

from orchestrator.config import CoordinationSettings
from orchestrator.coordination.endpoint_validation import (
    EndpointValidationError,
    validate_endpoint,
)
from orchestrator.coordination.health import effective_health_status
from orchestrator.coordination.registry import fetch_sentinels
from orchestrator.distribution.engine import drive_distribution
from orchestrator.persistence import repositories as repo
from orchestrator.persistence.database import get_privileged_session, get_tenant_session


def _select_targets(
    sentinels: list[dict[str, Any]], *, policy_type: str, settings: CoordinationSettings
) -> tuple[dict[str, str], list[dict[str, str]]]:
    """Partition the registry into (selected {sentinel_id: endpoint}, skipped [{id, reason}]).

    A target is selected iff enabled AND effective health is healthy AND policy_type is in its
    declared capabilities AND its endpoint still validates. Order-preserving; reasons are honest
    (disabled | unhealthy | incapable | invalid_endpoint).
    """
    now = datetime.now(timezone.utc)
    selected: dict[str, str] = {}
    skipped: list[dict[str, str]] = []
    for sentinel in sentinels:
        sentinel_id = sentinel["sentinel_id"]
        if not sentinel.get("enabled", True):
            skipped.append({"sentinel_id": sentinel_id, "reason": "disabled"})
            continue
        status = effective_health_status(
            sentinel, staleness_seconds=settings.staleness_seconds, now=now
        )
        if status != "healthy":
            skipped.append({"sentinel_id": sentinel_id, "reason": "unhealthy"})
            continue
        if policy_type not in (sentinel.get("capabilities") or []):
            skipped.append({"sentinel_id": sentinel_id, "reason": "incapable"})
            continue
        try:
            validate_endpoint(
                sentinel["endpoint"],
                allowlist=settings.endpoint_allowlist,
                allow_http=settings.allow_http,
            )
        except EndpointValidationError:
            skipped.append({"sentinel_id": sentinel_id, "reason": "invalid_endpoint"})
            continue
        selected[sentinel_id] = sentinel["endpoint"]
    return selected, skipped


async def coordinate_push(
    signed_policy: dict[str, Any], tenant_id: str, *, settings: CoordinationSettings
) -> dict[str, Any]:
    """Fan a signed policy across all healthy + capable registered Sentinels (best-effort).

    Returns {distribution_id, state, targets: [{sentinel_id, state, reason?}], skipped: [...]}.
    A target's state is the O-004 per-target outcome (distributed | failed); a skipped target is
    surfaced with state 'skipped' + a reason. With zero selected targets the parent aggregates to
    'failed' (honest: nothing healthy + capable to push to).
    """
    policy_id = signed_policy["policy_id"]
    policy_type = signed_policy["policy_type"]
    policy_version = signed_policy["policy_version"]

    sentinels = await fetch_sentinels()
    # Offload selection to a thread: it calls the blocking getaddrinfo (via validate_endpoint)
    # for every candidate, which would otherwise block the event loop on hostname endpoints.
    loop = asyncio.get_running_loop()
    selected, skipped = await loop.run_in_executor(
        None,
        functools.partial(_select_targets, sentinels, policy_type=policy_type, settings=settings),
    )

    # Build the distribution settings the engine consumes UNCHANGED, with .targets resolved from
    # the registry for the selected set (the registry IS the dynamic resolver O-004 reserved).
    dist_settings = replace(settings.distribution, targets=dict(selected))

    distribution_id = str(uuid.uuid4())
    content_hash = hashlib.sha256(
        json.dumps(signed_policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()

    # Persist the parent + per-target rows under the tenant session (RLS-enforced; AUTOBEGINS —
    # no nested session.begin(), ADR-0026) — exactly as the O-004 router does.
    async with get_tenant_session(tenant_id) as session:
        await repo.insert_policy_distribution(
            session,
            {
                "distribution_id": distribution_id,
                "policy_id": policy_id,
                "policy_version": policy_version,
                "tenant_id": tenant_id,
                "policy_type": policy_type,
                "state": "pending",
                "signed_record": signed_policy,
                "content_hash": content_hash,
            },
        )
        for sentinel_id in selected:
            await repo.insert_distribution_target(
                session,
                {
                    "target_id": str(uuid.uuid4()),
                    "distribution_id": distribution_id,
                    "tenant_id": tenant_id,
                    "sentinel_id": sentinel_id,
                    "state": "pending",
                    "attempt_count": 0,
                    "max_attempts": dist_settings.max_attempts,
                },
            )
        await session.commit()

    # Audit `submitted` (privileged session does NOT autobegin → open the begin here).
    async with get_privileged_session() as psession:
        async with psession.begin():
            await repo.append_distribution_audit_link(
                psession,
                {
                    "distribution_id": distribution_id,
                    "policy_id": policy_id,
                    "tenant_id": tenant_id,
                    "policy_type": policy_type,
                },
                disposition="submitted",
            )

    # Drive the fan-out via O-004's engine UNCHANGED, then read back the settled per-target state.
    await drive_distribution(distribution_id, tenant_id, settings=dist_settings)

    async with get_tenant_session(tenant_id) as session:
        dist = await repo.get_distribution(session, distribution_id)
        targets = await repo.list_distribution_targets(session, distribution_id)

    target_results: list[dict[str, Any]] = [
        {"sentinel_id": t["sentinel_id"], "state": t["state"]} for t in targets
    ]
    for sk in skipped:
        target_results.append(
            {"sentinel_id": sk["sentinel_id"], "state": "skipped", "reason": sk["reason"]}
        )

    return {
        "distribution_id": distribution_id,
        "policy_id": policy_id,
        "state": dist["state"] if dist is not None else "failed",
        "targets": target_results,
        "skipped": skipped,
    }
