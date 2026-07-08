"""Non-stubbed multi-Sentinel coordination e2e (O-005, ADR-0005) — THE gate.

Stands up >=2 REAL loopback Sentinel shims (genuine sockets, real httpx, real Sentinel
intake/enforcement) and proves, on a fresh Postgres:

  * REAL health-state transitions across >=3 registered Sentinels: A + B answer /healthz (→
    healthy), C is stopped (→ unreachable). previous_status was 'unknown' (a real transition).
  * A REAL coordinated push fans O-004's distribution across HEALTHY + CAPABLE targets only: A
    (capable) is distributed via Sentinel's REAL intake_policy persist; B (healthy but
    incapable) is skipped:incapable; C (capable but unhealthy) is skipped:unhealthy.
  * The distributed policy is REALLY enforced by Sentinel (evaluate_model_policies allows the
    allowlisted model, denies another) — proving the path is not stubbed.
  * Tenant RLS isolates the distribution rows (a second tenant's app-role session sees none).
  * The registry-mutation chain validates.

Gated by coordination_ready, which FAILS (not skips) under ORCH_REQUIRE_COORDINATION_E2E=1 so
this gate provably EXECUTES on CI.
"""

from __future__ import annotations

import dataclasses
import uuid

import pytest

from orchestrator.coordination.coordinator import coordinate_push
from orchestrator.coordination.health import run_health_cycle
from orchestrator.coordination.registry import fetch_sentinel, register_sentinel
from orchestrator.persistence.database import get_privileged_session
from orchestrator.persistence.repositories import (
    list_recent_registry_audit_admin,
    validate_registry_chain,
)

pytestmark = pytest.mark.integration


async def test_multi_sentinel_coordination_e2e(
    coordination_ready,
    clean_registry,
    spawn_sentinel_shim,
    coordination_settings,
    make_signed_policy,
    seed_sentinel_tenant,
    read_sentinel_policy_signature,
    sentinel_enforce,
    db_conn,
    app_db_conn,
) -> None:
    tenant_a = str(uuid.uuid4())
    other_tenant = str(uuid.uuid4())
    await seed_sentinel_tenant(tenant_a)  # Sentinel intake needs the tenant row (policies FK).

    # Three real loopback shims; C will be stopped to force an unreachable transition.
    shim_a = spawn_sentinel_shim()
    shim_b = spawn_sentinel_shim()
    shim_c = spawn_sentinel_shim()

    sid_a, sid_b, sid_c = "sentinel-a", "sentinel-b", "sentinel-c"
    # A: capable (model_allowlist). B: healthy but INCAPABLE (data_lock only). C: capable but
    # will be stopped (unreachable). Endpoints are loopback (allowlisted + allow_http in settings).
    await register_sentinel(
        sentinel_id=sid_a,
        endpoint=shim_a.base_url,
        capabilities=["model_allowlist"],
        settings=coordination_settings,
    )
    await register_sentinel(
        sentinel_id=sid_b,
        endpoint=shim_b.base_url,
        capabilities=["data_lock"],
        settings=coordination_settings,
    )
    await register_sentinel(
        sentinel_id=sid_c,
        endpoint=shim_c.base_url,
        capabilities=["model_allowlist"],
        settings=coordination_settings,
    )

    # Stop C → its endpoint now refuses connections.
    shim_c.stop()

    # --- REAL health transitions across >=2 registered Sentinels --------------------------- #
    results = await run_health_cycle(settings=coordination_settings)
    by_id = {r["sentinel_id"]: r for r in results}
    assert by_id[sid_a]["status"] == "healthy"
    assert by_id[sid_b]["status"] == "healthy"
    assert by_id[sid_c]["status"] == "unreachable"
    # Each began at 'unknown' (set at registration) → a genuine transition, not a no-op.
    assert by_id[sid_a]["previous_status"] == "unknown"
    assert by_id[sid_c]["previous_status"] == "unknown"

    # --- REAL coordinated push: fan to healthy + capable only ------------------------------ #
    policy = make_signed_policy(
        "model_allowlist", tenant_id=tenant_a, allowed_model_ids=["gpt-4o-mini"]
    )
    result = await coordinate_push(policy, tenant_a, settings=coordination_settings)

    target_by_id = {t["sentinel_id"]: t for t in result["targets"]}
    assert target_by_id[sid_a]["state"] == "distributed"
    assert target_by_id[sid_b] == {"sentinel_id": sid_b, "state": "skipped", "reason": "incapable"}
    assert target_by_id[sid_c] == {"sentinel_id": sid_c, "state": "skipped", "reason": "unhealthy"}
    # Only A was a SELECTED target and it distributed → parent aggregates to distributed.
    assert result["state"] == "distributed"

    # --- REAL distribution proof: Sentinel's intake persisted the byte-identical policy ----- #
    persisted_sig = await read_sentinel_policy_signature(policy["policy_id"])
    assert persisted_sig == policy["signature"]

    # --- REAL enforcement proof: the distributed allowlist is actually enforced ------------- #
    allow = await sentinel_enforce(tenant_a, "gpt-4o-mini")
    assert type(allow).__name__ == "ModelAllow"
    deny = await sentinel_enforce(tenant_a, "some-other-model")
    assert type(deny).__name__ == "ModelDeny"

    # --- Tenant RLS on the distribution rows the coordinated push produced ------------------ #
    dist_id = result["distribution_id"]
    privileged_count = await db_conn.fetchval(
        "SELECT count(*) FROM policy_distributions WHERE distribution_id = $1", dist_id
    )
    assert privileged_count == 1  # the privileged (BYPASSRLS) role sees it
    await app_db_conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", tenant_a)
    owner_count = await app_db_conn.fetchval(
        "SELECT count(*) FROM policy_distributions WHERE distribution_id = $1", dist_id
    )
    assert owner_count == 1  # the owning tenant's app-role session sees it
    await app_db_conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", other_tenant)
    other_count = await app_db_conn.fetchval(
        "SELECT count(*) FROM policy_distributions WHERE distribution_id = $1", dist_id
    )
    assert other_count == 0  # RLS hides it from another tenant (non-stubbed isolation)

    # --- Registry-mutation chain validates ------------------------------------------------- #
    async with get_privileged_session() as ps:
        assert await validate_registry_chain(ps) is True


def _rollback_links(links: list[dict], sentinel_id: str) -> list[dict]:
    return [
        link
        for link in links
        if link["sentinel_id"] == sentinel_id
        and link["action"] == "disable"
        and (link.get("error_reason") or "").startswith("auto_rollback:")
    ]


async def test_auto_rollback_off_by_default_e2e(
    coordination_ready,
    clean_registry,
    spawn_sentinel_shim,
    coordination_settings,
) -> None:
    """O-014 (ADR-0014), Fork D: with ORCH_AUTO_ROLLBACK_ENABLED off (the fixture's default),
    a REAL health cycle observing an unreachable target leaves it enabled — byte-identical
    pre-O-014 behavior. Isolated in its own test (own `clean_registry`) so it cannot be
    perturbed by a later cycle from the separate trip test below."""
    shim = spawn_sentinel_shim()
    sid = "sentinel-control"
    await register_sentinel(
        sentinel_id=sid,
        endpoint=shim.base_url,
        capabilities=["model_allowlist"],
        settings=coordination_settings,
    )
    shim.stop()
    results = await run_health_cycle(settings=coordination_settings)
    by_id = {r["sentinel_id"]: r for r in results}
    assert by_id[sid]["status"] == "unreachable"
    assert "auto_rollback" not in by_id[sid]
    row = await fetch_sentinel(sid)
    assert row["enabled"] is True  # untouched — the switch was off

    async with get_privileged_session() as ps:
        links = await list_recent_registry_audit_admin(
            ps, limit=50, action="disable", error_reason_prefix="auto_rollback:"
        )
    assert _rollback_links(links, sid) == []


async def test_auto_rollback_trips_and_is_idempotent_e2e(
    coordination_ready,
    clean_registry,
    spawn_sentinel_shim,
    coordination_settings,
) -> None:
    """O-014 (ADR-0014): with the switch ON, a REAL health cycle trips the circuit-breaker on
    a currently-enabled target that transitions to `unreachable`, in the SAME cycle that
    observed it; the trip is chain-audited (the ordinary `disable` action, distinguished from
    a manual disable only by its `auto_rollback:` error_reason prefix — Fork F); and a SECOND
    cycle against the still-down, now-disabled target does not re-trip (Fork G — no audit
    spam for an ongoing outage). Isolated in its own test/registry so a second health cycle
    here can never also re-evaluate the OTHER test's already-stopped control shim.
    """
    rollback_on = dataclasses.replace(coordination_settings, auto_rollback_enabled=True)

    shim = spawn_sentinel_shim()
    sid = "sentinel-target"
    await register_sentinel(
        sentinel_id=sid,
        endpoint=shim.base_url,
        capabilities=["model_allowlist"],
        settings=rollback_on,
    )
    shim.stop()
    results = await run_health_cycle(settings=rollback_on)
    by_id = {r["sentinel_id"]: r for r in results}
    assert by_id[sid]["status"] == "unreachable"
    assert by_id[sid]["auto_rollback"] is True
    row = await fetch_sentinel(sid)
    assert row["enabled"] is False  # the circuit-breaker actually tripped

    async with get_privileged_session() as ps:
        assert await validate_registry_chain(ps) is True
        links = await list_recent_registry_audit_admin(
            ps, limit=50, action="disable", error_reason_prefix="auto_rollback:"
        )
    rollback_links = _rollback_links(links, sid)
    assert len(rollback_links) == 1
    assert rollback_links[0]["error_reason"].startswith("auto_rollback:")

    # --- A second cycle against the still-down, now-disabled target does not re-trip. ------ #
    results_again = await run_health_cycle(settings=rollback_on)
    by_id_again = {r["sentinel_id"]: r for r in results_again}
    # The disabled-skip branch doesn't even re-probe; the target's status is carried forward.
    assert "auto_rollback" not in by_id_again[sid]
    async with get_privileged_session() as ps:
        links_after = await list_recent_registry_audit_admin(
            ps, limit=50, action="disable", error_reason_prefix="auto_rollback:"
        )
    assert len(_rollback_links(links_after, sid)) == 1  # no new link appended
