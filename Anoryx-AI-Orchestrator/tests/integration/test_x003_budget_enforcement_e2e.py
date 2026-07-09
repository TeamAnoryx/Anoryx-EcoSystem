"""X-003 -- the budget-enforcement killer loop, validated end to end (ADR-0017, non-stubbed).

The roadmap names this THE killer feature: "Delta budget hits cap -> policy pushed via
Orchestrator -> Sentinel blocks the team's next request within 1 second." Two of its three
legs already have non-stubbed proof elsewhere in this codebase:

  * Delta -> real O-004 distribution: `Delta/tests/budget_engine/test_o004_e2e.py` drives
    Delta's real cap-crossing budget engine all the way to a real signed POST accepted by a
    real O-004 app -- but its Sentinel-side forward target is an explicitly-documented
    "trivial accepting shim" (its own docstring: "the Sentinel-block leg is X-003").
  * O-004 -> real Sentinel intake + enforcement: `test_distribution_e2e.py` in this same
    directory proves the full submit -> distribute -> intake -> enforce loop non-stubbed --
    but only for MODEL policies (allowlist/denylist), never `budget_limit`.

Neither file proves the loop this roadmap task actually names: a `budget_limit` policy,
built and signed the way Delta's real D-005 emit path builds one
(`delta.attribution.budget_concept_to_policy_payload` + `delta.policy.sign.sign_policy_record`
-- imported unmodified from the installed `anoryx-delta` package), submitted through
Orchestrator's real O-004 HTTP distribution endpoint, landing in Sentinel's real policy store
via real `intake_policy()`, and then actually BLOCKING a request from the scoped team (while
leaving a sibling team on the same tenant untouched) -- with the whole submit-to-blocked
round trip measured well under the roadmap's 1-second claim.

Scope boundary (honesty, ADR-0017): this proves the POLICY SHAPE + SIGNING + the full
Orchestrator submit/distribute/intake/enforce chain for a `budget_limit` policy specifically,
using Delta's real (DB-free) payload-building and signing functions. It does NOT re-derive
Delta's own cap-crossing DECISION from ledger data (`test_o004_e2e.py` already proves that
non-stubbed) and does NOT re-drive a live Sentinel `/v1/chat/completions` HTTP request
(`evaluate_budget_pre_request` is Sentinel's own real, DB-backed enforcement entrypoint --
the exact function the gateway calls at request time, per `gateway/routes/chat_completions.py`
-- called directly here for the same reason X-001/O-004's `sentinel_enforce` fixture calls
`evaluate_model_policies` directly rather than standing up a full mocked-provider gateway
request).
"""

from __future__ import annotations

import json
import re
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import pytest

# NOTE: Sentinel's `policy.*` and Delta's `delta.*` are imported LAZILY inside fixtures/tests
# (not at module top), mirroring test_distribution_e2e.py's own convention, so the no-DB
# contract CI lane can still collect this file without either package's deps installed.

pytestmark = pytest.mark.integration

_TARGET = "sentinel-test"
ORCH_SERVICE_TOKEN = "x003-orch-service-token"  # noqa: S105 - test-only fake


@pytest.fixture
def budget_app(sentinel_db_ready, sentinel_shim_server, monkeypatch):
    """The real Orchestrator app wired to the real Sentinel shim as its one distribution target.

    Identical construction to test_distribution_e2e.py's `dist_app` (deliberately not
    imported from there -- each e2e file owns its app fixture, matching this suite's existing
    one-fixture-per-file convention for X-series/O-004 tests).
    """
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "x003-ingest-secret")
    monkeypatch.setenv("ORCH_SERVICE_TOKEN", ORCH_SERVICE_TOKEN)
    monkeypatch.setenv("SENTINEL_ADMIN_TOKEN", "x003-sentinel-admin-token")
    monkeypatch.setenv("ORCH_DISTRIBUTION_TARGETS", json.dumps({_TARGET: sentinel_shim_server}))
    monkeypatch.setenv("ORCH_SENTINEL_INTAKE_PATH", "/admin/policies/intake")
    monkeypatch.setenv("ORCH_DISTRIBUTION_BACKOFF_SECONDS", "0")
    monkeypatch.setenv("ORCH_DISTRIBUTION_MAX_ATTEMPTS", "2")

    from orchestrator.app import create_app

    return create_app()


def _bearer(token: str = ORCH_SERVICE_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _real_delta_signed_team_budget_policy(
    *, tenant_id: str, team_id: str, limit_cost_cents: int, private_key
) -> dict:
    """Build + sign a genuine `budget_limit` record via Delta's REAL D-005 emit + sign path.

    `BudgetDefinition` is a plain frozen dataclass (no DB row needed to construct one) and
    `build_policy_payload` / `sign_policy_record` are both pure functions -- exactly the
    artifact Delta's real cap-crossing drainer produces, without needing Delta's own database
    (already proven separately, non-stubbed, by Delta's own `test_o004_e2e.py`). Signed with
    the SAME test key Sentinel's shim trusts (`sentinel_signing`) -- in production this is the
    Delta signing identity ADR-0005 describes Sentinel as configured to trust; the test
    substitutes one shared key since the harness configures Sentinel with exactly one trusted
    signing key.
    """
    from delta.budget import BudgetPeriod, BudgetScope
    from delta.budget_engine.definitions import BudgetDefinition
    from delta.budget_engine.emit import build_policy_payload
    from delta.policy.sign import sign_policy_record

    budget = BudgetDefinition(
        budget_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        scope=BudgetScope.TEAM,
        team_id=team_id,
        project_id=str(uuid.uuid4()),
        agent_id="gateway-core",
        period=BudgetPeriod.DAILY,
        limit_tokens=None,
        limit_cost_cents=limit_cost_cents,
        currency="USD",
        policy_id=str(uuid.uuid4()),
    )
    unsigned = build_policy_payload(
        budget,
        policy_version=1,
        effective_from=datetime.now(timezone.utc) - timedelta(minutes=1),
    )
    return sign_policy_record(unsigned, private_key)


async def _submit_and_wait_distributed(app, db_conn, signed: dict) -> float:
    """POST the signed policy to the real submit endpoint; return the round-trip seconds.

    httpx's ASGITransport runs the FastAPI BackgroundTask synchronously (matches
    test_distribution_e2e.py's `test_submit_endpoint_drives_real_distribution_and_enforces`),
    so by the time POST returns, the real O-004 engine has already driven the distribution to
    Sentinel's real intake over a real loopback socket.
    """
    start = time.monotonic()
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        resp = await client.post(
            "/v1/policies/distributions", json={"policy": signed}, headers=_bearer()
        )
    assert resp.status_code == 202, resp.text
    distribution_id = resp.json()["distribution_id"]

    parent_state = await db_conn.fetchval(
        "SELECT state FROM policy_distributions WHERE distribution_id = $1", distribution_id
    )
    assert parent_state == "distributed", parent_state
    return time.monotonic() - start


async def _sentinel_evaluate_budget(tenant_id: str, team_id: str, *, est_cost: float):
    """Call Sentinel's REAL, DB-backed evaluate_budget_pre_request for this scope.

    Mirrors this file's sibling `sentinel_enforce` fixture (conftest.py) exactly, but for
    BUDGET policies: a dedicated sentinel_app engine in the test's own loop, the transaction-
    local tenant GUC set, then Sentinel's real budget entrypoint -- the same RLS-scoped read
    path `gateway/routes/chat_completions.py` calls at request time.
    """
    import os

    from policy.enforcement import RequestScope, evaluate_budget_pre_request
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
    from sqlalchemy.pool import NullPool

    url = re.sub(
        r"^postgresql(?:\+\w+)?://", "postgresql+asyncpg://", os.environ["APP_DATABASE_URL"]
    )
    engine = create_async_engine(url, connect_args={"ssl": False}, poolclass=NullPool)
    maker = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    try:
        async with maker() as session:
            await session.execute(
                text("SELECT set_config('app.current_tenant_id', :t, true)"), {"t": tenant_id}
            )
            scope = RequestScope(
                tenant_id=tenant_id,
                team_id=team_id,
                project_id=str(uuid.uuid4()),
                agent_id="gateway-core",
            )
            return await evaluate_budget_pre_request(
                session, scope, est_tokens=0, est_cost=est_cost
            )
    finally:
        await engine.dispose()


async def test_budget_cap_policy_blocks_the_teams_next_request_within_one_second(
    budget_app, db_conn, seed_sentinel_tenant, sentinel_signing
):
    """The full killer loop: a real Delta-signed budget_limit policy -> real O-004 submit ->
    real Sentinel intake -> a request from the CAPPED team is blocked, a SIBLING team is not,
    and the whole submit-to-enforced round trip is well under 1 second."""
    from policy.enforcement import BudgetExceeded, BudgetOk

    tenant = str(uuid.uuid4())
    capped_team = str(uuid.uuid4())
    sibling_team = str(uuid.uuid4())
    await seed_sentinel_tenant(tenant)

    signed = _real_delta_signed_team_budget_policy(
        tenant_id=tenant,
        team_id=capped_team,
        limit_cost_cents=100,
        private_key=sentinel_signing,
    )

    elapsed = await _submit_and_wait_distributed(budget_app, db_conn, signed)
    assert elapsed < 1.0, f"submit -> distributed took {elapsed:.3f}s, budget is < 1s"

    # The capped team's next request (estimated cost over the $1.00 cap) is BLOCKED.
    capped_decision = await _sentinel_evaluate_budget(tenant, capped_team, est_cost=150)
    assert isinstance(capped_decision, BudgetExceeded), capped_decision
    assert capped_decision.reason == "budget_cost_exceeded"

    # A sibling team on the SAME tenant is untouched -- this is a team-scoped block, not a
    # tenant-wide one (proves budget_matches_scope's team_id equality, not a wildcard blast).
    sibling_decision = await _sentinel_evaluate_budget(tenant, sibling_team, est_cost=150)
    assert isinstance(sibling_decision, BudgetOk), sibling_decision
