"""D-007 non-stubbed HTTP e2e: the real ASGI app, real auth, real DB.

Proves the real allow (correct bearer -> propose -> approve -> history visible) AND
the real deny (missing/wrong bearer -> 401, no tenant data) on the real path — banked
rule #2.
"""

from __future__ import annotations

import uuid

import httpx

from .conftest import db_required


def _payload(tenant_id: str, *, total: int = 5_000) -> dict:
    return {
        "tenant_id": tenant_id,
        "total_minor_units": total,
        "currency": "USD",
        "period": "monthly",
        "targets": [
            {
                "scope": "team",
                "team_id": str(uuid.uuid4()),
                "project_id": str(uuid.uuid4()),
                "agent_id": "gateway-core",
                "amount_minor_units": total,
            }
        ],
        "requested_by": "operator-1",
    }


async def test_missing_bearer_is_401(client: httpx.AsyncClient, tenant_id: str) -> None:
    resp = await client.post("/v1/admin/allocations", json=_payload(tenant_id))
    assert resp.status_code == 401


async def test_wrong_bearer_is_401(client: httpx.AsyncClient, tenant_id: str) -> None:
    resp = await client.post(
        "/v1/admin/allocations",
        json=_payload(tenant_id),
        headers={"Authorization": "Bearer not-the-token"},
    )
    assert resp.status_code == 401


@db_required
async def test_propose_approve_history_over_http(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str
) -> None:
    create_resp = await client.post(
        "/v1/admin/allocations", json=_payload(tenant_id), headers=auth_headers
    )
    assert create_resp.status_code == 201, create_resp.text
    allocation = create_resp.json()
    assert allocation["status"] == "requested"

    list_resp = await client.get(
        "/v1/admin/allocations",
        params={"tenant_id": tenant_id, "status": "requested"},
        headers=auth_headers,
    )
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1

    decision_resp = await client.post(
        f"/v1/admin/allocations/{allocation['allocation_id']}/decision",
        json={"tenant_id": tenant_id, "action": "approve", "actor": "operator-2"},
        headers=auth_headers,
    )
    assert decision_resp.status_code == 200, decision_resp.text
    decided = decision_resp.json()
    assert decided["status"] == "approved"
    assert all(t["budget_id"] for t in decided["targets"])

    # Re-approving is a conflict, not a silent no-op.
    replay_resp = await client.post(
        f"/v1/admin/allocations/{allocation['allocation_id']}/decision",
        json={"tenant_id": tenant_id, "action": "approve", "actor": "operator-2"},
        headers=auth_headers,
    )
    assert replay_resp.status_code == 409

    history_resp = await client.get(
        "/v1/admin/history",
        params={"tenant_id": tenant_id, "entity_id": allocation["allocation_id"]},
        headers=auth_headers,
    )
    assert history_resp.status_code == 200
    actions = [h["action"] for h in history_resp.json()]
    assert actions == ["approved", "requested"]  # newest first


@db_required
async def test_get_unknown_allocation_is_404(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str
) -> None:
    resp = await client.get(
        f"/v1/admin/allocations/{uuid.uuid4()}",
        params={"tenant_id": tenant_id},
        headers=auth_headers,
    )
    assert resp.status_code == 404


@db_required
async def test_unreconciled_allocation_is_422(
    client: httpx.AsyncClient, auth_headers: dict, tenant_id: str
) -> None:
    bad = _payload(tenant_id, total=10_000)
    bad["targets"][0]["amount_minor_units"] = 1_000  # short of total
    resp = await client.post("/v1/admin/allocations", json=bad, headers=auth_headers)
    assert resp.status_code == 422
