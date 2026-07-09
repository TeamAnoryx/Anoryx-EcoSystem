"""D-013 non-stubbed HTTP e2e suite: real ASGI app, real auth, real DB."""

from __future__ import annotations

from .conftest import db_required


@db_required
async def test_clients_endpoint_401_without_bearer(client) -> None:
    resp = await client.get("/v1/admin/crm/clients?tenant_id=11111111-1111-4111-8111-111111111111")
    assert resp.status_code == 401


@db_required
async def test_create_client_over_http(client, auth_headers, tenant_id) -> None:
    resp = await client.post(
        "/v1/admin/crm/clients",
        json={"tenant_id": tenant_id, "name": "Acme Corp"},
        headers=auth_headers,
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "Acme Corp"
    assert body["tenant_id"] == tenant_id


@db_required
async def test_full_deal_pipeline_and_relationship_score_flow(
    client, auth_headers, tenant_id
) -> None:
    create_resp = await client.post(
        "/v1/admin/crm/clients",
        json={"tenant_id": tenant_id, "name": "Acme Corp"},
        headers=auth_headers,
    )
    client_id = create_resp.json()["client_id"]

    deal_resp = await client.post(
        f"/v1/admin/crm/clients/{client_id}/deals",
        json={"tenant_id": tenant_id, "name": "Big Deal", "value_minor_units": 500_000},
        headers=auth_headers,
    )
    assert deal_resp.status_code == 201
    deal = deal_resp.json()
    assert deal["stage"] == "lead"

    stakeholder_resp = await client.post(
        f"/v1/admin/crm/clients/{client_id}/stakeholders",
        json={"tenant_id": tenant_id, "name": "Bob Smith", "role": "decision_maker"},
        headers=auth_headers,
    )
    assert stakeholder_resp.status_code == 201
    stakeholder_id = stakeholder_resp.json()["stakeholder_id"]

    interaction_resp = await client.post(
        f"/v1/admin/crm/clients/{client_id}/interactions",
        json={
            "tenant_id": tenant_id,
            "deal_id": deal["deal_id"],
            "stakeholder_id": stakeholder_id,
            "interaction_type": "call",
            "occurred_at": "2026-07-08T10:00:00Z",
            "summary": "Intro call",
            "created_by": "Jane Doe",
        },
        headers=auth_headers,
    )
    assert interaction_resp.status_code == 201

    stage_resp = await client.post(
        f"/v1/admin/crm/deals/{deal['deal_id']}/stage",
        json={"tenant_id": tenant_id, "stage": "won", "actor": "Jane Doe"},
        headers=auth_headers,
    )
    assert stage_resp.status_code == 200
    assert stage_resp.json()["stage"] == "won"

    # Already-terminal deal: a second transition is rejected.
    repeat_resp = await client.post(
        f"/v1/admin/crm/deals/{deal['deal_id']}/stage",
        json={"tenant_id": tenant_id, "stage": "lost", "actor": "Jane Doe"},
        headers=auth_headers,
    )
    assert repeat_resp.status_code == 409

    stakeholders_resp = await client.get(
        f"/v1/admin/crm/clients/{client_id}/stakeholders?tenant_id={tenant_id}",
        headers=auth_headers,
    )
    assert stakeholders_resp.status_code == 200
    [row] = stakeholders_resp.json()
    assert row["interaction_count"] == 1

    score_resp = await client.get(
        f"/v1/admin/crm/clients/{client_id}/relationship-score?tenant_id={tenant_id}",
        headers=auth_headers,
    )
    assert score_resp.status_code == 200
    score = score_resp.json()
    assert score["method"] == "recency_frequency_v1"
    assert score["score"] > 0.0

    detail_resp = await client.get(
        f"/v1/admin/crm/clients/{client_id}?tenant_id={tenant_id}", headers=auth_headers
    )
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["client"]["client_id"] == client_id
    assert len(detail["deals"]) == 1
    assert len(detail["recent_interactions"]) == 1
    assert len(detail["stakeholders"]) == 1


@db_required
async def test_deal_scope_mismatch_returns_422(client, auth_headers, tenant_id) -> None:
    client_a = (
        await client.post(
            "/v1/admin/crm/clients",
            json={"tenant_id": tenant_id, "name": "Client A"},
            headers=auth_headers,
        )
    ).json()["client_id"]
    client_b = (
        await client.post(
            "/v1/admin/crm/clients",
            json={"tenant_id": tenant_id, "name": "Client B"},
            headers=auth_headers,
        )
    ).json()["client_id"]
    deal_for_b = (
        await client.post(
            f"/v1/admin/crm/clients/{client_b}/deals",
            json={"tenant_id": tenant_id, "name": "B's Deal"},
            headers=auth_headers,
        )
    ).json()

    resp = await client.post(
        f"/v1/admin/crm/clients/{client_a}/interactions",
        json={
            "tenant_id": tenant_id,
            "deal_id": deal_for_b["deal_id"],
            "interaction_type": "note",
            "occurred_at": "2026-07-08T10:00:00Z",
            "summary": "Should be rejected",
            "created_by": "Jane Doe",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 422


@db_required
async def test_client_detail_404_for_missing_client(client, auth_headers, tenant_id) -> None:
    resp = await client.get(
        f"/v1/admin/crm/clients/99999999-9999-4999-8999-999999999999?tenant_id={tenant_id}",
        headers=auth_headers,
    )
    assert resp.status_code == 404


@db_required
async def test_cross_tenant_client_list_isolated_over_http(
    client, auth_headers, tenant_id, other_tenant_id
) -> None:
    await client.post(
        "/v1/admin/crm/clients",
        json={"tenant_id": tenant_id, "name": "Tenant A's Client"},
        headers=auth_headers,
    )

    resp = await client.get(
        f"/v1/admin/crm/clients?tenant_id={other_tenant_id}", headers=auth_headers
    )
    assert resp.status_code == 200
    assert resp.json() == []
