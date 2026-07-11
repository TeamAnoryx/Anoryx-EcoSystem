"""D-022 non-stubbed HTTP e2e suite: real ASGI app, real auth, real DB."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .conftest import db_required


def _iso(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()


@db_required
async def test_subscriptions_endpoint_401_without_bearer(client, tenant_id) -> None:
    resp = await client.get(f"/v1/admin/subscriptions?tenant_id={tenant_id}")
    assert resp.status_code == 401


@db_required
async def test_full_subscription_lifecycle_over_http(client, auth_headers, tenant_id) -> None:
    create_resp = await client.post(
        "/v1/admin/subscriptions",
        json={
            "tenant_id": tenant_id,
            "name": "Notion",
            "expected_amount_minor_units": 999,
            "cadence": "monthly",
            "created_by": "Jane Doe",
        },
        headers=auth_headers,
    )
    assert create_resp.status_code == 201
    sub = create_resp.json()
    assert sub["status"] == "active"
    assert sub["currency"] == "USD"

    charge_resp = await client.post(
        f"/v1/admin/subscriptions/{sub['subscription_id']}/charges",
        json={
            "tenant_id": tenant_id,
            "amount_minor_units": 999,
            "charged_at": _iso(1),
            "recorded_by": "Jane Doe",
        },
        headers=auth_headers,
    )
    assert charge_resp.status_code == 201
    assert charge_resp.json()["amount_minor_units"] == 999

    charges_resp = await client.get(
        f"/v1/admin/subscriptions/{sub['subscription_id']}/charges?tenant_id={tenant_id}",
        headers=auth_headers,
    )
    assert charges_resp.status_code == 200
    assert len(charges_resp.json()) == 1

    cancel_resp = await client.post(
        f"/v1/admin/subscriptions/{sub['subscription_id']}/cancel",
        json={"tenant_id": tenant_id, "actor": "Bob Smith"},
        headers=auth_headers,
    )
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["status"] == "cancelled"

    # Already-cancelled: a second cancel is rejected.
    repeat_resp = await client.post(
        f"/v1/admin/subscriptions/{sub['subscription_id']}/cancel",
        json={"tenant_id": tenant_id, "actor": "Bob Smith"},
        headers=auth_headers,
    )
    assert repeat_resp.status_code == 409

    list_resp = await client.get(
        f"/v1/admin/subscriptions?tenant_id={tenant_id}", headers=auth_headers
    )
    assert list_resp.status_code == 200
    assert len(list_resp.json()) == 1


@db_required
async def test_create_subscription_against_missing_vendor_returns_404(
    client, auth_headers, tenant_id
) -> None:
    resp = await client.post(
        "/v1/admin/subscriptions",
        json={
            "tenant_id": tenant_id,
            "vendor_id": "99999999-9999-4999-8999-999999999999",
            "name": "Ghost subscription",
            "cadence": "monthly",
            "created_by": "Jane Doe",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 404


@db_required
async def test_charge_against_missing_subscription_returns_404(
    client, auth_headers, tenant_id
) -> None:
    resp = await client.post(
        "/v1/admin/subscriptions/99999999-9999-4999-8999-999999999999/charges",
        json={
            "tenant_id": tenant_id,
            "amount_minor_units": 1000,
            "charged_at": _iso(1),
            "recorded_by": "Jane Doe",
        },
        headers=auth_headers,
    )
    assert resp.status_code == 404


@db_required
async def test_anomaly_report_end_to_end_over_http(client, auth_headers, tenant_id) -> None:
    create_resp = await client.post(
        "/v1/admin/subscriptions",
        json={
            "tenant_id": tenant_id,
            "name": "Cloud Hosting",
            "cadence": "monthly",
            "created_by": "Jane Doe",
        },
        headers=auth_headers,
    )
    subscription_id = create_resp.json()["subscription_id"]

    for days_ago in [200, 170, 140, 110, 80, 50]:
        resp = await client.post(
            f"/v1/admin/subscriptions/{subscription_id}/charges",
            json={
                "tenant_id": tenant_id,
                "amount_minor_units": 1000,
                "charged_at": _iso(days_ago),
                "recorded_by": "Jane Doe",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 201

    spike_resp = await client.post(
        f"/v1/admin/subscriptions/{subscription_id}/charges",
        json={
            "tenant_id": tenant_id,
            "amount_minor_units": 8000,
            "charged_at": _iso(1),
            "recorded_by": "Jane Doe",
        },
        headers=auth_headers,
    )
    assert spike_resp.status_code == 201

    anomalies_resp = await client.get(
        f"/v1/admin/subscriptions/anomalies?tenant_id={tenant_id}&baseline_window=6",
        headers=auth_headers,
    )
    assert anomalies_resp.status_code == 200
    body = anomalies_resp.json()
    assert body["method"] == "trailing_average_ratio_v1"
    rows = {r["subscription_id"]: r for r in body["anomalies"]}
    assert rows[subscription_id]["code"] == "SPEND_SPIKE"
    assert rows[subscription_id]["ratio"] == 8.0


@db_required
async def test_cross_tenant_subscription_list_isolated_over_http(
    client, auth_headers, tenant_id, other_tenant_id
) -> None:
    await client.post(
        "/v1/admin/subscriptions",
        json={
            "tenant_id": tenant_id,
            "name": "Tenant A's subscription",
            "cadence": "monthly",
            "created_by": "Jane Doe",
        },
        headers=auth_headers,
    )

    resp = await client.get(
        f"/v1/admin/subscriptions?tenant_id={other_tenant_id}", headers=auth_headers
    )
    assert resp.status_code == 200
    assert resp.json() == []


@db_required
async def test_baseline_window_out_of_range_returns_422(client, auth_headers, tenant_id) -> None:
    resp = await client.get(
        f"/v1/admin/subscriptions/anomalies?tenant_id={tenant_id}&baseline_window=99",
        headers=auth_headers,
    )
    assert resp.status_code == 422
