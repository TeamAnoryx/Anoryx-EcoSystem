"""D-017 non-stubbed HTTP e2e suite: real ASGI app, real auth, real DB. Covers both
the new /v1/admin/rbac/* surface AND the D-008 dashboards retrofit.
"""

from __future__ import annotations

from .conftest import db_required


@db_required
async def test_rbac_tokens_endpoint_401_without_bearer(client, tenant_id) -> None:
    resp = await client.get(f"/v1/admin/rbac/tokens?tenant_id={tenant_id}")
    assert resp.status_code == 401


@db_required
async def test_dashboards_still_401_without_bearer(client, tenant_id) -> None:
    resp = await client.get(
        f"/v1/admin/dashboards/summary?tenant_id={tenant_id}"
        "&start=2026-01-01T00:00:00Z&end=2026-12-31T00:00:00Z"
    )
    assert resp.status_code == 401


@db_required
async def test_dashboards_still_works_with_break_glass_token(
    client, auth_headers, tenant_id
) -> None:
    # Backward compatibility: the D-007 break-glass bearer must keep working exactly
    # as it did before this task retrofitted the dashboards router.
    resp = await client.get(
        f"/v1/admin/dashboards/summary?tenant_id={tenant_id}"
        "&start=2026-01-01T00:00:00Z&end=2026-12-31T00:00:00Z",
        headers=auth_headers,
    )
    assert resp.status_code == 200


@db_required
async def test_full_rbac_flow_over_http(client, auth_headers, tenant_id) -> None:
    # 1. Break-glass token issues a tenant_auditor token.
    issue_resp = await client.post(
        "/v1/admin/rbac/tokens",
        json={"tenant_id": tenant_id, "name": "CI viewer", "role": "tenant_auditor"},
        headers=auth_headers,
    )
    assert issue_resp.status_code == 201
    issued = issue_resp.json()
    assert issued["role"] == "tenant_auditor"
    raw_token = issued["token"]
    auditor_headers = {"Authorization": f"Bearer {raw_token}"}

    # 2. The auditor token CAN read dashboards.
    dash_resp = await client.get(
        f"/v1/admin/dashboards/summary?tenant_id={tenant_id}"
        "&start=2026-01-01T00:00:00Z&end=2026-12-31T00:00:00Z",
        headers=auditor_headers,
    )
    assert dash_resp.status_code == 200

    # 3. The auditor token CANNOT issue new tokens (needs tenant_admin).
    forbidden_resp = await client.post(
        "/v1/admin/rbac/tokens",
        json={"tenant_id": tenant_id, "name": "x", "role": "tenant_auditor"},
        headers=auditor_headers,
    )
    assert forbidden_resp.status_code == 401

    # 4. Listing tokens (admin-only) never exposes the raw token.
    list_resp = await client.get(
        f"/v1/admin/rbac/tokens?tenant_id={tenant_id}", headers=auth_headers
    )
    assert list_resp.status_code == 200
    listed = list_resp.json()
    assert len(listed) == 1
    assert "token" not in listed[0]

    # 5. Revoke the auditor token.
    revoke_resp = await client.post(
        f"/v1/admin/rbac/tokens/{issued['token_id']}/revoke",
        json={"tenant_id": tenant_id},
        headers=auth_headers,
    )
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["revoked_at"] is not None

    # 6. The revoked token can no longer read dashboards.
    dash_after_resp = await client.get(
        f"/v1/admin/dashboards/summary?tenant_id={tenant_id}"
        "&start=2026-01-01T00:00:00Z&end=2026-12-31T00:00:00Z",
        headers=auditor_headers,
    )
    assert dash_after_resp.status_code == 401


@db_required
async def test_cross_tenant_token_cannot_read_other_tenant_dashboards(
    client, auth_headers, tenant_id, other_tenant_id
) -> None:
    issue_resp = await client.post(
        "/v1/admin/rbac/tokens",
        json={"tenant_id": tenant_id, "name": "CI viewer", "role": "tenant_auditor"},
        headers=auth_headers,
    )
    raw_token = issue_resp.json()["token"]

    resp = await client.get(
        f"/v1/admin/dashboards/summary?tenant_id={other_tenant_id}"
        "&start=2026-01-01T00:00:00Z&end=2026-12-31T00:00:00Z",
        headers={"Authorization": f"Bearer {raw_token}"},
    )
    assert resp.status_code == 401


@db_required
async def test_revoke_missing_token_returns_404(client, auth_headers, tenant_id) -> None:
    resp = await client.post(
        "/v1/admin/rbac/tokens/99999999-9999-4999-8999-999999999999/revoke",
        json={"tenant_id": tenant_id},
        headers=auth_headers,
    )
    assert resp.status_code == 404


@db_required
async def test_bogus_bearer_token_rejected_by_rbac_endpoints(client, tenant_id) -> None:
    resp = await client.get(
        f"/v1/admin/rbac/tokens?tenant_id={tenant_id}",
        headers={"Authorization": "Bearer not-a-real-token"},
    )
    assert resp.status_code == 401
