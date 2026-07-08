"""The /health probe (R-010, ADR-0010 Fork G) — added to the R-003 base app factory so
every layer built on top of it (R-004 DB app, R-005+ chat app) inherits it for free.
"""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_ok(client: TestClient):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_health_not_in_openapi_schema(client: TestClient):
    # include_in_schema=False — the probe is not part of the public v1 contract.
    schema = client.get("/openapi.json").json()
    assert "/health" not in schema.get("paths", {})
