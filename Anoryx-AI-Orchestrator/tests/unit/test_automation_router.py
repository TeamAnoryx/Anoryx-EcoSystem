"""Auth/validation boundary for the O-011 automation-rules seam (ADR-0011). No DB.

Mirrors test_identity_router.py / test_distribution_router.py's pattern: the tenant
principal dependency is overridden and the repository layer is monkeypatched at the
`automation.router` module boundary (get_tenant_session + the repo functions imported by
name into that module), so no Postgres is needed anywhere in this file.
"""

from __future__ import annotations

import contextlib

import httpx
import pytest
from sqlalchemy.exc import IntegrityError

from orchestrator.automation import router as automation_router
from orchestrator.security import require_tenant_principal

_PRINCIPAL = "11111111-1111-4111-8111-111111111111"
_OTHER_TENANT_DISTRIBUTION = "22222222-2222-4222-8222-222222222222"
_KNOWN_EVENT_TYPE = "policy_decision_deny"


def _valid_body(**overrides) -> dict:
    body = {
        "name": "redistribute-on-deny",
        "trigger_event_type": _KNOWN_EVENT_TYPE,
        "action_type": "redistribute_policy",
        "action_config": {"distribution_id": "dist-a"},
    }
    body.update(overrides)
    return body


@pytest.fixture
def app(monkeypatch):
    monkeypatch.setenv("ORCH_INGEST_HMAC_SECRET", "unit-ingest-secret")
    from orchestrator.app import create_app

    return create_app()


@pytest.fixture
def test_app(app):
    """The app with the tenant principal dependency overridden (no auth boundary)."""
    app.dependency_overrides[require_tenant_principal] = lambda: _PRINCIPAL
    yield app
    app.dependency_overrides.clear()


class _FakeSession:
    """A minimal stand-in tenant session: supports the no-op commit/rollback the router
    calls, without touching a real DB. The repo-layer functions themselves are
    monkeypatched, so this session object is never otherwise inspected."""

    async def commit(self) -> None:
        return None

    async def rollback(self) -> None:
        return None


def _patch_tenant_session(monkeypatch):
    @contextlib.asynccontextmanager
    async def _fake(_tenant_id):
        yield _FakeSession()

    monkeypatch.setattr(automation_router, "get_tenant_session", _fake)


def _patch_distribution_found(monkeypatch, *, found: bool = True):
    async def _get_distribution(_session, distribution_id):
        if found:
            return {"distribution_id": distribution_id, "tenant_id": _PRINCIPAL}
        return None

    monkeypatch.setattr(automation_router, "get_distribution", _get_distribution)


def _patch_rule_count(monkeypatch, *, count: int = 0):
    async def _count_automation_rules(_session):
        return count

    monkeypatch.setattr(automation_router, "count_automation_rules", _count_automation_rules)


def _patch_rule_cap_lock(monkeypatch):
    """No-op stand-in for the per-tenant advisory lock (TOCTOU fix) — a real Postgres
    connection is unavailable in this no-DB unit-test module, so the lock acquisition
    itself is monkeypatched at the module boundary like every other repo-layer call here.
    """

    async def _lock_automation_rule_cap(_session, _tenant_id):
        return None

    monkeypatch.setattr(automation_router, "lock_automation_rule_cap", _lock_automation_rule_cap)


def _patch_insert(monkeypatch, *, raise_integrity: bool = False):
    async def _insert_automation_rule(_session, row):
        if raise_integrity:
            raise IntegrityError("insert", {}, Exception("duplicate"))
        return {
            **row,
            "created_at": "2026-07-08T12:00:00+00:00",
            "updated_at": "2026-07-08T12:00:00+00:00",
        }

    monkeypatch.setattr(automation_router, "insert_automation_rule", _insert_automation_rule)


async def _post(app, path: str, *, json_body=None, headers=None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.post(path, headers=headers or {}, json=json_body)


async def _get(app, path: str, *, headers=None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.get(path, headers=headers or {})


async def _patch(app, path: str, *, json_body=None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.patch(path, json=json_body)


async def _delete(app, path: str) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.delete(path)


# --------------------------------------------------------------------------- #
# Missing tenant principal -> 401 (real dependency, no override).
# --------------------------------------------------------------------------- #


async def test_missing_principal_post_is_401(app):
    resp = await _post(app, "/v1/automation/rules", json_body=_valid_body())
    assert resp.status_code == 401
    assert resp.json()["error"]["code"] == "unauthorized"


async def test_missing_principal_get_list_is_401(app):
    resp = await _get(app, "/v1/automation/rules")
    assert resp.status_code == 401


async def test_missing_principal_get_executions_is_401(app):
    resp = await _get(app, "/v1/automation/executions")
    assert resp.status_code == 401


# --------------------------------------------------------------------------- #
# POST /v1/automation/rules — structural + closed-set validation (no DB reached).
# --------------------------------------------------------------------------- #


async def test_unknown_field_is_422(test_app):
    resp = await _post(test_app, "/v1/automation/rules", json_body={**_valid_body(), "x": 1})
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_missing_name_is_422(test_app):
    body = {k: v for k, v in _valid_body().items() if k != "name"}
    resp = await _post(test_app, "/v1/automation/rules", json_body=body)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_unknown_event_type_is_422(test_app):
    resp = await _post(
        test_app,
        "/v1/automation/rules",
        json_body=_valid_body(trigger_event_type="not_a_real_event_type"),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "unknown_event_type"


async def test_unknown_source_product_is_422(test_app):
    resp = await _post(
        test_app,
        "/v1/automation/rules",
        json_body=_valid_body(trigger_source_product="not-a-product"),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "unknown_source_product"


async def test_known_source_product_passes_that_check(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)
    _patch_distribution_found(monkeypatch, found=True)
    _patch_rule_cap_lock(monkeypatch)
    _patch_rule_count(monkeypatch, count=0)
    _patch_insert(monkeypatch)
    resp = await _post(
        test_app,
        "/v1/automation/rules",
        json_body=_valid_body(trigger_source_product="sentinel"),
    )
    assert resp.status_code == 201


async def test_non_scalar_condition_value_is_422(test_app):
    resp = await _post(
        test_app,
        "/v1/automation/rules",
        json_body=_valid_body(trigger_conditions={"nested": {"a": 1}}),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_unknown_action_type_is_422(test_app):
    resp = await _post(
        test_app, "/v1/automation/rules", json_body=_valid_body(action_type="delete_everything")
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "unknown_action_type"


async def test_action_config_missing_distribution_id_is_422(test_app):
    resp = await _post(test_app, "/v1/automation/rules", json_body=_valid_body(action_config={}))
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_action_config_extra_key_is_422(test_app):
    resp = await _post(
        test_app,
        "/v1/automation/rules",
        json_body=_valid_body(action_config={"distribution_id": "dist-a", "extra": 1}),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_nul_byte_is_422(test_app):
    resp = await _post(test_app, "/v1/automation/rules", json_body=_valid_body(name="bad\x00name"))
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_too_many_trigger_conditions_keys_is_422(test_app):
    resp = await _post(
        test_app,
        "/v1/automation/rules",
        json_body=_valid_body(trigger_conditions={f"k{i}": i for i in range(21)}),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "trigger_conditions_too_large"


async def test_trigger_conditions_over_byte_cap_is_422(test_app):
    # 50 keys of ~100-char string values comfortably exceeds the 4096-byte cap while
    # staying under the 20-key cap, so this proves the BYTE cap specifically.
    big_value = "x" * 100
    resp = await _post(
        test_app,
        "/v1/automation/rules",
        json_body=_valid_body(trigger_conditions={"only_key": big_value * 50}),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "trigger_conditions_too_large"


# --------------------------------------------------------------------------- #
# Deeply-nested body -> RecursionError caught as 422, never an uncaught 500.
# --------------------------------------------------------------------------- #


async def _post_raw(app, path: str, *, content: bytes) -> httpx.Response:
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        return await client.post(
            path, content=content, headers={"Content-Type": "application/json"}
        )


def _deeply_nested_json_array(depth: int) -> bytes:
    # Built by string multiplication (NOT recursive construction/serialization) so
    # constructing the fixture itself never hits Python's own recursion limit.
    return (b"[" * depth) + (b"]" * depth)


async def test_deeply_nested_create_body_is_422_not_500(test_app):
    resp = await _post_raw(
        test_app, "/v1/automation/rules", content=_deeply_nested_json_array(4000)
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


def _deeply_nested_json_object(depth: int) -> bytes:
    # A single-key-nested OBJECT (not array): json.loads' C decoder tolerates a deeper
    # object/array nesting than pure-Python contains_nul's own recursive walk does, so a
    # depth in this range parses SUCCESSFULLY (json.loads never raises) but blows
    # contains_nul's own call stack — proving THAT specific RecursionError catch site
    # (not merely the json.loads one exercised above).
    return (b'{"n":' * depth) + b"{}" + (b"}" * depth)


async def test_deeply_nested_object_body_is_422_via_contains_nul_guard(test_app):
    resp = await _post_raw(
        test_app, "/v1/automation/rules", content=_deeply_nested_json_object(650)
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_deeply_nested_patch_body_is_422_not_500(test_app):
    transport = httpx.ASGITransport(app=test_app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://orch") as client:
        resp = await client.patch(
            "/v1/automation/rules/rule-abc",
            content=_deeply_nested_json_array(4000),
            headers={"Content-Type": "application/json"},
        )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


# --------------------------------------------------------------------------- #
# POST — distribution ownership + rule-cap + duplicate-name (repo layer mocked).
# --------------------------------------------------------------------------- #


async def test_distribution_not_found_is_422(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)
    _patch_distribution_found(monkeypatch, found=False)
    resp = await _post(test_app, "/v1/automation/rules", json_body=_valid_body())
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "distribution_not_found"


async def test_rule_limit_exceeded_is_422(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)
    _patch_distribution_found(monkeypatch, found=True)
    _patch_rule_cap_lock(monkeypatch)
    _patch_rule_count(monkeypatch, count=20)  # == default ORCH_AUTOMATION_MAX_RULES_PER_TENANT
    resp = await _post(test_app, "/v1/automation/rules", json_body=_valid_body())
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "rule_limit_exceeded"


async def test_duplicate_name_is_409(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)
    _patch_distribution_found(monkeypatch, found=True)
    _patch_rule_cap_lock(monkeypatch)
    _patch_rule_count(monkeypatch, count=0)
    _patch_insert(monkeypatch, raise_integrity=True)
    resp = await _post(test_app, "/v1/automation/rules", json_body=_valid_body())
    assert resp.status_code == 409
    assert resp.json()["error"]["code"] == "duplicate_name"


async def test_create_success_is_201(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)
    _patch_distribution_found(monkeypatch, found=True)
    _patch_rule_cap_lock(monkeypatch)
    _patch_rule_count(monkeypatch, count=0)
    _patch_insert(monkeypatch)
    resp = await _post(test_app, "/v1/automation/rules", json_body=_valid_body())
    assert resp.status_code == 201
    body = resp.json()
    assert body["name"] == "redistribute-on-deny"
    assert body["action_type"] == "redistribute_policy"
    assert body["enabled"] is True
    assert "trigger_source_product" not in body  # opt-in-when-present, absent here


async def test_rule_cap_lock_is_taken_before_the_count(test_app, monkeypatch):
    """Proves the router calls `lock_automation_rule_cap` before `count_automation_rules`
    (TOCTOU fix ordering) — a real concurrent race is proven at the DB layer by the
    integration suite; this unit test proves the call ORDER the router itself performs."""
    _patch_tenant_session(monkeypatch)
    _patch_distribution_found(monkeypatch, found=True)
    _patch_insert(monkeypatch)

    call_order: list[str] = []

    async def _lock_automation_rule_cap(_session, _tenant_id):
        call_order.append("lock")

    async def _count_automation_rules(_session):
        call_order.append("count")
        return 0

    monkeypatch.setattr(automation_router, "lock_automation_rule_cap", _lock_automation_rule_cap)
    monkeypatch.setattr(automation_router, "count_automation_rules", _count_automation_rules)

    resp = await _post(test_app, "/v1/automation/rules", json_body=_valid_body())
    assert resp.status_code == 201
    assert call_order == ["lock", "count"]


# --------------------------------------------------------------------------- #
# GET one / PATCH / DELETE — repo layer mocked.
# --------------------------------------------------------------------------- #


def _sample_row(**overrides) -> dict:
    row = {
        "id": "rule-abc",
        "tenant_id": _PRINCIPAL,
        "name": "redistribute-on-deny",
        "enabled": True,
        "trigger_event_type": _KNOWN_EVENT_TYPE,
        "trigger_source_product": None,
        "trigger_conditions": {},
        "action_type": "redistribute_policy",
        "action_config": {"distribution_id": "dist-a"},
        "created_at": "2026-07-08T12:00:00+00:00",
        "updated_at": "2026-07-08T12:00:00+00:00",
    }
    row.update(overrides)
    return row


async def test_get_unknown_rule_is_404(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _get_automation_rule(_session, _rule_id):
        return None

    monkeypatch.setattr(automation_router, "get_automation_rule", _get_automation_rule)
    resp = await _get(test_app, "/v1/automation/rules/rule-does-not-exist")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "not_found"


async def test_get_known_rule_is_200(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _get_automation_rule(_session, rule_id):
        return _sample_row(id=rule_id)

    monkeypatch.setattr(automation_router, "get_automation_rule", _get_automation_rule)
    resp = await _get(test_app, "/v1/automation/rules/rule-abc")
    assert resp.status_code == 200
    assert resp.json()["id"] == "rule-abc"


async def test_patch_unknown_field_is_422(test_app):
    resp = await _patch(
        test_app, "/v1/automation/rules/rule-abc", json_body={"enabled": True, "name": "x"}
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "schema_invalid"


async def test_patch_non_bool_enabled_is_422(test_app):
    resp = await _patch(test_app, "/v1/automation/rules/rule-abc", json_body={"enabled": "yes"})
    assert resp.status_code == 422


async def test_patch_unknown_rule_is_404(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _update_automation_rule_enabled(_session, *, rule_id, enabled):
        return 0

    monkeypatch.setattr(
        automation_router, "update_automation_rule_enabled", _update_automation_rule_enabled
    )
    resp = await _patch(test_app, "/v1/automation/rules/rule-missing", json_body={"enabled": False})
    assert resp.status_code == 404


async def test_patch_disable_success_is_200(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _update_automation_rule_enabled(_session, *, rule_id, enabled):
        return 1

    async def _get_automation_rule(_session, rule_id):
        return _sample_row(id=rule_id, enabled=False)

    monkeypatch.setattr(
        automation_router, "update_automation_rule_enabled", _update_automation_rule_enabled
    )
    monkeypatch.setattr(automation_router, "get_automation_rule", _get_automation_rule)
    resp = await _patch(test_app, "/v1/automation/rules/rule-abc", json_body={"enabled": False})
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False


async def test_delete_unknown_rule_is_404(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _delete_automation_rule(_session, _rule_id):
        return 0

    monkeypatch.setattr(automation_router, "delete_automation_rule", _delete_automation_rule)
    resp = await _delete(test_app, "/v1/automation/rules/rule-missing")
    assert resp.status_code == 404


async def test_delete_success_is_204(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _delete_automation_rule(_session, _rule_id):
        return 1

    monkeypatch.setattr(automation_router, "delete_automation_rule", _delete_automation_rule)
    resp = await _delete(test_app, "/v1/automation/rules/rule-abc")
    assert resp.status_code == 204


# --------------------------------------------------------------------------- #
# GET /v1/automation/rules — list (repo layer mocked, mirrors test_identity_router.py).
# --------------------------------------------------------------------------- #


async def test_list_rules_projects_expected_fields(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _list_automation_rules(_session, *, limit, cursor):
        return [_sample_row()], None

    monkeypatch.setattr(automation_router, "list_automation_rules", _list_automation_rules)
    resp = await _get(test_app, "/v1/automation/rules")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["data"]) == 1
    assert body["data"][0]["id"] == "rule-abc"
    assert body["next_cursor"] is None


async def test_list_rules_malformed_cursor_is_422(test_app):
    resp = await _get(test_app, "/v1/automation/rules?cursor=not-valid-base64!!!")
    assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# GET /v1/automation/executions (repo layer mocked).
# --------------------------------------------------------------------------- #


async def test_list_executions_projects_expected_fields(test_app, monkeypatch):
    _patch_tenant_session(monkeypatch)

    async def _list_automation_executions(_session, *, limit, cursor):
        row = {
            "rule_id": "rule-abc",
            "tenant_id": _PRINCIPAL,
            "triggering_event_id": "evt-1",
            "action_type": "redistribute_policy",
            "disposition": "executed",
            "error_reason": None,
            "created_at": "2026-07-08T12:00:00+00:00",
        }
        return [row], None

    monkeypatch.setattr(
        automation_router, "list_automation_executions", _list_automation_executions
    )
    resp = await _get(test_app, "/v1/automation/executions")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["data"]) == 1
    assert "error_reason" not in body["data"][0]
