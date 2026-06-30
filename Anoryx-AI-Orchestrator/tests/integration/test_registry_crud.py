"""Registry CRUD + registry-mutation audit chain on a real Postgres (O-005, ADR-0005).

Non-stubbed against the orchestrator DB (no Sentinel needed — endpoints are public IP literals
that validate without an allowlist). Proves: register/modify/deregister persist + append a
hash-chained audit link per mutation; an SSRF-blocked registration is rejected AND recorded as a
`rejected` link (with no registry row created); the chain validates; and the audit log is
append-only at the DB (deny-triggers reject UPDATE/DELETE).
"""

from __future__ import annotations

import uuid

import asyncpg
import pytest

from orchestrator.config import CoordinationSettings, DistributionSettings
from orchestrator.coordination import registry
from orchestrator.coordination.endpoint_validation import EndpointValidationError
from orchestrator.coordination.registry import (
    SentinelConflictError,
    SentinelNotFoundError,
)
from orchestrator.persistence.database import get_privileged_session
from orchestrator.persistence.repositories import validate_registry_chain

pytestmark = pytest.mark.integration


def _settings(
    *, allowlist: frozenset[str] = frozenset(), allow_http: bool = False
) -> CoordinationSettings:
    return CoordinationSettings(
        admin_token=None,
        endpoint_allowlist=allowlist,
        allow_http=allow_http,
        health_path="/healthz",
        health_timeout_seconds=5.0,
        staleness_seconds=300,
        unreachable_threshold=1,
        distribution=DistributionSettings(
            service_token=None,
            sentinel_admin_token="adm",  # noqa: S106 - test fake
            targets={},
            intake_path="/admin/policies/intake",
            max_attempts=2,
            backoff_seconds=0.0,
            http_timeout_seconds=5.0,
        ),
    )


def _sid(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


async def _audit_rows(db_conn, sentinel_id: str) -> list:
    return await db_conn.fetch(
        "SELECT action, disposition, error_reason, endpoint FROM sentinel_registry_audit_log "
        "WHERE sentinel_id = $1 ORDER BY sequence_number ASC",
        sentinel_id,
    )


async def test_register_persists_row_and_accepted_audit_link(db_conn) -> None:
    sid = _sid("reg")
    created = await registry.register_sentinel(
        sentinel_id=sid,
        endpoint="https://8.8.8.8",
        capabilities=["model_allowlist", "model_denylist"],
        settings=_settings(),
    )
    assert created["sentinel_id"] == sid
    assert created["endpoint"] == "https://8.8.8.8"
    assert created["health_status"] == "unknown"
    assert created["capabilities"] == ["model_allowlist", "model_denylist"]
    assert created["enabled"] is True

    fetched = await registry.fetch_sentinel(sid)
    assert fetched is not None
    assert fetched["peer_auth_ref"] == "global"

    rows = await _audit_rows(db_conn, sid)
    assert [(r["action"], r["disposition"]) for r in rows] == [("register", "accepted")]

    async with get_privileged_session() as ps:
        assert await validate_registry_chain(ps) is True


async def test_register_duplicate_is_conflict(db_conn) -> None:
    sid = _sid("dup")
    await registry.register_sentinel(
        sentinel_id=sid,
        endpoint="https://8.8.8.8",
        capabilities=["code_scan"],
        settings=_settings(),
    )
    with pytest.raises(SentinelConflictError):
        await registry.register_sentinel(
            sentinel_id=sid,
            endpoint="https://8.8.4.4",
            capabilities=["code_scan"],
            settings=_settings(),
        )


async def test_modify_updates_fields_and_audits(db_conn) -> None:
    sid = _sid("mod")
    await registry.register_sentinel(
        sentinel_id=sid,
        endpoint="https://8.8.8.8",
        capabilities=["model_allowlist"],
        settings=_settings(),
    )
    updated = await registry.modify_sentinel(
        sid,
        endpoint="https://8.8.4.4",
        capabilities=["model_allowlist", "data_lock"],
        settings=_settings(),
    )
    assert updated["endpoint"] == "https://8.8.4.4"
    assert updated["capabilities"] == ["model_allowlist", "data_lock"]

    rows = await _audit_rows(db_conn, sid)
    assert [(r["action"], r["disposition"]) for r in rows] == [
        ("register", "accepted"),
        ("modify", "accepted"),
    ]


async def test_modify_only_enabled_audits_as_disable(db_conn) -> None:
    sid = _sid("dis")
    await registry.register_sentinel(
        sentinel_id=sid,
        endpoint="https://8.8.8.8",
        capabilities=["model_allowlist"],
        settings=_settings(),
    )
    updated = await registry.modify_sentinel(sid, enabled=False, settings=_settings())
    assert updated["enabled"] is False
    rows = await _audit_rows(db_conn, sid)
    assert rows[-1]["action"] == "disable"


async def test_modify_unknown_is_not_found(db_ready) -> None:
    with pytest.raises(SentinelNotFoundError):
        await registry.modify_sentinel(_sid("ghost"), enabled=False, settings=_settings())


async def test_deregister_removes_row_and_audits(db_conn) -> None:
    sid = _sid("del")
    await registry.register_sentinel(
        sentinel_id=sid,
        endpoint="https://8.8.8.8",
        capabilities=["model_allowlist"],
        settings=_settings(),
    )
    await registry.deregister_sentinel(sid)
    assert await registry.fetch_sentinel(sid) is None
    rows = await _audit_rows(db_conn, sid)
    assert rows[-1]["action"] == "deregister"
    async with get_privileged_session() as ps:
        assert await validate_registry_chain(ps) is True


async def test_deregister_unknown_is_not_found(db_ready) -> None:
    with pytest.raises(SentinelNotFoundError):
        await registry.deregister_sentinel(_sid("ghost"))


async def test_ssrf_blocked_registration_is_recorded_and_no_row(db_conn) -> None:
    sid = _sid("ssrf")
    with pytest.raises(EndpointValidationError) as exc:
        await registry.register_sentinel(
            sentinel_id=sid,
            endpoint="https://10.0.0.9",  # private IP, allowlist empty → blocked
            capabilities=["model_allowlist"],
            settings=_settings(),
        )
    assert exc.value.reason == "blocked_private_ip"

    # No registry row was created.
    assert await registry.fetch_sentinel(sid) is None
    # ...but the rejected attempt IS recorded tamper-evidently, with the attempted endpoint.
    rows = await _audit_rows(db_conn, sid)
    assert [(r["action"], r["disposition"]) for r in rows] == [("register", "rejected")]
    assert rows[0]["error_reason"] == "blocked_private_ip"
    assert rows[0]["endpoint"] == "https://10.0.0.9"

    async with get_privileged_session() as ps:
        assert await validate_registry_chain(ps) is True


async def test_audit_log_is_append_only(db_conn) -> None:
    sid = _sid("append")
    await registry.register_sentinel(
        sentinel_id=sid,
        endpoint="https://8.8.8.8",
        capabilities=["model_allowlist"],
        settings=_settings(),
    )
    # The deny-triggers reject UPDATE and DELETE even on the privileged connection.
    with pytest.raises(asyncpg.PostgresError):
        await db_conn.execute(
            "UPDATE sentinel_registry_audit_log SET disposition = 'accepted' "
            "WHERE sentinel_id = $1",
            sid,
        )
    with pytest.raises(asyncpg.PostgresError):
        await db_conn.execute("DELETE FROM sentinel_registry_audit_log WHERE sentinel_id = $1", sid)
