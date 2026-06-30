"""Sentinel-registry CRUD orchestration (O-005, ADR-0005).

Operator-scoped registry of Sentinel instances. Every mutation runs on the PRIVILEGED session
(the registry is operator-global infra, not tenant data — no RLS), validates its endpoint
through the SSRF gate BEFORE persisting, and appends a hash-chained registry-mutation audit
link in the SAME transaction (atomic: the row and its `accepted` link commit together). An
SSRF-blocked registration is recorded with disposition='rejected' (tamper-evident proof of the
attempt) and then raised. Reads are privileged, no transaction.

This module owns session lifecycle + validation + audit; the row-level data access lives in
persistence.repositories (mirrors how the O-004 router/engine own sessions and repositories
owns `session.execute`).
"""

from __future__ import annotations

import json
import re
from typing import Any

from orchestrator.config import CoordinationSettings
from orchestrator.coordination.endpoint_validation import (
    EndpointValidationError,
    validate_endpoint,
)
from orchestrator.persistence import repositories as repo
from orchestrator.persistence.database import get_privileged_session

# The SIX locked policy_type values (mirrors the locked policy.schema.json closed set and the
# 0002 migration CHECK). A Sentinel may only declare capabilities drawn from this set.
KNOWN_POLICY_TYPES = frozenset(
    {
        "budget_limit",
        "model_allowlist",
        "model_approval",
        "model_denylist",
        "code_scan",
        "data_lock",
    }
)

_SENTINEL_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_MAX_PEER_AUTH_REF = 128


class RegistryValidationError(ValueError):
    """A registry input failed semantic validation (bad id/capabilities). Maps to 422.

    `reason` is a short stable code for the audit/error envelope.
    """

    def __init__(self, reason: str, message: str | None = None) -> None:
        self.reason = reason
        super().__init__(message or reason)


class SentinelNotFoundError(LookupError):
    """A modify/deregister targeted an unknown sentinel_id. Maps to 404."""


class SentinelConflictError(ValueError):
    """A register targeted an already-registered sentinel_id. Maps to 409."""


def _validate_sentinel_id(sentinel_id: object) -> str:
    if not isinstance(sentinel_id, str) or not _SENTINEL_ID_PATTERN.match(sentinel_id):
        raise RegistryValidationError("invalid_sentinel_id", "sentinel_id is malformed")
    return sentinel_id


def _validate_capabilities(capabilities: object) -> list[str]:
    """Normalise + validate declared capabilities → a non-empty, deduped list of known types."""
    if not isinstance(capabilities, list) or not capabilities:
        raise RegistryValidationError(
            "invalid_capabilities", "capabilities must be a non-empty array of policy_types"
        )
    seen: set[str] = set()
    normalized: list[str] = []
    for cap in capabilities:
        if not isinstance(cap, str) or cap not in KNOWN_POLICY_TYPES:
            raise RegistryValidationError(
                "invalid_capabilities", "capabilities must all be known policy_types"
            )
        if cap not in seen:
            seen.add(cap)
            normalized.append(cap)
    return normalized


def _validate_peer_auth_ref(peer_auth_ref: object) -> str:
    if peer_auth_ref is None:
        return "global"
    if (
        not isinstance(peer_auth_ref, str)
        or not peer_auth_ref
        or len(peer_auth_ref) > _MAX_PEER_AUTH_REF
    ):
        raise RegistryValidationError("invalid_peer_auth_ref", "peer_auth_ref is malformed")
    return peer_auth_ref


def _canon_capabilities(capabilities: list[str]) -> str:
    """Canonical JSON string of capabilities for the audit chain (deterministic, opt-in field)."""
    return json.dumps(capabilities, separators=(",", ":"), ensure_ascii=False)


async def _audit(
    *,
    sentinel_id: str,
    action: str,
    disposition: str,
    endpoint: str | None = None,
    capabilities: list[str] | None = None,
    error_reason: str | None = None,
) -> None:
    """Append one registry-mutation audit link in its own privileged transaction."""
    caps_json = _canon_capabilities(capabilities) if capabilities is not None else None
    async with get_privileged_session() as psession:
        async with psession.begin():
            await repo.append_registry_audit_link(
                psession,
                sentinel_id=sentinel_id,
                action=action,
                disposition=disposition,
                endpoint=endpoint,
                capabilities=caps_json,
                error_reason=error_reason,
            )


async def register_sentinel(
    *,
    sentinel_id: object,
    endpoint: object,
    capabilities: object,
    peer_auth_ref: object = None,
    settings: CoordinationSettings,
) -> dict[str, Any]:
    """Register a Sentinel instance. Validates id + capabilities + endpoint (SSRF), then persists.

    On SSRF endpoint failure: appends a `rejected` audit link (recording the attempted endpoint),
    then raises EndpointValidationError. On a duplicate id: raises SentinelConflictError. On
    success: persists the row + an `accepted` audit link atomically and returns the created row.
    """
    sid = _validate_sentinel_id(sentinel_id)
    caps = _validate_capabilities(capabilities)
    ref = _validate_peer_auth_ref(peer_auth_ref)
    if not isinstance(endpoint, str):
        raise RegistryValidationError("invalid_endpoint", "endpoint must be a string")

    try:
        normalized_endpoint = validate_endpoint(
            endpoint, allowlist=settings.endpoint_allowlist, allow_http=settings.allow_http
        )
    except EndpointValidationError as exc:
        # Record the SSRF-blocked attempt tamper-evidently (the attempted endpoint is stored).
        await _audit(
            sentinel_id=sid,
            action="register",
            disposition="rejected",
            endpoint=endpoint,
            capabilities=caps,
            error_reason=exc.reason,
        )
        raise

    async with get_privileged_session() as psession:
        async with psession.begin():
            if await repo.get_sentinel(psession, sid) is not None:
                raise SentinelConflictError(f"sentinel_id {sid!r} is already registered")
            await repo.insert_sentinel(
                psession,
                {
                    "sentinel_id": sid,
                    "endpoint": normalized_endpoint,
                    "peer_auth_ref": ref,
                    "capabilities": caps,
                    "health_status": "unknown",
                },
            )
            await repo.append_registry_audit_link(
                psession,
                sentinel_id=sid,
                action="register",
                disposition="accepted",
                endpoint=normalized_endpoint,
                capabilities=_canon_capabilities(caps),
            )
    created = await fetch_sentinel(sid)
    assert created is not None  # noqa: S101 - just committed it in the same process
    return created


async def modify_sentinel(
    sentinel_id: str,
    *,
    endpoint: object = None,
    capabilities: object = None,
    peer_auth_ref: object = None,
    enabled: object = None,
    settings: CoordinationSettings,
) -> dict[str, Any]:
    """Modify a registered Sentinel's mutable fields. Only provided fields change.

    Re-validates the endpoint (SSRF) when it changes (rejected attempt audited). The audit
    action is `enable`/`disable` when ONLY `enabled` toggles, else `modify`. 404 on unknown id.
    """
    values: dict[str, Any] = {}
    audit_caps: list[str] | None = None
    audit_endpoint: str | None = None

    if endpoint is not None:
        if not isinstance(endpoint, str):
            raise RegistryValidationError("invalid_endpoint", "endpoint must be a string")
        try:
            normalized = validate_endpoint(
                endpoint, allowlist=settings.endpoint_allowlist, allow_http=settings.allow_http
            )
        except EndpointValidationError as exc:
            await _audit(
                sentinel_id=sentinel_id,
                action="modify",
                disposition="rejected",
                endpoint=endpoint,
                error_reason=exc.reason,
            )
            raise
        values["endpoint"] = normalized
        audit_endpoint = normalized
    if capabilities is not None:
        caps = _validate_capabilities(capabilities)
        values["capabilities"] = caps
        audit_caps = caps
    if peer_auth_ref is not None:
        values["peer_auth_ref"] = _validate_peer_auth_ref(peer_auth_ref)
    if enabled is not None:
        if not isinstance(enabled, bool):
            raise RegistryValidationError("invalid_enabled", "enabled must be a boolean")
        values["enabled"] = enabled

    if not values:
        raise RegistryValidationError("empty_modification", "no modifiable fields supplied")

    only_enabled = set(values) == {"enabled"}
    action = ("enable" if values["enabled"] else "disable") if only_enabled else "modify"

    async with get_privileged_session() as psession:
        async with psession.begin():
            if await repo.get_sentinel(psession, sentinel_id) is None:
                raise SentinelNotFoundError(f"sentinel_id {sentinel_id!r} is not registered")
            await repo.update_sentinel(psession, sentinel_id=sentinel_id, values=values)
            await repo.append_registry_audit_link(
                psession,
                sentinel_id=sentinel_id,
                action=action,
                disposition="accepted",
                endpoint=audit_endpoint,
                capabilities=_canon_capabilities(audit_caps) if audit_caps is not None else None,
            )
    updated = await fetch_sentinel(sentinel_id)
    assert updated is not None  # noqa: S101 - just updated it
    return updated


async def deregister_sentinel(sentinel_id: str, *, settings: CoordinationSettings) -> None:
    """Deregister (delete) a Sentinel instance + audit `deregister`. 404 on unknown id."""
    async with get_privileged_session() as psession:
        async with psession.begin():
            existing = await repo.get_sentinel(psession, sentinel_id)
            if existing is None:
                raise SentinelNotFoundError(f"sentinel_id {sentinel_id!r} is not registered")
            await repo.delete_sentinel(psession, sentinel_id)
            await repo.append_registry_audit_link(
                psession,
                sentinel_id=sentinel_id,
                action="deregister",
                disposition="accepted",
                endpoint=existing["endpoint"],
            )


async def fetch_sentinel(sentinel_id: str) -> dict[str, Any] | None:
    """Return one registered Sentinel as a dict, or None (privileged read)."""
    async with get_privileged_session() as psession:
        return await repo.get_sentinel(psession, sentinel_id)


async def fetch_sentinels() -> list[dict[str, Any]]:
    """Return every registered Sentinel as a list of dicts (privileged read)."""
    async with get_privileged_session() as psession:
        return await repo.list_sentinels(psession)
