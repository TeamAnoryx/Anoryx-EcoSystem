"""POST/GET/PATCH/DELETE /v1/automation/rules + GET /v1/automation/executions (O-011).

Tenant-scoped CRUD + read, reusing the EXISTING `require_tenant_principal` dependency
from security.py — the SAME credential already gating `/v1/events` and
`/v1/identity/events` reads (no new principal type is invented here).

Validation order at rule-creation time (each a 422 with a distinct code, or a 409 for a
duplicate name — never a 5xx for an ordinary validation failure):
  1. structural (unknown fields / wrong types) -> schema_invalid
  2. trigger_event_type must be one of the F-002 known event types
     (schema_validation.known_event_types(), reused — not a hand-invented allow-list) ->
     unknown_event_type
  3. trigger_source_product, if present, must be a known source product -> unknown_source_product
  4. trigger_conditions values must all be JSON scalars (str/int/float/bool) -> schema_invalid
  5. action_type must be exactly "redistribute_policy" (v1's one supported action) ->
     unknown_action_type
  6. action_config must be {"distribution_id": <non-empty string>} and that distribution
     must belong to THIS tenant (get_distribution under get_tenant_session(principal)) ->
     distribution_not_found
  7. the per-tenant rule cap (ORCH_AUTOMATION_MAX_RULES_PER_TENANT) -> rule_limit_exceeded
  8. UNIQUE(tenant_id, name) -> 409 duplicate_name (caught narrowly around the INSERT)
"""

from __future__ import annotations

import base64
import binascii
import json
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy.exc import IntegrityError

from orchestrator.boundary import contains_nul
from orchestrator.config import KNOWN_IDENTITY_SOURCE_PRODUCTS, AutomationSettings
from orchestrator.persistence.database import get_tenant_session
from orchestrator.persistence.repositories import (
    count_automation_rules,
    delete_automation_rule,
    get_automation_rule,
    get_distribution,
    insert_automation_rule,
    list_automation_executions,
    list_automation_rules,
    update_automation_rule_enabled,
)
from orchestrator.schema_validation import known_event_types
from orchestrator.security import require_tenant_principal

router = APIRouter()

# v1 supports EXACTLY one action type — adding a second is explicit future work (ADR-0011).
_SUPPORTED_ACTION_TYPES = frozenset({"redistribute_policy"})
_ALLOWED_CREATE_KEYS = frozenset(
    {
        "name",
        "trigger_event_type",
        "trigger_source_product",
        "trigger_conditions",
        "action_type",
        "action_config",
        "enabled",
    }
)
_ALLOWED_PATCH_KEYS = frozenset({"enabled"})
_SCALAR_TYPES = (str, int, float, bool)

_MAX_NAME_LEN = 128
_MAX_EVENT_TYPE_LEN = 64

_DEFAULT_LIMIT = 50
_MIN_LIMIT = 1
_MAX_LIMIT = 200
_MAX_CURSOR_LENGTH = 512
_BIGINT_MIN = -9223372036854775808
_BIGINT_MAX = 9223372036854775807


def _request_id() -> str:
    return "req-orch-" + uuid.uuid4().hex[:24]


def _error(status: int, code: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "request_id": request_id}},
        headers={"X-Request-Id": request_id},
    )


def _isoformat(value: object) -> object:
    return value.isoformat() if isinstance(value, datetime) else value


def _clamp_limit(raw: int | None) -> int:
    if raw is None:
        return _DEFAULT_LIMIT
    if raw < _MIN_LIMIT:
        return _MIN_LIMIT
    if raw > _MAX_LIMIT:
        return _MAX_LIMIT
    return raw


def _encode_seq_cursor(sequence_number: int) -> str:
    return base64.urlsafe_b64encode(str(sequence_number).encode("utf-8")).decode("ascii")


def _decode_seq_cursor(cursor: str) -> int:
    value = int(base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8"))
    if not (_BIGINT_MIN <= value <= _BIGINT_MAX):
        raise ValueError("cursor sequence_number is outside the signed BIGINT range")
    return value


def _encode_rule_cursor(created_at: object, rule_id: str) -> str:
    payload = json.dumps([_isoformat(created_at), rule_id])
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii")


def _decode_rule_cursor(cursor: str) -> tuple[str, str]:
    decoded = json.loads(base64.urlsafe_b64decode(cursor.encode("ascii")).decode("utf-8"))
    if (
        not isinstance(decoded, list)
        or len(decoded) != 2
        or not all(isinstance(x, str) and x for x in decoded)
    ):
        raise ValueError("cursor is malformed")
    return decoded[0], decoded[1]


def _rule_body(row: dict[str, Any]) -> dict[str, Any]:
    body: dict[str, Any] = {
        "id": row["id"],
        "tenant_id": row["tenant_id"],
        "name": row["name"],
        "enabled": row["enabled"],
        "trigger_event_type": row["trigger_event_type"],
        "trigger_conditions": row.get("trigger_conditions") or {},
        "action_type": row["action_type"],
        "action_config": row["action_config"],
        "created_at": _isoformat(row["created_at"]),
        "updated_at": _isoformat(row["updated_at"]),
    }
    if row.get("trigger_source_product") is not None:
        body["trigger_source_product"] = row["trigger_source_product"]
    return body


def _execution_body(row: dict[str, Any]) -> dict[str, Any]:
    body: dict[str, Any] = {
        "rule_id": row["rule_id"],
        "tenant_id": row["tenant_id"],
        "triggering_event_id": row["triggering_event_id"],
        "action_type": row["action_type"],
        "disposition": row["disposition"],
        "created_at": _isoformat(row["created_at"]),
    }
    if row.get("error_reason") is not None:
        body["error_reason"] = row["error_reason"]
    return body


def _validate_create_body(body: dict[str, Any]) -> tuple[str, str] | None:
    """Structural + closed-set validation of a POST body. Returns (code, message) for a
    422, or None when valid. Never touches the DB (the distribution-ownership + rule-cap
    checks happen separately, after this passes)."""
    if set(body) - _ALLOWED_CREATE_KEYS:
        return ("schema_invalid", "request contains unknown fields")

    name = body.get("name")
    if not isinstance(name, str) or not name or len(name) > _MAX_NAME_LEN:
        return ("schema_invalid", "name is required")

    trigger_event_type = body.get("trigger_event_type")
    if (
        not isinstance(trigger_event_type, str)
        or not trigger_event_type
        or len(trigger_event_type) > _MAX_EVENT_TYPE_LEN
    ):
        return ("schema_invalid", "trigger_event_type is required")
    if trigger_event_type not in known_event_types():
        return ("unknown_event_type", "trigger_event_type is not a known F-002 event type")

    trigger_source_product = body.get("trigger_source_product")
    if trigger_source_product is not None and (
        not isinstance(trigger_source_product, str)
        or trigger_source_product not in KNOWN_IDENTITY_SOURCE_PRODUCTS
    ):
        return ("unknown_source_product", "trigger_source_product is not a known source product")

    trigger_conditions = body.get("trigger_conditions", {})
    if not isinstance(trigger_conditions, dict):
        return ("schema_invalid", "trigger_conditions must be an object")
    for key, value in trigger_conditions.items():
        if not isinstance(key, str) or not isinstance(value, _SCALAR_TYPES):
            return (
                "schema_invalid",
                "trigger_conditions values must be scalar (string, number, or boolean)",
            )

    action_type = body.get("action_type")
    if action_type not in _SUPPORTED_ACTION_TYPES:
        return ("unknown_action_type", "action_type is not a supported action type")

    action_config = body.get("action_config")
    if not isinstance(action_config, dict) or set(action_config) != {"distribution_id"}:
        return (
            "schema_invalid",
            "action_config for redistribute_policy must be exactly {distribution_id}",
        )
    distribution_id = action_config.get("distribution_id")
    if not isinstance(distribution_id, str) or not distribution_id:
        return ("schema_invalid", "action_config.distribution_id must be a non-empty string")

    enabled = body.get("enabled", True)
    if not isinstance(enabled, bool):
        return ("schema_invalid", "enabled must be a boolean")

    return None


@router.post("/v1/automation/rules")
async def create_automation_rule(
    request: Request, principal: str = Depends(require_tenant_principal)
) -> JSONResponse:
    request_id = _request_id()
    raw_body = await request.body()
    try:
        body = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _error(422, "schema_invalid", "request body is not valid JSON", request_id)
    if not isinstance(body, dict):
        return _error(422, "schema_invalid", "request body must be a JSON object", request_id)
    if contains_nul(body):
        return _error(
            422, "schema_invalid", "request contains a forbidden NUL character", request_id
        )

    structural = _validate_create_body(body)
    if structural is not None:
        code, message = structural
        return _error(422, code, message, request_id)

    distribution_id = body["action_config"]["distribution_id"]

    async with get_tenant_session(principal) as session:
        # 1. The referenced distribution must exist AND belong to THIS tenant (RLS-scoped
        #    lookup — a cross-tenant reference is invisible here, same as a missing one).
        distribution = await get_distribution(session, distribution_id)
        if distribution is None:
            return _error(
                422,
                "distribution_not_found",
                "action_config.distribution_id does not exist for this tenant",
                request_id,
            )

        # 2. Per-tenant rule cap (bounds worst-case per-event evaluation cost).
        settings: AutomationSettings = request.app.state.automation_settings
        existing_count = await count_automation_rules(session)
        if existing_count >= settings.max_rules_per_tenant:
            return _error(
                422,
                "rule_limit_exceeded",
                "this tenant has reached its automation-rule limit",
                request_id,
            )

        row = {
            "id": "rule-" + uuid.uuid4().hex,
            "tenant_id": principal,
            "name": body["name"],
            "enabled": body.get("enabled", True),
            "trigger_event_type": body["trigger_event_type"],
            "trigger_source_product": body.get("trigger_source_product"),
            "trigger_conditions": body.get("trigger_conditions", {}),
            "action_type": body["action_type"],
            "action_config": body["action_config"],
        }
        try:
            inserted = await insert_automation_rule(session, row)
        except IntegrityError:
            await session.rollback()
            return _error(
                409,
                "duplicate_name",
                "an automation rule with this name already exists",
                request_id,
            )
        await session.commit()

    return JSONResponse(
        status_code=201, content=_rule_body(inserted), headers={"X-Request-Id": request_id}
    )


@router.get("/v1/automation/rules")
async def list_rules(
    principal: str = Depends(require_tenant_principal),
    limit: int | None = Query(default=None),
    cursor: str | None = Query(default=None, max_length=_MAX_CURSOR_LENGTH),
) -> JSONResponse:
    request_id = _request_id()
    limit_value = _clamp_limit(limit)
    decoded_cursor: tuple[str, str] | None = None
    if cursor is not None:
        try:
            decoded_cursor = _decode_rule_cursor(cursor)
        except (ValueError, KeyError, TypeError, binascii.Error, json.JSONDecodeError):
            return _error(422, "schema_invalid", "cursor is malformed", request_id)

    async with get_tenant_session(principal) as session:
        rows, next_cursor = await list_automation_rules(
            session, limit=limit_value, cursor=decoded_cursor
        )
    body = {
        "data": [_rule_body(row) for row in rows],
        "next_cursor": _encode_rule_cursor(*next_cursor) if next_cursor is not None else None,
    }
    return JSONResponse(status_code=200, content=body, headers={"X-Request-Id": request_id})


@router.get("/v1/automation/rules/{rule_id}")
async def get_rule(
    rule_id: str, principal: str = Depends(require_tenant_principal)
) -> JSONResponse:
    request_id = _request_id()
    async with get_tenant_session(principal) as session:
        row = await get_automation_rule(session, rule_id)
    if row is None:
        return _error(404, "not_found", "automation rule not found", request_id)
    return JSONResponse(
        status_code=200, content=_rule_body(row), headers={"X-Request-Id": request_id}
    )


@router.patch("/v1/automation/rules/{rule_id}")
async def patch_rule(
    rule_id: str, request: Request, principal: str = Depends(require_tenant_principal)
) -> JSONResponse:
    request_id = _request_id()
    raw_body = await request.body()
    try:
        body = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _error(422, "schema_invalid", "request body is not valid JSON", request_id)
    if not isinstance(body, dict):
        return _error(422, "schema_invalid", "request body must be a JSON object", request_id)
    if set(body) != _ALLOWED_PATCH_KEYS or not isinstance(body.get("enabled"), bool):
        return _error(
            422, "schema_invalid", "request body must be exactly {enabled: <boolean>}", request_id
        )

    async with get_tenant_session(principal) as session:
        rowcount = await update_automation_rule_enabled(
            session, rule_id=rule_id, enabled=body["enabled"]
        )
        if rowcount == 0:
            return _error(404, "not_found", "automation rule not found", request_id)
        await session.commit()

    # A FRESH tenant session for the re-read: get_tenant_session's SET LOCAL tenant GUC is
    # transaction-scoped and reverts once the update above committed, so reusing the same
    # session here would run the read with no tenant context set (RLS -> zero rows -> a
    # false 404). Mirrors distribution/router.py's two-separate-sessions precedent.
    async with get_tenant_session(principal) as session:
        row = await get_automation_rule(session, rule_id)
    return JSONResponse(
        status_code=200, content=_rule_body(row), headers={"X-Request-Id": request_id}
    )


@router.delete("/v1/automation/rules/{rule_id}")
async def delete_rule(
    rule_id: str, principal: str = Depends(require_tenant_principal)
) -> JSONResponse:
    request_id = _request_id()
    async with get_tenant_session(principal) as session:
        rowcount = await delete_automation_rule(session, rule_id)
        if rowcount == 0:
            return _error(404, "not_found", "automation rule not found", request_id)
        await session.commit()
    return Response(status_code=204, headers={"X-Request-Id": request_id})


@router.get("/v1/automation/executions")
async def list_executions(
    principal: str = Depends(require_tenant_principal),
    limit: int | None = Query(default=None),
    cursor: str | None = Query(default=None, max_length=_MAX_CURSOR_LENGTH),
) -> JSONResponse:
    request_id = _request_id()
    limit_value = _clamp_limit(limit)
    decoded_cursor: int | None = None
    if cursor is not None:
        try:
            decoded_cursor = _decode_seq_cursor(cursor)
        except (ValueError, KeyError, TypeError, binascii.Error):
            return _error(422, "schema_invalid", "cursor is malformed", request_id)

    async with get_tenant_session(principal) as session:
        rows, next_seq = await list_automation_executions(
            session, limit=limit_value, cursor=decoded_cursor
        )
    body = {
        "data": [_execution_body(row) for row in rows],
        "next_cursor": _encode_seq_cursor(next_seq) if next_seq is not None else None,
    }
    return JSONResponse(status_code=200, content=body, headers={"X-Request-Id": request_id})
