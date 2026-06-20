"""Small shared helpers for admin routes (F-012a)."""

from __future__ import annotations

import json
import re
import uuid
from typing import TypeVar

from fastapi import HTTPException, Path
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ValidationError
from starlette.requests import Request

_M = TypeVar("_M", bound=BaseModel)

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def validate_tenant_id_path(tenant_id: str = Path(...)) -> str:
    """Router dependency: reject a non-UUID {tenant_id} with 422 BEFORE any session
    opens or any audit event is appended (security-audit MED-1).

    Without this, a non-UUID path segment would still cause emit_admin_event to
    append an audit row whose tenant_id violates contracts/events.schema.json —
    silent contract corruption of the immutable hash chain consumed by Delta /
    the Orchestrator.
    """
    if not _UUID_RE.match(tenant_id):
        raise HTTPException(status_code=422, detail="invalid_tenant_id")
    return tenant_id


def request_id(request: Request) -> str:
    """Return the canonical request_id (set by TerminalAuditMiddleware) or a fallback.

    The id is used to correlate admin audit events with the originating request.
    Conforms to events.schema ^[A-Za-z0-9._-]{1,64}$.
    """
    rid = getattr(request.state, "request_id", None)
    return rid if rid else "req-" + uuid.uuid4().hex[:32]


async def parse_body(request: Request, model: type[_M]) -> _M:
    """Parse + validate a JSON request body against a pydantic model.

    RequestValidationMiddleware reads the body into request.state.raw_body and
    does NOT re-inject it into the ASGI receive channel, so FastAPI body params
    arrive null. Admin POST/PATCH routes therefore parse raw_body here (the same
    pattern as gateway/routes/compliance.py::export). Invalid JSON or schema
    violations (incl. extra fields under extra='forbid') -> 422.
    """
    raw = getattr(request.state, "raw_body", None)
    if raw is None:
        raw = await request.body()  # fallback (e.g. tests without the middleware)
    try:
        data = json.loads(raw)
    except Exception as exc:
        raise RequestValidationError(
            errors=[{"type": "json_invalid", "loc": ["body"], "msg": "invalid JSON", "input": None}]
        ) from exc
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise RequestValidationError(errors=exc.errors()) from exc
