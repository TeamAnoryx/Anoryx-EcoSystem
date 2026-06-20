"""Compliance evidence endpoints (F-011, ADR-0013 §12).

GET  /v1/compliance/evidence  — audit-ready evidence summary (tenant self-service).
POST /v1/compliance/export    — signed, tamper-evident compliance evidence pack ZIP.

Auth: tenant Bearer virtual key (same scheme as /v1/chat/completions).
Tenant is SERVER-RESOLVED from the verified key — there is NO tenant_id param.
Evidence reads run under the sentinel_app RLS role (ADR-0013 §2 D1).

R1: the evidence generation path issues ZERO writes to events_audit_log.
The two compliance meta-events (compliance_evidence_generated /
compliance_pack_exported) are SEPARATE, EXPLICIT best-effort appends AFTER
generation — appending a new row is the log's designed behaviour, never a
mutation of existing rows (ADR-0013 §8 D7).

Honest framing: "audit-ready" throughout; never "compliant".
Mandatory disclaimer on every artifact:
  "Automated evidence for audit preparation. Certification requires an
   accredited auditor."
"""

from __future__ import annotations

import hashlib
import os
import tempfile
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog
from fastapi import APIRouter, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ValidationError, field_validator

from compliance.constants import DISCLAIMER, SENTINEL_VERSION, STATUS_GAP, STATUS_NOT_COVERED
from compliance.errors import EvidenceWindowError, PackSigningKeyError
from compliance.evidence import generate_evidence, read_chain_segment
from compliance.gap_analysis import analyze_gaps
from compliance.mapping import load_framework
from compliance.pack import (
    build_pack_record,
    export_pack_zip,
    load_pack_signing_keys,
    sign_pack,
)
from gateway.exceptions import GatewayError
from gateway.middleware.tenant_context import resolve_tenant_context
from persistence.database import get_privileged_session
from persistence.repositories.audit_log_repository import AuditLogRepository

log = structlog.get_logger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Sentinel version string (embedded in pack records)
# ---------------------------------------------------------------------------

# Pack/evidence sentinel_version; single source in compliance.constants so the
# HTTP route and the CLI never embed divergent values (code-review LOW-13).
_SENTINEL_VERSION = SENTINEL_VERSION

# ---------------------------------------------------------------------------
# Agent slug for compliance meta-events (ADR-0013 §8 D7)
# ---------------------------------------------------------------------------

_COMPLIANCE_AGENT_ID = "compliance-engine"

# ---------------------------------------------------------------------------
# Request model for POST /v1/compliance/export
# ---------------------------------------------------------------------------


class ExportRequest(BaseModel):
    """Closed request body for POST /v1/compliance/export.

    additionalProperties are rejected by Pydantic's model_config
    (extra='forbid') — an injected 'tenant_id' field returns 422.
    The tenant is SERVER-RESOLVED; no tenant_id field exists.
    """

    model_config = {"extra": "forbid"}

    framework: str
    t0: str
    t1: str

    @field_validator("framework")
    @classmethod
    def _validate_framework(cls, v: str) -> str:
        if v not in ("SOC2", "ISO27001"):
            raise ValueError("framework must be SOC2 or ISO27001")
        return v


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_datetime(value: str, param_name: str) -> datetime:
    """Parse an ISO 8601 / RFC 3339 datetime string; 400 on parse failure."""
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z"):
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except ValueError:
        raise GatewayError("invalid_request") from None


def _build_evidence_summary(
    framework_map,
    gap_report,
    t0_str: str,
    t1_str: str,
) -> dict[str, Any]:
    """Build the ComplianceEvidenceSummary response dict (openapi schema)."""
    controls = [
        {
            "control_id": r.control_id,
            "title": r.title,
            "status": r.status,
            "evidence_event_count": r.evidence_count,
        }
        for r in gap_report.results
    ]
    gaps = [
        r.control_id for r in gap_report.results if r.status in (STATUS_GAP, STATUS_NOT_COVERED)
    ]
    return {
        "framework": gap_report.framework,
        "framework_version": gap_report.framework_version,
        "window": {"t0": t0_str, "t1": t1_str},
        "controls": controls,
        "gaps": gaps,
        "readiness_score": gap_report.readiness,
        "disclaimer": DISCLAIMER,
    }


async def _emit_compliance_event(event_data: dict[str, Any]) -> None:
    """Best-effort append of a compliance meta-event to the audit log.

    Mirrors emit_routing_decision / emit_rate_limit_event: uses
    get_privileged_session() + AuditLogRepository.append().  Exceptions are
    swallowed and logged at ERROR — a failed emit MUST NOT fail the request
    (ADR-0013 §8 D7; R1: the emit is a SEPARATE explicit append, never a
    mutation of the generation read path).
    """
    try:
        async with get_privileged_session() as session:
            async with session.begin():
                repo = AuditLogRepository(session)
                await repo.append(event_data)
        log.info(
            "compliance_event_appended",
            event_type=event_data.get("event_type"),
            request_id=event_data.get("request_id"),
        )
    except Exception:
        log.error(
            "compliance_event_append_failed",
            event_type=event_data.get("event_type"),
            request_id=event_data.get("request_id"),
        )


def _build_compliance_event(
    event_type: str,
    *,
    request_id: str,
    tenant_id: str,
    team_id: str,
    project_id: str,
    virtual_key_id: str,
    framework: str,
    framework_version: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a compliance meta-event dict with real four IDs (ADR-0013 §8 D7).

    agent_id = 'compliance-engine' (the emitting component slug, not the
    end-user agent).  Carries the caller's REAL tenant_id/team_id/project_id
    resolved from the Bearer key — NOT WILDCARD_UUID (D7 §8: these are
    tenant-attributed actions).
    """
    now_utc = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    data: dict[str, Any] = {
        "event_type": event_type,
        "tenant_id": tenant_id,
        "team_id": team_id,
        "project_id": project_id,
        "agent_id": _COMPLIANCE_AGENT_ID,
        "event_id": str(uuid.uuid4()),
        "event_timestamp": now_utc,
        "request_id": request_id,
        "action_taken": "logged",
        "framework": framework,
        "framework_version": framework_version,
    }
    if extra:
        data.update(extra)
    return data


# ---------------------------------------------------------------------------
# GET /v1/compliance/evidence
# ---------------------------------------------------------------------------


@router.get("/v1/compliance/evidence", include_in_schema=True)
async def get_compliance_evidence(
    request: Request,
    framework: str = Query(..., description="SOC2 or ISO27001"),
    t0: str = Query(..., description="Window start (ISO 8601 / RFC 3339)"),
    t1: str = Query(..., description="Window end (ISO 8601 / RFC 3339)"),
) -> JSONResponse:
    """Return an audit-ready compliance evidence summary for the authenticated tenant.

    Auth: tenant Bearer virtual key (same as /v1/chat/completions).
    Tenant is server-resolved; no tenant_id query param exists.
    Evidence read is zero-write (R1).  The meta-audit emit is best-effort.
    """
    request_id: str = getattr(request.state, "request_id", None) or ("req-" + uuid.uuid4().hex[:32])

    # Step 5: ID cross-check + tenant context resolution (same as chat route).
    ctx = resolve_tenant_context(request)

    # Validate framework.
    if framework not in ("SOC2", "ISO27001"):
        raise GatewayError("invalid_request")

    # Parse and validate window.
    t0_dt = _parse_datetime(t0, "t0")
    t1_dt = _parse_datetime(t1, "t1")
    try:
        from compliance.evidence import validate_window

        validate_window(t0_dt, t1_dt)
    except EvidenceWindowError:
        raise GatewayError("invalid_request") from None

    # Load framework mapping (fail-closed on unknown/malformed).
    try:
        framework_map = load_framework(framework)
    except Exception:
        log.exception("compliance_framework_load_failed", framework=framework)
        raise GatewayError("internal_error") from None

    # Generate evidence (R1: zero writes on this path).
    try:
        projection = await generate_evidence(framework_map, t0_dt, t1_dt, tenant_id=ctx.tenant_id)
    except EvidenceWindowError:
        raise GatewayError("invalid_request") from None
    except Exception:
        log.exception("compliance_evidence_generation_failed", request_id=request_id)
        raise GatewayError("internal_error") from None

    # Gap analysis.
    try:
        gap_report = analyze_gaps(framework_map, projection)
    except Exception:
        log.exception("compliance_gap_analysis_failed", request_id=request_id)
        raise GatewayError("internal_error") from None

    # Build response.
    summary = _build_evidence_summary(framework_map, gap_report, t0, t1)

    # Best-effort meta-audit emit (SEPARATE explicit append — R1 nuance D7).
    event_data = _build_compliance_event(
        "compliance_evidence_generated",
        request_id=request_id,
        tenant_id=ctx.tenant_id,
        team_id=ctx.team_id,
        project_id=ctx.project_id,
        virtual_key_id=ctx.virtual_key_id,
        framework=framework,
        framework_version=framework_map.framework_version,
    )
    await _emit_compliance_event(event_data)

    return JSONResponse(content=summary, status_code=200)


# ---------------------------------------------------------------------------
# POST /v1/compliance/export
# ---------------------------------------------------------------------------


@router.post("/v1/compliance/export", include_in_schema=True)
async def export_compliance_pack(
    request: Request,
) -> Response:
    """Export a signed, tamper-evident compliance evidence pack ZIP.

    Auth: tenant Bearer virtual key (same as /v1/chat/completions).
    Tenant is server-resolved; no tenant_id field in the request body exists.
    additionalProperties on the request body are REJECTED (422) — an injected
    'tenant_id' field is refused by Pydantic extra='forbid'.
    The pack is ECDSA-signed (ES256/JWS, Layer B) and embeds F-003 chain
    hashes (Layer A) for offline verification.

    R1: the pack export path issues ZERO writes to events_audit_log.
    The compliance_pack_exported meta-event is a SEPARATE best-effort append.
    """
    request_id: str = getattr(request.state, "request_id", None) or ("req-" + uuid.uuid4().hex[:32])

    # Step 5: ID cross-check + tenant context resolution.
    ctx = resolve_tenant_context(request)

    # Parse and validate body.
    raw_body = getattr(request.state, "raw_body", None)
    if raw_body is None:
        # Fallback: read body directly (e.g. in tests without RequestValidationMiddleware).
        raw_body = await request.body()

    try:
        import json as _json

        body_dict = _json.loads(raw_body)
    except Exception:
        raise GatewayError("invalid_request") from None

    try:
        export_req = ExportRequest.model_validate(body_dict)
    except ValidationError as exc:
        # Pydantic ValidationError (extra fields, bad enum, missing required) → 422.
        # Re-raise as FastAPI RequestValidationError so FastAPI's validation error
        # handler returns a proper 422 Unprocessable Entity response.
        # This is the structural cross-tenant-override defense (vector 9):
        # an injected 'tenant_id' field is rejected here before any generation runs.
        raise RequestValidationError(errors=exc.errors()) from exc

    framework = export_req.framework
    t0_dt = _parse_datetime(export_req.t0, "t0")
    t1_dt = _parse_datetime(export_req.t1, "t1")

    try:
        from compliance.evidence import validate_window

        validate_window(t0_dt, t1_dt)
    except EvidenceWindowError:
        raise GatewayError("invalid_request") from None

    # Load signing keys (fail-closed; PackSigningKeyError → 500).
    try:
        private_key, public_key = load_pack_signing_keys()
    except PackSigningKeyError as exc:
        # Never leak key paths or key material in error responses (CLAUDE.md non-neg #4).
        log.error("compliance_pack_signing_key_error", request_id=request_id)
        raise GatewayError("internal_error") from exc

    # Load framework mapping.
    try:
        framework_map = load_framework(framework)
    except Exception:
        log.exception("compliance_framework_load_failed", framework=framework)
        raise GatewayError("internal_error") from None

    # Generate evidence (R1: zero writes).
    try:
        projection = await generate_evidence(framework_map, t0_dt, t1_dt, tenant_id=ctx.tenant_id)
        chain_links = await read_chain_segment(t0_dt, t1_dt, tenant_id=ctx.tenant_id)
    except EvidenceWindowError:
        raise GatewayError("invalid_request") from None
    except Exception:
        log.exception("compliance_evidence_generation_failed", request_id=request_id)
        raise GatewayError("internal_error") from None

    # Gap analysis.
    try:
        gap_report = analyze_gaps(framework_map, projection)
    except Exception:
        log.exception("compliance_gap_analysis_failed", request_id=request_id)
        raise GatewayError("internal_error") from None

    # Build pack record, sign (Layer B), export to ZIP.
    try:
        record = build_pack_record(
            gap_report,
            projection,
            chain_links,
            tenant_id=ctx.tenant_id,
            sentinel_version=_SENTINEL_VERSION,
        )
        jws = sign_pack(record, private_key)

        # Compute content_hash from canonical evidence bytes (same as export_pack_zip).
        from policy.crypto import canonical_claims

        evidence_bytes = canonical_claims(record)
        content_hash = hashlib.sha256(evidence_bytes).hexdigest()

        # Write ZIP to a temp file, read bytes, then clean up.
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            export_pack_zip(record, jws, public_key, out_path=tmp_path)
            with open(tmp_path, "rb") as fh:
                zip_bytes = fh.read()
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    except GatewayError:
        raise
    except Exception:
        log.exception("compliance_pack_export_failed", request_id=request_id)
        raise GatewayError("internal_error") from None

    # Best-effort meta-audit emit (SEPARATE explicit append — R1 nuance D7).
    event_data = _build_compliance_event(
        "compliance_pack_exported",
        request_id=request_id,
        tenant_id=ctx.tenant_id,
        team_id=ctx.team_id,
        project_id=ctx.project_id,
        virtual_key_id=ctx.virtual_key_id,
        framework=framework,
        framework_version=framework_map.framework_version,
        extra={"pack_content_hash": content_hash},
    )
    await _emit_compliance_event(event_data)

    return Response(
        content=zip_bytes,
        status_code=200,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="compliance-{framework.lower()}.zip"',
        },
    )
