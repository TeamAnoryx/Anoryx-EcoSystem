"""POST /v1/ingest/events — the O-002 ingest seam receiver (O-003, ADR-0003).

Boundary stages (synchronous), then the in-process pipeline:
  1. Read the RAW body before parsing (the HMAC was computed over these bytes).
  2. HMAC verify → 401 (missing/malformed) / 403 (stale ts or signature mismatch).
  3. Parse JSON + structural envelope validation → 422 (malformed envelope).
  4. Run the pipeline → 202 {status: accepted, event_id}. A pipeline-stage failure is an
     internal reject-to-DLQ disposition (still 202 — the envelope was durably recorded as
     a DLQ entry); the contract defines no dead-lettered client status.

Errors below the boundary (e.g. a DB outage during the pipeline) are NOT swallowed — they
propagate to the app's fail-safe handler (5xx BLOCK). A non-durably-recorded event is
never 202'd.
"""

from __future__ import annotations

import json
import time
import uuid

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from orchestrator.config import IngestSettings
from orchestrator.hmac_verify import HmacOutcome, verify_ingest_signature
from orchestrator.pipeline.ingest_pipeline import process_envelope
from orchestrator.schema_validation import envelope_structure_errors

router = APIRouter()

_SIG_HEADER = "X-Sentinel-Signature"
_TS_HEADER = "X-Sentinel-Timestamp"


def _request_id() -> str:
    return "req-orch-" + uuid.uuid4().hex[:24]


def _error(status: int, code: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "request_id": request_id}},
        headers={"X-Request-Id": request_id},
    )


@router.post("/v1/ingest/events")
async def ingest_event(request: Request) -> JSONResponse:
    settings: IngestSettings = request.app.state.ingest_settings
    request_id = _request_id()

    # 1. Raw body (before any parse) — the exact bytes the signature covers.
    raw_body = await request.body()

    # 2. HMAC verification.
    hmac_result = verify_ingest_signature(
        secret=settings.hmac_secret,
        raw_body=raw_body,
        signature_header=request.headers.get(_SIG_HEADER),
        timestamp_header=request.headers.get(_TS_HEADER),
        tolerance_seconds=settings.hmac_tolerance_seconds,
        now=time.time(),
    )
    if hmac_result.outcome is HmacOutcome.UNAUTHENTICATED:
        return _error(401, "unauthorized", "peer authentication failed", request_id)
    if hmac_result.outcome is HmacOutcome.REJECTED:
        return _error(403, "signature_invalid", "request signature rejected", request_id)

    # 3. Parse JSON + structural envelope validation.
    try:
        envelope = json.loads(raw_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _error(422, "schema_invalid", "request body is not valid JSON", request_id)
    if not isinstance(envelope, dict):
        return _error(422, "schema_invalid", "envelope must be a JSON object", request_id)
    structure_errors = envelope_structure_errors(envelope)
    if structure_errors:
        return _error(422, "schema_invalid", "envelope failed structural validation", request_id)

    # 4. Pipeline (durably records as an accepted event OR a DLQ entry). Any error below
    #    here propagates to the fail-safe handler (5xx) — never a 202 for a non-recorded
    #    event.
    result = await process_envelope(envelope, settings=settings)
    return JSONResponse(
        status_code=202,
        content={"status": "accepted", "event_id": result.event_id},
        headers={"X-Request-Id": request_id},
    )
