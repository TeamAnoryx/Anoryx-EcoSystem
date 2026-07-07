"""The Delta inbound consume endpoint: POST /v1/ingest/usage (ADR-0004 §3.2).

Pipeline: HMAC verify (401 on forgery) -> parse + validate (permanent -> dead-letter
+ 4xx) -> post one balanced, idempotent debit (transient -> 503, dispatcher retries;
permanent -> dead-letter + 4xx). A successful post or an idempotent replay both return
200, so the Orchestrator dispatcher marks the outbox row forwarded either way.
"""

from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..budget_engine.evaluator import evaluate_after_post
from ..kill_switch.evaluator import evaluate_kill_switch
from .config import ATTEMPT_HEADER, SIGNATURE_HEADER, TIMESTAMP_HEADER
from .dlq import dead_letter
from .errors import DeadLetterReason, PermanentIngestError, is_transient
from .hmac_verify import verify_signature
from .posting import build_usage_record, post_usage

logger = logging.getLogger("delta.ingest.router")

router = APIRouter()

# Cap the stored raw blob for a non-JSON body so a hostile payload can't bloat the DLQ.
_MAX_RAW_DLQ_CHARS = 10_000


def _parse_attempt(header_value: str | None) -> int:
    """The dispatcher's attempt counter (advisory, for the DLQ row). Defaults to 1."""
    if not header_value:
        return 1
    try:
        return max(1, int(header_value))
    except (TypeError, ValueError):
        return 1


async def _dead_letter_or_503(
    error: PermanentIngestError, *, original_payload: dict, attempt: int
) -> JSONResponse:
    """Dead-letter a permanent failure; if the DLQ write itself fails transiently,
    return 503 so the dispatcher retries (the event is never lost)."""
    try:
        await dead_letter(error, original_payload=original_payload, attempt_count=attempt)
    except Exception as dlq_exc:  # noqa: BLE001 — classify, never swallow silently
        if is_transient(dlq_exc):
            # Transient DB error writing the DLQ row: retry later (event not yet persisted).
            return JSONResponse(
                status_code=503, content={"status": "retry", "detail": "dead-letter deferred"}
            )
        # Non-transient DLQ-write failure: the event cannot be persisted to the DLQ at all.
        # Bare-raising would surface as a 503 and the dispatcher would retry forever until the
        # outbox row exhausts its attempts and lands 'failed' with NO Delta DLQ trace — the
        # payload would then be unauditable and effectively lost. Instead emit the full event to
        # the log (this log line is the emergency audit trail, the only surviving record) and
        # return 422 so the dispatcher marks the row 'failed' immediately rather than burning
        # retries. The payload is the usage event; no secret is logged.
        logger.error(
            "delta.ingest DLQ-write FAILED (non-transient) — emergency audit trail: "
            "reason=%s tenant=%s event_id=%s event_type=%s dlq_error=%r original_payload=%r",
            error.reason.value,
            error.tenant_id or "<unknown>",
            error.event_id or "<none>",
            error.event_type or "<none>",
            dlq_exc,
            original_payload,
        )
        return JSONResponse(
            status_code=422,
            content={"status": "dead_letter_failed", "reason": error.reason.value},
        )
    return JSONResponse(
        status_code=422,
        content={"status": "dead_lettered", "reason": error.reason.value},
    )


@router.post("/v1/ingest/usage")
async def ingest_usage(request: Request) -> JSONResponse:
    raw = await request.body()

    settings = request.app.state.ingest_settings
    if not verify_signature(
        secret=settings.hmac_secret,
        timestamp_header=request.headers.get(TIMESTAMP_HEADER),
        signature_header=request.headers.get(SIGNATURE_HEADER),
        raw_body=raw,
    ):
        # Forged / unauthenticated: reject. Not a financial event to preserve.
        return JSONResponse(status_code=401, content={"status": "unauthorized"})

    attempt = _parse_attempt(request.headers.get(ATTEMPT_HEADER))

    # --- parse JSON body
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        # Strip NUL: Postgres cannot store U+0000 in JSONB/text, so an un-stripped NUL
        # would fail the DLQ insert and the event would survive only in the emergency log.
        snippet = raw.decode("utf-8", "replace").replace("\x00", "")[:_MAX_RAW_DLQ_CHARS]
        return await _dead_letter_or_503(
            PermanentIngestError(DeadLetterReason.MALFORMED_PAYLOAD, "body is not valid JSON"),
            original_payload={"_raw": snippet},
            attempt=attempt,
        )

    dlq_payload = payload if isinstance(payload, dict) else {"_raw": payload}

    # --- validate into a UsageRecord (permanent failures are dead-lettered)
    try:
        record = build_usage_record(payload)
    except PermanentIngestError as exc:
        return await _dead_letter_or_503(exc, original_payload=dlq_payload, attempt=attempt)

    # --- post one balanced, idempotent debit
    try:
        result = await post_usage(record)
    except PermanentIngestError as exc:  # explicit permanent from the posting path
        return await _dead_letter_or_503(exc, original_payload=dlq_payload, attempt=attempt)
    except Exception as exc:  # noqa: BLE001 — classify transient vs permanent, never swallow
        if is_transient(exc):
            # DB down / timeout: retry later, do NOT dead-letter (event is recoverable).
            return JSONResponse(
                status_code=503, content={"status": "retry", "detail": "downstream unavailable"}
            )
        # A non-transient DB/logic rejection (e.g. a constraint) — dead-letter it.
        perm = PermanentIngestError(
            DeadLetterReason.UNRESOLVABLE_ACCOUNT,
            f"posting rejected: {exc}",
            tenant_id=record.tenant_id,
            event_id=record.event_id,
            event_type="usage",
        )
        return await _dead_letter_or_503(perm, original_payload=dlq_payload, attempt=attempt)

    # D-005 budget engine hook: evaluate the affected scope AFTER the debit is durable.
    # This is a post-commit side effect — it NEVER alters this response (the ledger is the
    # authority; enforcement is downstream). evaluate_after_post classifies and absorbs all
    # of its own failures (it never raises), so a successful debit always returns 200.
    await evaluate_after_post(record, request.app.state.budget_engine_settings)

    # D-006 kill-switch hook: an independent, faster, per-transaction check (unauthorized
    # agent identity / anomalous single-transaction cost) — no period accumulation. Same
    # post-commit, never-raises, response-never-altered shape as the budget engine above.
    await evaluate_kill_switch(record, request.app.state.kill_switch_settings)

    return JSONResponse(
        status_code=200,
        content={
            "status": "accepted",
            "applied": result.applied,
            "idempotent_replay": result.idempotent_replay,
            "txn_id": result.txn_id,
        },
    )
