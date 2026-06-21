"""Bulk worker — per-job tenant-scoped file processor (F-015, ADR-0018 §2/§3, Fork 1).

The worker is a NEW async principal OUTSIDE the HTTP path. For EACH file job it:

  1. Opens an EXPLICIT `get_tenant_session(job.tenant_id)` on the NOBYPASSRLS
     sentinel_app engine (Fork 1 (a)) — ALL per-file state reads/writes + the
     F-008 policy read run under that RLS scope. The worker NEVER opens a blanket
     BYPASSRLS session for processing; `get_privileged_session()` is used ONLY for
     the global hash-chain audit append (as the sync gateway does).
  2. Checkpoint: skips files already in a terminal state (idempotent redelivery /
     resume — R5, vector 10).
  3. Runs the file through the reused F-005 + F-008 pipeline (pipeline.process_file).
  4. Records the per-file outcome + emits batch_file_processed / batch_file_blocked.
  5. On failure: bounded retry (re-enqueue) then DLQ — a single bad file never
     fails the batch (R7, vector 11); every dead-letter is audited (R6, vector 15).
  6. Completion: when the last file reaches a terminal state, marks the batch
     completed + emits batch_completed.

Runtime: a horizontally-scalable Redis Streams consumer-group pool (run N
processes against the same group). The queue is Redis Streams (reusing the F-009
pool) — chosen over arq's native list broker because consumer groups give
at-least-once delivery + per-consumer pending + reclaim, which the DLQ / retry /
checkpoint semantics (R5/R7) need. The arq dependency remains available; the pool
is realized as a Streams consumer group. KEDA scales on queue.queue_depth() (D9).
"""

from __future__ import annotations

import asyncio
import uuid

import structlog

from bulk.audit_events import emit_batch_event
from bulk.config import get_bulk_settings
from bulk.content import decode_text
from bulk.exceptions import ObjectTooLarge, StorageError, UnsupportedContent
from bulk.models.batch_file import FILE_TERMINAL_STATUSES
from bulk.pipeline import context_from_job, process_file
from bulk.queue import JobMessage, dead_letter, enqueue_files, ensure_group
from bulk.repositories.batch_repository import BatchRepository
from bulk.storage.keys import key_belongs_to_tenant
from gateway.redis_client import get_client
from persistence.database import get_privileged_session, get_tenant_session

log = structlog.get_logger(__name__)

# Idle time (ms) before a pending message is reclaimable from a crashed worker.
_CLAIM_MIN_IDLE_MS = 60_000
_READ_BLOCK_MS = 5_000
_READ_COUNT = 10


def _classify_failure(exc: Exception) -> str:
    """Map an exception to a bounded failure CLASS (never raw message — PII/secret risk)."""
    if isinstance(exc, ObjectTooLarge):
        return "oversize"
    if isinstance(exc, UnsupportedContent):
        return "unsupported_content"
    if isinstance(exc, StorageError):
        return "storage_error"
    try:
        from orchestration.exceptions import HookFailSafeError

        if isinstance(exc, HookFailSafeError):
            return "inspection_failsafe"
    except Exception:
        pass
    return "processing_error"


async def _emit(job: JobMessage, event_type: str, request_id: str) -> None:
    """Append a batch_* lifecycle event (privileged session). Best-effort + logged."""
    try:
        async with get_privileged_session() as ps:
            async with ps.begin():
                await emit_batch_event(
                    ps,
                    event_type=event_type,
                    tenant_id=job.tenant_id,
                    team_id=job.team_id,
                    project_id=job.project_id,
                    request_id=request_id,
                )
    except Exception:
        # Out-of-band error log — never converts an outcome (R6 honest scope).
        log.error("bulk_event_emit_failed", event_type=event_type, request_id=request_id)


async def _release_slots(job: JobMessage, *, batch_complete: bool) -> None:
    """Release the in-flight file slot (+ batch slot on completion). Best-effort."""
    from bulk import limits

    try:
        await limits.release_file(job.tenant_id)
        if batch_complete:
            await limits.release_batch_slot(job.tenant_id)
    except Exception:
        # Fairness counters self-heal via TTL; never fail processing on a Redis hiccup.
        log.error("bulk_limit_release_failed", tenant_present=bool(job.tenant_id))


async def _complete_if_done(job: JobMessage) -> bool:
    """Atomically complete the batch iff this was the last terminal file (HIGH-2).

    Runs in a SEPARATE tenant session AFTER the file's terminal status is committed,
    so the NOT EXISTS check sees it. Returns True iff this call won the transition —
    so batch_completed + the batch-slot release happen exactly once under concurrency.
    """
    async with get_tenant_session(job.tenant_id) as session:
        won = await BatchRepository(session).try_complete_batch(job.batch_id)
        await session.commit()
    return won


async def _finalize(job: JobMessage, *, status: str, outcome: str, request_id: str) -> None:
    """Persist the terminal file outcome (tenant session) + emit lifecycle events."""
    async with get_tenant_session(job.tenant_id) as session:
        await BatchRepository(session).set_file_status(job.file_id, status=status, outcome=outcome)
        await session.commit()
    won = await _complete_if_done(job)
    await _emit(
        job,
        "batch_file_blocked" if status == "blocked" else "batch_file_processed",
        request_id,
    )
    if won:
        await _emit(job, "batch_completed", request_id)
    await _release_slots(job, batch_complete=won)


async def _handle_failure(
    job: JobMessage, *, attempt: int, failure_class: str, request_id: str
) -> str:
    """Bounded retry → DLQ. Returns 'retry' or 'dead_lettered'."""
    settings = get_bulk_settings()
    if attempt < settings.bulk_retry_max:
        # Re-queue for another attempt; reset status so checkpoint won't skip it.
        async with get_tenant_session(job.tenant_id) as session:
            await BatchRepository(session).set_file_status(job.file_id, status="queued")
            await session.commit()
        await enqueue_files([job])
        log.info(
            "bulk_file_retry", request_id=request_id, attempt=attempt, failure_class=failure_class
        )
        return "retry"

    # Exhausted retries → dead-letter (audited; no silent drop — R6/R7, vectors 11/15).
    async with get_tenant_session(job.tenant_id) as session:
        await BatchRepository(session).set_file_status(
            job.file_id, status="dead_lettered", failure_class=failure_class
        )
        await session.commit()
    await dead_letter(job, failure_class=failure_class)
    won = await _complete_if_done(job)
    await _emit(job, "batch_file_dead_lettered", request_id)
    if won:
        await _emit(job, "batch_completed", request_id)
    await _release_slots(job, batch_complete=won)
    log.warning("bulk_file_dead_lettered", request_id=request_id, failure_class=failure_class)
    return "dead_lettered"


async def process_job(
    job: JobMessage, *, storage, hook_registry, gateway_settings, orch_settings
) -> str:
    """Process ONE file under the submitting tenant's RLS scope (Fork 1 (a)).

    Returns: 'done' | 'blocked' | 'dead_lettered' | 'retry' | 'skipped'.
    All state work runs under get_tenant_session(job.tenant_id); audit appends use
    the privileged session. No blanket BYPASSRLS session is ever opened here.
    """
    request_id = job.file_id  # per-file id (valid event request_id, <= 64 chars)
    tenant_context = context_from_job(
        tenant_id=job.tenant_id,
        team_id=job.team_id,
        project_id=job.project_id,
        agent_id=job.agent_id,
    )

    # --- Checkpoint + claim (tenant session) ---
    async with get_tenant_session(job.tenant_id) as session:
        repo = BatchRepository(session)
        bf = await repo.get_file(job.file_id)
        if bf is None:
            return "skipped"  # not visible under this tenant / already removed
        if bf.status in FILE_TERMINAL_STATUSES:
            return "skipped"  # already processed (idempotent redelivery — vector 10)
        # SECURITY (audit HIGH): the RLS-loaded row is the AUTHORITATIVE object key,
        # not the queue payload. The Redis queue is a separate trust boundary and
        # object storage has no RLS, so we fetch bf.object_key (guaranteed this
        # tenant's by RLS) — never job.object_key. A mismatch means a forged/replayed
        # job pairing a foreign key with this tenant's file_id → dead-letter, never fetch.
        safe_key = bf.object_key
        updated = await repo.set_file_status(job.file_id, status="running", increment_attempt=True)
        attempt = updated.attempt_count  # post-increment count = this attempt number
        # get_tenant_session autobegins; commit to persist the claim (admin pattern).
        await session.commit()

    settings = get_bulk_settings()

    # Fail-closed on a queue/DB key mismatch (tampering or producer bug). No retry —
    # a foreign key never becomes a fetch target (cross-tenant object read defense).
    if job.object_key != safe_key or not key_belongs_to_tenant(safe_key, job.tenant_id):
        log.warning("bulk_key_tenant_mismatch", request_id=request_id, batch_id=job.batch_id)
        return await _handle_failure(
            job,
            attempt=settings.bulk_retry_max,
            failure_class="key_tenant_mismatch",
            request_id=request_id,
        )

    # --- Fetch + inspect (tenant session for the policy read) ---
    try:
        data = await storage.fetch(safe_key, max_bytes=settings.bulk_max_file_bytes)
        text = decode_text(data, max_bytes=settings.bulk_max_file_bytes)
        # This session is READ-ONLY (process_file only READS policy under RLS — review
        # HIGH-1). Detector + policy_decision audit events emit on their OWN privileged
        # sessions (HookContext.emit / emit_policy_decision), so no write happens here;
        # the autobegun read txn rolls back harmlessly on exit. No commit needed.
        async with get_tenant_session(job.tenant_id) as session:
            outcome = await process_file(
                content=text,
                tenant_context=tenant_context,
                request_id=request_id,
                model=job.model,
                session=session,
                hook_registry=hook_registry,
                gateway_settings=gateway_settings,
                orch_settings=orch_settings,
            )
    except Exception as exc:  # noqa: BLE001 — bounded retry/DLQ is the fail-safe
        return await _handle_failure(
            job, attempt=attempt, failure_class=_classify_failure(exc), request_id=request_id
        )

    await _finalize(job, status=outcome.status, outcome=outcome.outcome, request_id=request_id)
    return outcome.status


# --------------------------------------------------------------------------- #
# Consumer-group worker loop (the horizontally-scalable pool)
# --------------------------------------------------------------------------- #
def _build_deps():
    """Assemble the (storage, hook_registry, gateway_settings, orch_settings) deps."""
    from bulk.storage import get_storage
    from gateway.config import get_settings
    from orchestration.config import get_orchestration_settings
    from orchestration.registry import build_default_registry

    return (
        get_storage(),
        build_default_registry(),
        get_settings(),
        get_orchestration_settings(),
    )


async def _consume_batch(client, group: str, consumer: str, stream: str, deps) -> int:
    """Read + process one batch of messages (new + reclaimed). Returns count handled."""
    storage, hook_registry, gw, orch = deps
    handled = 0

    # Reclaim messages stuck on crashed workers (at-least-once on crash).
    try:
        _next, claimed, _deleted = await client.xautoclaim(
            stream,
            group,
            consumer,
            min_idle_time=_CLAIM_MIN_IDLE_MS,
            start_id="0",
            count=_READ_COUNT,
        )
    except Exception:
        claimed = []

    # Read new messages.
    new_msgs: list = []
    try:
        resp = await client.xreadgroup(
            group, consumer, {stream: ">"}, count=_READ_COUNT, block=_READ_BLOCK_MS
        )
        for _stream_name, entries in resp or []:
            new_msgs.extend(entries)
    except Exception:
        new_msgs = []

    for msg_id, fields in list(claimed) + new_msgs:
        # Parse + validate FIRST. A malformed/poison message is discarded (acked)
        # rather than reclaim-looping forever or writing corrupt IDs (review MED).
        try:
            job = JobMessage.from_fields(fields)
        except (KeyError, ValueError):
            log.error("bulk_worker_malformed_message_discarded", msg_id=str(msg_id))
            await client.xack(stream, group, msg_id)
            continue
        try:
            await process_job(
                job,
                storage=storage,
                hook_registry=hook_registry,
                gateway_settings=gw,
                orch_settings=orch,
            )
        except Exception:
            # process_job handles its own failures; a leak here means an
            # unexpected error — leave the message PENDING for later reclaim
            # (do NOT ack) so the file is not silently dropped.
            log.error("bulk_worker_unexpected_error", msg_id=str(msg_id))
            continue
        await client.xack(stream, group, msg_id)
        handled += 1

    return handled


async def run_worker(*, stop_event: asyncio.Event | None = None) -> None:
    """Run the consumer-group worker loop until stop_event is set (or forever)."""
    settings = get_bulk_settings()
    stream = settings.bulk_stream_key
    group = settings.bulk_consumer_group
    consumer = f"worker-{uuid.uuid4().hex[:8]}"

    await ensure_group()
    deps = _build_deps()
    log.info("bulk_worker_started", consumer=consumer, stream=stream)

    while stop_event is None or not stop_event.is_set():
        async with await get_client() as client:
            await _consume_batch(client, group, consumer, stream, deps)
