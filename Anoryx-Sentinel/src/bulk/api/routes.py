"""Bulk data-plane routes (F-015, ADR-0018 §1.2, Fork 5).

All routes are tenant-facing (/v1/batches*) under the existing virtual-API-key
Bearer path: AuthMiddleware sets virtual_key_row; resolve_tenant_context() builds
the server-resolved TenantContext (RLS scope + honest attribution). Each route
sets request.state.audit_emitted = True:
  - submit emits an explicit batch_submitted event (so the terminal usage row is
    suppressed — one intentional audit append, not a spurious usage row),
  - the read routes (status, manifest) and the upload mint perform NO audit write
    (reads write zero rows — the F-012a read-only principle).

The body is read from request.state.raw_body (RequestValidationMiddleware already
consumed the stream under the 1 MiB cap), so models are parsed manually — exactly
as chat_completions.py does.
"""

from __future__ import annotations

import json
import uuid

import structlog
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from redis.exceptions import ConnectionError as RedisConnectionError
from redis.exceptions import TimeoutError as RedisTimeoutError
from sqlalchemy.exc import IntegrityError

from bulk.api.schemas import (
    BatchSubmitRequest,
    UploadMintRequest,
)
from bulk.audit_events import emit_batch_event
from bulk.config import get_bulk_settings
from bulk.exceptions import BatchLimitExceeded
from bulk.limits import release_reservation, reserve_batch
from bulk.queue import JobMessage, enqueue_files
from bulk.repositories.batch_repository import BatchRepository
from bulk.storage import get_storage, key_belongs_to_tenant, mint_object_key
from gateway.exceptions import GatewayError
from gateway.middleware.tenant_context import resolve_tenant_context
from persistence.database import get_privileged_session, get_tenant_session

log = structlog.get_logger(__name__)

router = APIRouter()


def _request_id(request: Request) -> str:
    return getattr(request.state, "request_id", None) or ("req-" + uuid.uuid4().hex[:32])


def _parse_body(request: Request, model):
    """Parse + validate the captured raw body into a closed Pydantic model."""
    raw = getattr(request.state, "raw_body", b"")
    if not raw:
        raise GatewayError("invalid_request")
    try:
        return model(**json.loads(raw))
    except (json.JSONDecodeError, ValueError, ValidationError, TypeError):
        raise GatewayError("invalid_request") from None


# --------------------------------------------------------------------------- #
# POST /v1/batches/uploads — mint presigned single-object upload grants
# --------------------------------------------------------------------------- #
@router.post("/v1/batches/uploads", response_model=None)
async def mint_uploads(request: Request) -> JSONResponse:
    request.state.audit_emitted = True  # minting URLs writes no audit row
    ctx = resolve_tenant_context(request)
    settings = get_bulk_settings()
    body = _parse_body(request, UploadMintRequest)
    if body.count > settings.bulk_max_files_per_batch:
        raise GatewayError("invalid_request")

    # The middle key segment is a server-minted upload-group id (a fresh UUID) —
    # tenant-namespaced + unguessable, like the eventual batch grouping (R3).
    group_id = str(uuid.uuid4())
    try:
        storage = get_storage()
        uploads = []
        for _ in range(body.count):
            key = mint_object_key(ctx.tenant_id, group_id)
            grant = storage.presign_upload(
                key,
                max_bytes=settings.bulk_max_file_bytes,
                ttl=settings.bulk_presign_ttl_seconds,
            )
            uploads.append(
                {
                    "object_key": grant.key,
                    "url": grant.url,
                    "fields": grant.fields,
                    "max_bytes": grant.max_bytes,
                    "expires_in": grant.expires_in,
                }
            )
    except GatewayError:
        raise
    except Exception:
        # StorageDependencyMissing / StorageError / config issue → fail-safe 500.
        log.error("bulk_upload_mint_failed", request_id=_request_id(request))
        raise GatewayError("internal_error") from None

    return JSONResponse(
        content={"uploads": uploads},
        status_code=200,
        headers={"X-Request-Id": _request_id(request)},
    )


# --------------------------------------------------------------------------- #
# POST /v1/batches — submit a batch (idempotent)
# --------------------------------------------------------------------------- #
@router.post("/v1/batches", response_model=None)
async def submit_batch(request: Request) -> JSONResponse:
    request.state.audit_emitted = True  # we emit batch_submitted explicitly
    ctx = resolve_tenant_context(request)
    settings = get_bulk_settings()
    body = _parse_body(request, BatchSubmitRequest)
    request_id = _request_id(request)

    # Dedupe object keys (order-preserving) + validate each is in THIS tenant's
    # namespace and well-formed (vectors 2, 7). A key outside the tenant prefix
    # or with traversal/bad shape is rejected before any DB write.
    keys = list(dict.fromkeys(body.object_keys))
    if not (1 <= len(keys) <= settings.bulk_max_files_per_batch):
        raise GatewayError("invalid_request")
    for k in keys:
        if not key_belongs_to_tenant(k, ctx.tenant_id):
            raise GatewayError("invalid_request")

    # Idempotent replay: return the existing batch WITHOUT reserving or enqueuing
    # (a status replay must never be rate-limited or double-processed — vector 9).
    pre = await _fetch_existing_optional(ctx, body.idempotency_key)
    if pre is not None:
        _kind, batch_id, status, counts, _jobs = pre
        return JSONResponse(
            content={
                "batch_id": batch_id,
                "status": status,
                "total_files": sum(counts.values()),
                "counts": counts,
            },
            status_code=200,
            headers={"X-Request-Id": request_id},
        )

    # New batch: reserve per-tenant slots (backpressure → 429). Fail-OPEN on a Redis
    # hiccup (fairness degrades gracefully — the F-009 γ posture), fail-CLOSED only
    # on a real cap breach.
    reserved = False
    try:
        await reserve_batch(ctx.tenant_id, len(keys))
        reserved = True
    except BatchLimitExceeded:
        raise GatewayError("rate_limit_exceeded") from None
    except (RedisConnectionError, RedisTimeoutError):
        # Fail-OPEN only on genuine Redis degradation (F-009 γ posture): fairness
        # degrades gracefully rather than rejecting traffic. Counters self-heal
        # via TTL. Any OTHER error propagates → fail-safe 500 (not silently unmetered).
        log.error("bulk_reserve_failed_fail_open", request_id=request_id)

    try:
        kind, batch_id, status, counts, jobs = await _create_or_get(
            ctx, body.idempotency_key, keys, body.model
        )
    except IntegrityError:
        # Concurrent identical submit — re-fetch the winner (no second batch).
        kind, batch_id, status, counts, jobs = await _fetch_existing(ctx, body.idempotency_key)
    except Exception:
        if reserved:
            try:
                await release_reservation(ctx.tenant_id, len(keys))
            except Exception:
                log.error("bulk_release_failed", request_id=request_id)
        raise

    if kind == "created":
        await enqueue_files(jobs)
        # batch_submitted is appended on a privileged session (global chain).
        # Best-effort: the batch is valid + every file is audited per-outcome, so
        # a lost lifecycle marker is logged out-of-band, never a 500 that orphans
        # an already-created+enqueued batch (honest scope, ADR-0018 §4).
        try:
            async with get_privileged_session() as ps:
                async with ps.begin():
                    await emit_batch_event(
                        ps,
                        event_type="batch_submitted",
                        tenant_id=ctx.tenant_id,
                        team_id=ctx.team_id,
                        project_id=ctx.project_id,
                        request_id=request_id,
                    )
        except Exception:
            log.error("batch_submitted_emit_failed", request_id=request_id, batch_id=batch_id)
    elif reserved:
        # Creation race: another identical submit won. Give back our reservation
        # (the winner's worker drains the slots; ours created nothing).
        try:
            await release_reservation(ctx.tenant_id, len(keys))
        except Exception:
            log.error("bulk_release_failed", request_id=request_id)

    return JSONResponse(
        content={
            "batch_id": batch_id,
            "status": status,
            "total_files": len(keys) if kind == "created" else sum(counts.values()),
            "counts": counts,
        },
        status_code=202 if kind == "created" else 200,
        headers={"X-Request-Id": request_id},
    )


async def _create_or_get(ctx, idempotency_key: str, keys: list[str], model: str | None):
    """Idempotent create: return ('exists'|'created', batch_id, status, counts, jobs)."""
    async with get_tenant_session(ctx.tenant_id) as session:
        repo = BatchRepository(session)
        existing = await repo.get_by_idempotency_key(ctx.tenant_id, idempotency_key)
        if existing is not None:
            counts = await repo.count_files_by_status(existing.batch_id)
            return "exists", existing.batch_id, existing.status, counts, []
        batch, files = await repo.create_batch(
            tenant_id=ctx.tenant_id,
            team_id=ctx.team_id,
            project_id=ctx.project_id,
            agent_id=ctx.agent_id,
            idempotency_key=idempotency_key,
            object_keys=keys,
            model=model,
        )
        # Capture values BEFORE commit (expire_on_commit would detach the ORM rows).
        batch_id = batch.batch_id
        file_tuples = [(f.file_id, f.object_key) for f in files]
        # get_tenant_session autobegins; commit to persist the batch (admin pattern).
        await session.commit()
        jobs = [
            JobMessage(
                batch_id=batch_id,
                file_id=fid,
                tenant_id=ctx.tenant_id,
                team_id=ctx.team_id,
                project_id=ctx.project_id,
                agent_id=ctx.agent_id,
                object_key=okey,
                idempotency_key=idempotency_key,
                model=model or "",
            )
            for fid, okey in file_tuples
        ]
        return "created", batch_id, "queued", {"queued": len(file_tuples)}, jobs


async def _fetch_existing(ctx, idempotency_key: str):
    """Re-fetch the batch that won an idempotency race (fresh tenant session)."""
    async with get_tenant_session(ctx.tenant_id) as session:
        repo = BatchRepository(session)
        existing = await repo.get_by_idempotency_key(ctx.tenant_id, idempotency_key)
        if existing is None:
            raise GatewayError("internal_error")
        counts = await repo.count_files_by_status(existing.batch_id)
        return "exists", existing.batch_id, existing.status, counts, []


async def _fetch_existing_optional(ctx, idempotency_key: str):
    """Return the existing-batch tuple for an idempotent replay, or None if new."""
    async with get_tenant_session(ctx.tenant_id) as session:
        repo = BatchRepository(session)
        existing = await repo.get_by_idempotency_key(ctx.tenant_id, idempotency_key)
        if existing is None:
            return None
        counts = await repo.count_files_by_status(existing.batch_id)
        return "exists", existing.batch_id, existing.status, counts, []


# --------------------------------------------------------------------------- #
# GET /v1/batches/{batch_id} — batch status (RLS-scoped, read-only)
# --------------------------------------------------------------------------- #
@router.get("/v1/batches/{batch_id}", response_model=None)
async def get_batch_status(request: Request, batch_id: str) -> JSONResponse:
    request.state.audit_emitted = True  # read writes no audit row
    ctx = resolve_tenant_context(request)
    async with get_tenant_session(ctx.tenant_id) as session:
        repo = BatchRepository(session)
        batch = await repo.get_batch(batch_id)
        if batch is None:
            raise GatewayError("not_found")  # RLS hid it or it is absent — same 404
        counts = await repo.count_files_by_status(batch_id)
        payload = {
            "batch_id": batch.batch_id,
            "status": batch.status,
            "total_files": batch.total_files,
            "counts": counts,
        }
    return JSONResponse(
        content=payload, status_code=200, headers={"X-Request-Id": _request_id(request)}
    )


# --------------------------------------------------------------------------- #
# GET /v1/batches/{batch_id}/files — per-file manifest (RLS-scoped, read-only)
# --------------------------------------------------------------------------- #
@router.get("/v1/batches/{batch_id}/files", response_model=None)
async def get_batch_manifest(request: Request, batch_id: str) -> JSONResponse:
    request.state.audit_emitted = True  # read writes no audit row
    ctx = resolve_tenant_context(request)
    async with get_tenant_session(ctx.tenant_id) as session:
        repo = BatchRepository(session)
        batch = await repo.get_batch(batch_id)
        if batch is None:
            raise GatewayError("not_found")
        files = await repo.list_files(batch_id)
        items = [
            {
                "file_id": f.file_id,
                "object_key": f.object_key,
                "status": f.status,
                "outcome": f.outcome,
                "attempt_count": f.attempt_count,
                "failure_class": f.failure_class,
            }
            for f in files
        ]
    return JSONResponse(
        content={"batch_id": batch_id, "files": items},
        status_code=200,
        headers={"X-Request-Id": _request_id(request)},
    )
