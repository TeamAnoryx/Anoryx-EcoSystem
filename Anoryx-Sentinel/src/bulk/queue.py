"""Redis Streams job queue for the bulk pipeline (F-015, ADR-0018 §1.2/§3).

One message PER FILE (file-level fan-out) → maximum worker parallelism + per-file
failure isolation (R7). Delivery is at-least-once (Fork 2): a redelivered or
replayed file is deduped by its terminal status in `batch_files` (the worker skips
files already done/blocked/dead_lettered — R5/checkpoint).

This module is the PRODUCER + the message type + the consumer-group plumbing
(XADD / XREADGROUP / XACK / DLQ XADD). It reuses the F-009 Redis pool
(`gateway.redis_client.get_client`). The job message carries the four stable IDs so
the worker can open the correct per-job tenant session (Fork 1 (a)). It carries NO
file content — only the object key (content is fetched from storage, never queued).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import structlog

from bulk.config import get_bulk_settings
from gateway.redis_client import get_client

log = structlog.get_logger(__name__)

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


@dataclass(frozen=True, slots=True)
class JobMessage:
    """One file-processing job. Flat str fields only (Redis Streams)."""

    batch_id: str
    file_id: str
    tenant_id: str
    team_id: str
    project_id: str
    agent_id: str
    object_key: str
    idempotency_key: str
    # Target model the batch is destined for ("" = none → detectors-only scan).
    model: str = ""

    def to_fields(self) -> dict[str, str]:
        return {
            "batch_id": self.batch_id,
            "file_id": self.file_id,
            "tenant_id": self.tenant_id,
            "team_id": self.team_id,
            "project_id": self.project_id,
            "agent_id": self.agent_id,
            "object_key": self.object_key,
            "idempotency_key": self.idempotency_key,
            "model": self.model,
        }

    @classmethod
    def from_fields(cls, fields: dict[str, str]) -> JobMessage:
        """Deserialize + VALIDATE a stream message. Raises KeyError/ValueError on a
        malformed message so the consumer discards it (never writes corrupt IDs to
        the audit log, never reclaim-loops a poison message — review MED)."""
        job = cls(
            batch_id=fields["batch_id"],
            file_id=fields["file_id"],
            tenant_id=fields["tenant_id"],
            team_id=fields["team_id"],
            project_id=fields["project_id"],
            agent_id=fields["agent_id"],
            object_key=fields["object_key"],
            idempotency_key=fields["idempotency_key"],
            model=fields.get("model", ""),
        )
        for uid in (job.batch_id, job.file_id, job.tenant_id, job.team_id, job.project_id):
            if not _UUID_RE.match(uid):
                raise ValueError("job message carries a non-UUID stable id")
        if not job.agent_id or not job.object_key:
            raise ValueError("job message missing agent_id/object_key")
        return job


async def enqueue_files(jobs: list[JobMessage]) -> None:
    """XADD one message per file to the jobs stream (producer).

    Called by the submission API AFTER the batch + file rows are committed. On an
    idempotent re-submit (existing batch) the caller does NOT call this — so a
    replayed key never re-enqueues (no double-process, vector 9).
    """
    if not jobs:
        return
    settings = get_bulk_settings()
    stream = settings.bulk_stream_key
    async with await get_client() as client:
        for job in jobs:
            await client.xadd(stream, job.to_fields())


async def ensure_group() -> None:
    """Create the consumer group (idempotent) — MKSTREAM so it works pre-first-XADD."""
    settings = get_bulk_settings()
    async with await get_client() as client:
        try:
            await client.xgroup_create(
                settings.bulk_stream_key,
                settings.bulk_consumer_group,
                id="0",
                mkstream=True,
            )
        except Exception as exc:
            # BUSYGROUP — group already exists. Any other error re-raises.
            if "BUSYGROUP" not in str(exc):
                raise


async def queue_depth() -> int:
    """Return the jobs-stream length — the KEDA-ready scaling signal (D9).

    LEAN: stream length (XLEN) is the clean queue-depth signal a future KEDA
    ScaledObject would scale on. Best-effort; returns 0 on any Redis error.
    """
    settings = get_bulk_settings()
    try:
        async with await get_client() as client:
            return int(await client.xlen(settings.bulk_stream_key))
    except Exception:
        return 0


async def dead_letter(job: JobMessage, *, failure_class: str) -> None:
    """XADD a dead-lettered job to the DLQ stream (audited separately — R6)."""
    settings = get_bulk_settings()
    fields = job.to_fields()
    fields["failure_class"] = failure_class
    async with await get_client() as client:
        await client.xadd(settings.bulk_dlq_stream_key, fields)
