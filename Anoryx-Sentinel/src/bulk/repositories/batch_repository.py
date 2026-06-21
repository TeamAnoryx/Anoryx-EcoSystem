"""BatchRepository — all CRUD on a TENANT session (RLS-scoped) (F-015, ADR-0018).

Every method runs inside `get_tenant_session(tenant_id)` opened by the caller, so
RLS is the isolation floor: a query can only ever see/write the GUC tenant's rows.
The repo NEVER opens its own session and NEVER touches the privileged engine — the
worker passes its per-job tenant session in (Fork 1 (a)).

`get_tenant_session` autobegins a transaction; the repo only add/flush/execute and
lets the caller's context commit (no nested begin()).
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from bulk.models.batch import Batch
from bulk.models.batch_file import FILE_TERMINAL_STATUSES, BatchFile


class BatchRepository:
    """Tenant-scoped CRUD for batches + batch_files."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    # ----------------------------------------------------------- submit-side
    async def get_by_idempotency_key(self, tenant_id: str, idempotency_key: str) -> Batch | None:
        """Return the existing batch for (tenant, key), or None (idempotency, vector 9)."""
        stmt = select(Batch).where(
            Batch.tenant_id == tenant_id,
            Batch.idempotency_key == idempotency_key,
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def create_batch(
        self,
        *,
        tenant_id: str,
        team_id: str,
        project_id: str,
        agent_id: str,
        idempotency_key: str,
        object_keys: list[str],
        model: str | None = None,
    ) -> tuple[Batch, list[BatchFile]]:
        """Insert a batch + one queued batch_file per object key. Caller commits.

        Returns (batch, files) so the caller can enqueue one job per file without
        a second query. RLS WITH CHECK rejects any row whose tenant_id != the
        session GUC, so a mis-scoped insert fails closed at the DB. May raise
        IntegrityError on a concurrent duplicate (tenant, key) — the caller re-fetches.
        """
        batch_id = str(uuid.uuid4())
        batch = Batch(
            batch_id=batch_id,
            tenant_id=tenant_id,
            team_id=team_id,
            project_id=project_id,
            agent_id=agent_id,
            idempotency_key=idempotency_key,
            model=model,
            status="queued",
            total_files=len(object_keys),
        )
        self._session.add(batch)
        files: list[BatchFile] = []
        for key in object_keys:
            bf = BatchFile(
                file_id=str(uuid.uuid4()),
                batch_id=batch_id,
                tenant_id=tenant_id,
                object_key=key,
                status="queued",
            )
            files.append(bf)
            self._session.add(bf)
        await self._session.flush()
        return batch, files

    # ----------------------------------------------------------- read-side
    async def get_batch(self, batch_id: str) -> Batch | None:
        """Return the batch by id (RLS-scoped — only the caller tenant's rows)."""
        stmt = select(Batch).where(Batch.batch_id == batch_id)
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def list_files(self, batch_id: str) -> list[BatchFile]:
        """Per-file manifest rows for a batch (RLS-scoped, read-only)."""
        stmt = (
            select(BatchFile)
            .where(BatchFile.batch_id == batch_id)
            .order_by(BatchFile.created_at, BatchFile.file_id)
        )
        return list((await self._session.execute(stmt)).scalars().all())

    async def count_files_by_status(self, batch_id: str) -> dict[str, int]:
        """Map of status -> count for a batch (RLS-scoped)."""
        stmt = (
            select(BatchFile.status, func.count())
            .where(BatchFile.batch_id == batch_id)
            .group_by(BatchFile.status)
        )
        rows = (await self._session.execute(stmt)).all()
        return {status: int(n) for status, n in rows}

    # ----------------------------------------------------------- worker-side
    async def get_file(self, file_id: str) -> BatchFile | None:
        stmt = select(BatchFile).where(BatchFile.file_id == file_id)
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def count_non_terminal_files(self, batch_id: str) -> int:
        """Count files NOT yet in a terminal state (for completion detection)."""
        stmt = select(func.count()).where(
            BatchFile.batch_id == batch_id,
            BatchFile.status.notin_(FILE_TERMINAL_STATUSES),
        )
        return int((await self._session.execute(stmt)).scalar_one())

    async def mark_batch_status(self, batch_id: str, status: str) -> None:
        batch = await self.get_batch(batch_id)
        if batch is not None:
            batch.status = status
            await self._session.flush()

    async def try_complete_batch(self, batch_id: str) -> bool:
        """Atomically flip the batch to 'completed' iff all files are terminal and it
        is not already completed. Returns True iff THIS call won the transition.

        Concurrency-safe (review HIGH-2): two workers finishing the last files cannot
        both win — the `status <> 'completed'` guard + the single UPDATE statement
        mean exactly one transition succeeds, so batch_completed is emitted once. RLS
        scopes both tables to the GUC tenant. The caller commits.
        """
        stmt = text(
            """
            UPDATE batches SET status = 'completed', updated_at = now()
            WHERE batch_id = :bid AND status <> 'completed'
              AND NOT EXISTS (
                SELECT 1 FROM batch_files
                WHERE batch_id = :bid
                  AND status NOT IN ('done', 'blocked', 'dead_lettered')
              )
            RETURNING batch_id
            """
        )
        row = (await self._session.execute(stmt, {"bid": batch_id})).first()
        return row is not None

    async def set_file_status(
        self,
        file_id: str,
        *,
        status: str,
        outcome: str | None = None,
        failure_class: str | None = None,
        increment_attempt: bool = False,
    ) -> BatchFile | None:
        """Update a file row's status/outcome (RLS-scoped). Returns the row or None.

        Only mutates fields that are passed (outcome/failure_class set when given).
        increment_attempt bumps attempt_count for bounded-retry accounting.
        """
        bf = await self.get_file(file_id)
        if bf is None:
            return None
        bf.status = status
        if outcome is not None:
            bf.outcome = outcome
        if failure_class is not None:
            bf.failure_class = failure_class
        if increment_attempt:
            bf.attempt_count = bf.attempt_count + 1
        await self._session.flush()
        return bf
