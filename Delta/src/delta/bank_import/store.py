"""Bank-import persistence (D-025, ADR-0025).

Tenant-scoped reads/writes against ``bank_sources``/``statement_imports``/
``imported_statement_lines`` (migration 0017). Every function takes an already-open
:class:`AsyncSession` (from ``delta.persistence.database.get_tenant_session``) and
does NOT commit — the caller (``service.py``) owns the transaction, exactly like
every prior Delta store module.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import insert, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.models import bank_sources, imported_statement_lines, statement_imports

DEFAULT_LIST_LIMIT = 100
MAX_LIST_LIMIT = 500


def _clamp_limit(limit: int) -> int:
    return max(1, min(limit, MAX_LIST_LIMIT))


def reference_hash(external_reference: str) -> str:
    """SHA-256 hex of the bank-side transaction reference. Equality is all dedup
    needs, so the raw bank-side identifier is never persisted (ADR-0025 Fork 2)."""
    return hashlib.sha256(external_reference.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SourceRecord:
    source_id: str
    tenant_id: str
    account_id: str
    institution_label: str
    created_by: str
    created_at: datetime


@dataclass(frozen=True)
class ImportRecord:
    import_id: str
    tenant_id: str
    source_id: str
    imported_by: str
    imported_at: datetime
    records_supplied: int
    records_imported: int
    records_skipped_duplicate: int
    records_rejected: int


@dataclass(frozen=True)
class LineRecord:
    line_id: str
    tenant_id: str
    import_id: str
    source_id: str
    external_reference_hash: str
    status: str
    rejected_reason: str | None
    txn_id: str | None
    created_at: datetime


def _source_from_row(row) -> SourceRecord:
    return SourceRecord(
        source_id=row.source_id,
        tenant_id=row.tenant_id,
        account_id=row.account_id,
        institution_label=row.institution_label,
        created_by=row.created_by,
        created_at=row.created_at,
    )


def _import_from_row(row) -> ImportRecord:
    return ImportRecord(
        import_id=row.import_id,
        tenant_id=row.tenant_id,
        source_id=row.source_id,
        imported_by=row.imported_by,
        imported_at=row.imported_at,
        records_supplied=row.records_supplied,
        records_imported=row.records_imported,
        records_skipped_duplicate=row.records_skipped_duplicate,
        records_rejected=row.records_rejected,
    )


async def acquire_source_import_lock(session: AsyncSession, *, source_id: str) -> None:
    """Transaction-scoped advisory lock serializing imports for ONE source — two
    concurrent imports of the same statement export would otherwise race the
    dedup check (the partial unique index would abort the whole second import with
    an IntegrityError instead of cleanly skipping duplicates). Same
    ``pg_advisory_xact_lock(hashtext(...))`` shape as D-024's per-account lock.
    """
    await session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:s))"), {"s": source_id})


# ------------------------------------------------------------------------- sources


async def create_source(
    session: AsyncSession,
    *,
    tenant_id: str,
    account_id: str,
    institution_label: str,
    created_by: str,
    now: datetime,
    source_id: str | None = None,
) -> SourceRecord:
    sid = source_id or str(uuid.uuid4())
    await session.execute(
        insert(bank_sources).values(
            source_id=sid,
            tenant_id=tenant_id,
            account_id=account_id,
            institution_label=institution_label,
            created_by=created_by,
            created_at=now,
        )
    )
    return SourceRecord(
        source_id=sid,
        tenant_id=tenant_id,
        account_id=account_id,
        institution_label=institution_label,
        created_by=created_by,
        created_at=now,
    )


async def get_source(session: AsyncSession, *, source_id: str) -> SourceRecord | None:
    row = (
        await session.execute(select(bank_sources).where(bank_sources.c.source_id == source_id))
    ).first()
    return None if row is None else _source_from_row(row)


async def list_sources(
    session: AsyncSession, *, limit: int = DEFAULT_LIST_LIMIT
) -> list[SourceRecord]:
    stmt = (
        select(bank_sources).order_by(bank_sources.c.created_at.desc()).limit(_clamp_limit(limit))
    )
    rows = (await session.execute(stmt)).all()
    return [_source_from_row(r) for r in rows]


# ------------------------------------------------------------------------- imports


async def imported_hashes_for_source(
    session: AsyncSession, *, source_id: str, hashes: list[str]
) -> set[str]:
    """The subset of ``hashes`` already IMPORTED for ``source_id`` — one query for
    the whole batch (never one query per line; D-012 Fork 2's no-N+1 discipline)."""
    if not hashes:
        return set()
    stmt = select(imported_statement_lines.c.external_reference_hash).where(
        imported_statement_lines.c.source_id == source_id,
        imported_statement_lines.c.status == "imported",
        imported_statement_lines.c.external_reference_hash.in_(hashes),
    )
    rows = (await session.execute(stmt)).all()
    return {r[0] for r in rows}


async def create_import(
    session: AsyncSession,
    *,
    tenant_id: str,
    source_id: str,
    imported_by: str,
    imported_at: datetime,
    records_supplied: int,
    records_imported: int,
    records_skipped_duplicate: int,
    records_rejected: int,
    import_id: str | None = None,
) -> ImportRecord:
    iid = import_id or str(uuid.uuid4())
    await session.execute(
        insert(statement_imports).values(
            import_id=iid,
            tenant_id=tenant_id,
            source_id=source_id,
            imported_by=imported_by,
            imported_at=imported_at,
            records_supplied=records_supplied,
            records_imported=records_imported,
            records_skipped_duplicate=records_skipped_duplicate,
            records_rejected=records_rejected,
        )
    )
    return ImportRecord(
        import_id=iid,
        tenant_id=tenant_id,
        source_id=source_id,
        imported_by=imported_by,
        imported_at=imported_at,
        records_supplied=records_supplied,
        records_imported=records_imported,
        records_skipped_duplicate=records_skipped_duplicate,
        records_rejected=records_rejected,
    )


async def create_line(
    session: AsyncSession,
    *,
    tenant_id: str,
    import_id: str,
    source_id: str,
    external_reference_hash: str,
    status: str,
    rejected_reason: str | None,
    txn_id: str | None,
    created_at: datetime,
    line_id: str | None = None,
) -> LineRecord:
    lid = line_id or str(uuid.uuid4())
    await session.execute(
        insert(imported_statement_lines).values(
            line_id=lid,
            tenant_id=tenant_id,
            import_id=import_id,
            source_id=source_id,
            external_reference_hash=external_reference_hash,
            status=status,
            rejected_reason=rejected_reason,
            txn_id=txn_id,
            created_at=created_at,
        )
    )
    return LineRecord(
        line_id=lid,
        tenant_id=tenant_id,
        import_id=import_id,
        source_id=source_id,
        external_reference_hash=external_reference_hash,
        status=status,
        rejected_reason=rejected_reason,
        txn_id=txn_id,
        created_at=created_at,
    )


async def list_imports(
    session: AsyncSession, *, source_id: str | None = None, limit: int = DEFAULT_LIST_LIMIT
) -> list[ImportRecord]:
    stmt = select(statement_imports)
    if source_id is not None:
        stmt = stmt.where(statement_imports.c.source_id == source_id)
    stmt = stmt.order_by(statement_imports.c.imported_at.desc()).limit(_clamp_limit(limit))
    rows = (await session.execute(stmt)).all()
    return [_import_from_row(r) for r in rows]
