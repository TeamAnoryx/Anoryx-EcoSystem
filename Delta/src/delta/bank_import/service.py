"""Bank-import orchestration (D-025, ADR-0025).

``run_import`` normalizes a batch of caller-supplied statement lines into D-021's
personal ledger in ONE database transaction:

- per-source advisory lock (two concurrent imports of the same export dedup
  cleanly instead of racing the partial unique index into an IntegrityError),
- batch dedup via ONE query over the lines' reference hashes (never per-line),
- per-line outcome rows (imported / skipped_duplicate / rejected) with the bank
  reference stored only as its SHA-256 hash,
- one D-021 ``personal_transactions`` row (``source='import'``) per imported line,
- one D-009 audit-chain row per import RUN (per-line audit rows would flood the
  chain with what the lines table already records; the run row carries the counters).

Duplicates WITHIN one request batch dedup against each other too (first occurrence
wins) — a statement export with a repeated reference must not import twice any more
than two separate imports of the same export may.

Honesty boundary (ADR-0025 Sec 1): the caller supplies the statement lines. No bank
connection exists in this codebase; a future real aggregator's integration point is
exactly this module's input shape.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from ..persistence.audit_log import append_history
from ..personal_finance import store as personal_finance_store
from . import store
from .schemas import (
    ImportRequest,
    ImportResultView,
    ImportSummaryView,
    LineOutcomeView,
    SourceRegisterRequest,
    SourceView,
)


class AccountNotFoundError(LookupError):
    pass


class SourceNotFoundError(LookupError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _source_to_view(record: store.SourceRecord) -> SourceView:
    return SourceView(
        source_id=record.source_id,
        tenant_id=record.tenant_id,
        account_id=record.account_id,
        institution_label=record.institution_label,
        created_by=record.created_by,
        created_at=record.created_at,
    )


def _import_to_summary(record: store.ImportRecord) -> ImportSummaryView:
    return ImportSummaryView(
        import_id=record.import_id,
        tenant_id=record.tenant_id,
        source_id=record.source_id,
        imported_by=record.imported_by,
        imported_at=record.imported_at,
        records_supplied=record.records_supplied,
        records_imported=record.records_imported,
        records_skipped_duplicate=record.records_skipped_duplicate,
        records_rejected=record.records_rejected,
    )


# ------------------------------------------------------------------------- sources


async def register_source(session: AsyncSession, req: SourceRegisterRequest) -> SourceView:
    account = await personal_finance_store.get_account(session, account_id=req.account_id)
    if account is None or account.tenant_id != req.tenant_id:
        raise AccountNotFoundError(req.account_id)
    now = _now()
    record = await store.create_source(
        session,
        tenant_id=req.tenant_id,
        account_id=req.account_id,
        institution_label=req.institution_label,
        created_by=req.created_by,
        now=now,
    )
    await append_history(
        session,
        tenant_id=req.tenant_id,
        entity_type="bank_source",
        entity_id=record.source_id,
        action="registered",
        actor=req.created_by,
        now=now,
        note=req.institution_label,
    )
    await session.commit()
    return _source_to_view(record)


async def list_source_views(session: AsyncSession, *, limit: int) -> list[SourceView]:
    records = await store.list_sources(session, limit=limit)
    return [_source_to_view(r) for r in records]


# ------------------------------------------------------------------------- imports


async def run_import(
    session: AsyncSession, *, source_id: str, req: ImportRequest
) -> ImportResultView:
    source = await store.get_source(session, source_id=source_id)
    if source is None or source.tenant_id != req.tenant_id:
        raise SourceNotFoundError(source_id)
    account = await personal_finance_store.get_account(session, account_id=source.account_id)
    if account is None:
        raise AccountNotFoundError(source.account_id)  # unreachable: FK-backed

    now = _now()

    # Serialize concurrent imports for this source (see module docstring).
    await store.acquire_source_import_lock(session, source_id=source_id)

    hashes = [store.reference_hash(line.external_reference) for line in req.lines]
    already_imported = await store.imported_hashes_for_source(
        session, source_id=source_id, hashes=hashes
    )

    # First pass: decide every line's outcome and write the imported lines' D-021
    # ledger rows. The statement_imports row (whose counters these outcomes sum to)
    # is inserted AFTER this pass — imported_statement_lines' composite FK points at
    # it, so the parent row must exist before any line row is inserted.
    decided: list[tuple[str, str, str | None, str | None]] = []  # (hash, status, reason, txn_id)
    seen_in_batch: set[str] = set()
    imported = skipped = rejected = 0

    for line, line_hash in zip(req.lines, hashes, strict=True):
        if line_hash in already_imported or line_hash in seen_in_batch:
            decided.append((line_hash, "skipped_duplicate", None, None))
            skipped += 1
        elif line.currency != account.currency:
            decided.append((line_hash, "rejected", "currency_mismatch", None))
            rejected += 1
        else:
            txn = await personal_finance_store.create_transaction(
                session,
                tenant_id=req.tenant_id,
                account_id=source.account_id,
                category=line.category,
                amount_minor_units=line.amount_minor_units,
                currency=line.currency,
                description=line.description,
                merchant=line.merchant,
                occurred_at=line.occurred_at,
                now=now,
                source="import",
            )
            decided.append((line_hash, "imported", None, txn.txn_id))
            seen_in_batch.add(line_hash)
            imported += 1

    import_record = await store.create_import(
        session,
        tenant_id=req.tenant_id,
        source_id=source_id,
        imported_by=req.imported_by,
        imported_at=now,
        records_supplied=len(req.lines),
        records_imported=imported,
        records_skipped_duplicate=skipped,
        records_rejected=rejected,
    )

    outcomes: list[LineOutcomeView] = []
    for line_hash, status, reason, txn_id in decided:
        line_record = await store.create_line(
            session,
            tenant_id=req.tenant_id,
            import_id=import_record.import_id,
            source_id=source_id,
            external_reference_hash=line_hash,
            status=status,
            rejected_reason=reason,
            txn_id=txn_id,
            created_at=now,
        )
        outcomes.append(
            LineOutcomeView(
                line_id=line_record.line_id,
                external_reference_hash=line_hash,
                status=status,  # type: ignore[arg-type]
                rejected_reason=reason,  # type: ignore[arg-type]
                txn_id=txn_id,
            )
        )
    await append_history(
        session,
        tenant_id=req.tenant_id,
        entity_type="statement_import",
        entity_id=import_record.import_id,
        action="imported",
        actor=req.imported_by,
        now=now,
        note=(
            f"supplied={len(req.lines)} imported={imported} "
            f"skipped_duplicate={skipped} rejected={rejected}"
        ),
    )
    await session.commit()

    return ImportResultView(
        import_id=import_record.import_id,
        tenant_id=import_record.tenant_id,
        source_id=import_record.source_id,
        imported_by=import_record.imported_by,
        imported_at=import_record.imported_at,
        records_supplied=import_record.records_supplied,
        records_imported=import_record.records_imported,
        records_skipped_duplicate=import_record.records_skipped_duplicate,
        records_rejected=import_record.records_rejected,
        lines=outcomes,
    )


async def list_import_summaries(
    session: AsyncSession, *, source_id: str | None, limit: int
) -> list[ImportSummaryView]:
    records = await store.list_imports(session, source_id=source_id, limit=limit)
    return [_import_to_summary(r) for r in records]
