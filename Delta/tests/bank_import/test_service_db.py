"""D-025 service-layer DB tests: dedup (across imports and within a batch), retryable
rejections, hash-only reference storage, counter consistency, D-009 audit wiring, and
cross-tenant isolation — all against a real Postgres, never stubbed."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import text

from delta.bank_import.schemas import ImportRequest, SourceRegisterRequest, StatementLine
from delta.bank_import.service import (
    AccountNotFoundError,
    SourceNotFoundError,
    list_import_summaries,
    register_source,
    run_import,
)
from delta.persistence.audit_log import list_history
from delta.persistence.database import get_privileged_session, get_tenant_session
from delta.personal_finance.schemas import AccountCreateRequest
from delta.personal_finance.service import create_account
from delta.personal_finance.store import list_transactions

from .conftest import db_required


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _make_account(tenant_id: str, *, currency: str = "USD") -> str:
    async with get_tenant_session(tenant_id) as session:
        account = await create_account(
            session,
            AccountCreateRequest(
                tenant_id=tenant_id, type="checking", currency=currency, name="Main"
            ),
            now=_now(),
        )
    return account.account_id


async def _make_source(tenant_id: str, account_id: str) -> str:
    async with get_tenant_session(tenant_id) as session:
        source = await register_source(
            session,
            SourceRegisterRequest(
                tenant_id=tenant_id,
                account_id=account_id,
                institution_label="Test Bank",
                created_by="Jane",
            ),
        )
    return source.source_id


def _line(ref: str, **overrides) -> StatementLine:
    payload = {
        "external_reference": ref,
        "amount_minor_units": -1250,
        "currency": "USD",
        "occurred_at": _now(),
    }
    payload.update(overrides)
    return StatementLine(**payload)


def _import_req(tenant_id: str, lines: list[StatementLine]) -> ImportRequest:
    return ImportRequest(tenant_id=tenant_id, imported_by="Jane", lines=lines)


@db_required
async def test_register_source_missing_account_raises(tenant_id) -> None:
    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(AccountNotFoundError):
            await register_source(
                session,
                SourceRegisterRequest(
                    tenant_id=tenant_id,
                    account_id="99999999-9999-4999-8999-999999999999",
                    institution_label="Ghost Bank",
                    created_by="Jane",
                ),
            )


@db_required
async def test_imported_lines_land_in_d021_ledger(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    source_id = await _make_source(tenant_id, account_id)

    async with get_tenant_session(tenant_id) as session:
        result = await run_import(
            session,
            source_id=source_id,
            req=_import_req(
                tenant_id,
                [
                    _line("ref-1", amount_minor_units=-1250, category="dining"),
                    _line("ref-2", amount_minor_units=250_000, category="income"),
                ],
            ),
        )

    assert result.records_supplied == 2
    assert result.records_imported == 2
    assert result.records_skipped_duplicate == 0
    assert result.records_rejected == 0

    async with get_tenant_session(tenant_id) as session:
        txns = await list_transactions(session, account_id=account_id, limit=10)
    assert len(txns) == 2
    assert all(t.source == "import" for t in txns)
    amounts = {t.amount_minor_units for t in txns}
    assert amounts == {-1250, 250_000}
    # Each imported line links to a real ledger row.
    ledger_ids = {t.txn_id for t in txns}
    assert {o.txn_id for o in result.lines} == ledger_ids


@db_required
async def test_reimport_of_same_lines_skips_all_as_duplicates(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    source_id = await _make_source(tenant_id, account_id)
    lines = [_line("ref-1"), _line("ref-2")]

    async with get_tenant_session(tenant_id) as session:
        await run_import(session, source_id=source_id, req=_import_req(tenant_id, lines))
    async with get_tenant_session(tenant_id) as session:
        second = await run_import(session, source_id=source_id, req=_import_req(tenant_id, lines))

    assert second.records_imported == 0
    assert second.records_skipped_duplicate == 2

    async with get_tenant_session(tenant_id) as session:
        txns = await list_transactions(session, account_id=account_id, limit=10)
    assert len(txns) == 2  # nothing imported twice


@db_required
async def test_duplicate_within_one_batch_imports_once(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    source_id = await _make_source(tenant_id, account_id)

    async with get_tenant_session(tenant_id) as session:
        result = await run_import(
            session,
            source_id=source_id,
            req=_import_req(tenant_id, [_line("ref-1"), _line("ref-1")]),
        )
    assert result.records_imported == 1
    assert result.records_skipped_duplicate == 1


@db_required
async def test_currency_mismatch_line_rejected_rest_import(tenant_id) -> None:
    account_id = await _make_account(tenant_id, currency="USD")
    source_id = await _make_source(tenant_id, account_id)

    async with get_tenant_session(tenant_id) as session:
        result = await run_import(
            session,
            source_id=source_id,
            req=_import_req(tenant_id, [_line("ref-1"), _line("ref-2", currency="EUR")]),
        )
    assert result.records_imported == 1
    assert result.records_rejected == 1
    rejected = [o for o in result.lines if o.status == "rejected"]
    assert rejected[0].rejected_reason == "currency_mismatch"
    assert rejected[0].txn_id is None


@db_required
async def test_rejected_line_reference_is_retryable_after_fix(tenant_id) -> None:
    account_id = await _make_account(tenant_id, currency="USD")
    source_id = await _make_source(tenant_id, account_id)

    async with get_tenant_session(tenant_id) as session:
        first = await run_import(
            session,
            source_id=source_id,
            req=_import_req(tenant_id, [_line("ref-1", currency="EUR")]),
        )
    assert first.records_rejected == 1

    # Same reference, fixed currency: imports cleanly (the unique index is partial).
    async with get_tenant_session(tenant_id) as session:
        retry = await run_import(
            session,
            source_id=source_id,
            req=_import_req(tenant_id, [_line("ref-1", currency="USD")]),
        )
    assert retry.records_imported == 1
    assert retry.records_skipped_duplicate == 0


@db_required
async def test_raw_external_reference_is_not_stored(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    source_id = await _make_source(tenant_id, account_id)
    raw_ref = "SUPER-SECRET-BANK-REF-XYZ.123"

    async with get_tenant_session(tenant_id) as session:
        await run_import(session, source_id=source_id, req=_import_req(tenant_id, [_line(raw_ref)]))

    # Scan every column of the stored line rows: the raw reference must appear
    # nowhere (only its SHA-256 hex, which never contains the raw substring).
    async with get_privileged_session() as session:
        rows = (await session.execute(text("SELECT * FROM delta.imported_statement_lines"))).all()
    assert rows, "expected at least one stored line row"
    for row in rows:
        for value in row:
            assert raw_ref not in str(value)


@db_required
async def test_counters_match_line_outcomes(tenant_id) -> None:
    account_id = await _make_account(tenant_id, currency="USD")
    source_id = await _make_source(tenant_id, account_id)

    async with get_tenant_session(tenant_id) as session:
        result = await run_import(
            session,
            source_id=source_id,
            req=_import_req(
                tenant_id,
                [_line("a"), _line("a"), _line("b", currency="EUR"), _line("c")],
            ),
        )
    by_status = {"imported": 0, "skipped_duplicate": 0, "rejected": 0}
    for outcome in result.lines:
        by_status[outcome.status] += 1
    assert result.records_imported == by_status["imported"] == 2
    assert result.records_skipped_duplicate == by_status["skipped_duplicate"] == 1
    assert result.records_rejected == by_status["rejected"] == 1
    assert result.records_supplied == 4

    async with get_tenant_session(tenant_id) as session:
        summaries = await list_import_summaries(session, source_id=source_id, limit=10)
    assert summaries[0].records_imported == 2


@db_required
async def test_cross_tenant_source_is_404(tenant_id, other_tenant_id) -> None:
    victim_account = await _make_account(other_tenant_id)
    victim_source = await _make_source(other_tenant_id, victim_account)

    async with get_tenant_session(tenant_id) as session:
        with pytest.raises(SourceNotFoundError):
            await run_import(
                session, source_id=victim_source, req=_import_req(tenant_id, [_line("ref-1")])
            )


@db_required
async def test_import_lands_in_d009_audit_chain(tenant_id) -> None:
    account_id = await _make_account(tenant_id)
    source_id = await _make_source(tenant_id, account_id)

    async with get_tenant_session(tenant_id) as session:
        result = await run_import(
            session, source_id=source_id, req=_import_req(tenant_id, [_line("ref-1")])
        )

    async with get_tenant_session(tenant_id) as session:
        source_rows = await list_history(session, entity_type="bank_source", entity_id=source_id)
        import_rows = await list_history(
            session, entity_type="statement_import", entity_id=result.import_id
        )
    assert {r.action for r in source_rows} == {"registered"}
    assert {r.action for r in import_rows} == {"imported"}
    assert "imported=1" in import_rows[0].note


@db_required
async def test_bank_import_tables_have_no_update_delete_grant() -> None:
    async with get_privileged_session() as session:
        rows = (
            await session.execute(
                text(
                    "SELECT table_name, privilege_type "
                    "FROM information_schema.role_table_grants "
                    "WHERE table_schema = 'delta' AND grantee = 'delta_app' "
                    "AND table_name IN "
                    "('bank_sources', 'statement_imports', 'imported_statement_lines')"
                )
            )
        ).all()
    by_table: dict[str, set[str]] = {}
    for table_name, privilege in rows:
        by_table.setdefault(table_name, set()).add(privilege)
    assert by_table == {
        "bank_sources": {"SELECT", "INSERT"},
        "statement_imports": {"SELECT", "INSERT"},
        "imported_statement_lines": {"SELECT", "INSERT"},
    }
