"""Vectors 3, 5, 7 — payload validation + balanced two-leg mapping (UNIT, no DB).

Exercises the pure posting helpers directly:
  * ``build_usage_record`` — integer-cents quantization (the one sanctioned float touch)
    and the permanent-failure taxonomy (INVALID_COST / MALFORMED_PAYLOAD / UNKNOWN_TENANT);
  * ``build_transaction`` — a balanced two-leg transaction (debit expense, credit contra);
  * ``resolve_account_ids`` — deterministic, per-(tenant, currency) account ids (vector 7).
"""

from __future__ import annotations

import uuid

import pytest

from delta.ingest.errors import DeadLetterReason, PermanentIngestError
from delta.ingest.posting import build_transaction, build_usage_record
from delta.ingest.resolver import resolve_account_ids
from delta.ledger import EntryDirection
from delta.usage import UsageRecord


def test_valid_event_yields_record_with_integer_cost(usage_event):
    tenant = str(uuid.uuid4())
    record = build_usage_record(usage_event(tenant, cost=1234))
    assert isinstance(record, UsageRecord)
    assert record.cost_estimate_cents == 1234
    assert type(record.cost_estimate_cents) is int  # noqa: E721 - exact int, never a float
    assert record.tenant_id == tenant
    assert record.currency == "USD"


def test_fractional_cost_quantizes_half_even(usage_event):
    tenant = str(uuid.uuid4())
    # 1234.6 rounds to 1235 (nearest); the result is an exact int, no float retained.
    record = build_usage_record(usage_event(tenant, cost=1234.6))
    assert record.cost_estimate_cents == 1235
    assert type(record.cost_estimate_cents) is int  # noqa: E721 - exact int, never a float


def test_half_even_rounds_to_even(usage_event):
    tenant = str(uuid.uuid4())
    # 12.5 -> 12 (banker's rounding to the even neighbour), never 13.
    assert build_usage_record(usage_event(tenant, cost=12.5)).cost_estimate_cents == 12


def test_negative_cost_is_invalid_cost(usage_event):
    tenant = str(uuid.uuid4())
    with pytest.raises(PermanentIngestError) as exc:
        build_usage_record(usage_event(tenant, cost=-5))
    assert exc.value.reason is DeadLetterReason.INVALID_COST


@pytest.mark.parametrize("bad", [float("inf"), float("nan"), 1e30])
def test_non_finite_or_overrange_cost_is_invalid_cost(usage_event, bad):
    tenant = str(uuid.uuid4())
    with pytest.raises(PermanentIngestError) as exc:
        build_usage_record(usage_event(tenant, cost=bad))
    assert exc.value.reason is DeadLetterReason.INVALID_COST


def test_non_usage_event_type_is_malformed_payload(usage_event):
    tenant = str(uuid.uuid4())
    with pytest.raises(PermanentIngestError) as exc:
        build_usage_record(usage_event(tenant, event_type="audit"))
    assert exc.value.reason is DeadLetterReason.MALFORMED_PAYLOAD


def test_missing_tenant_is_unknown_tenant_with_null_attribution(usage_event):
    event = usage_event(str(uuid.uuid4()))
    event.pop("tenant_id")
    with pytest.raises(PermanentIngestError) as exc:
        build_usage_record(event)
    assert exc.value.reason is DeadLetterReason.UNKNOWN_TENANT
    # Attribution is NULL so the dead-letter row is written tenant-NULL (RLS-invisible).
    assert exc.value.tenant_id is None


def test_missing_cost_is_malformed_payload(usage_event):
    event = usage_event(str(uuid.uuid4()))
    event.pop("cost_estimate_cents")
    with pytest.raises(PermanentIngestError) as exc:
        build_usage_record(event)
    assert exc.value.reason is DeadLetterReason.MALFORMED_PAYLOAD


def test_build_transaction_is_balanced_two_leg(usage_event):
    tenant = str(uuid.uuid4())
    record = build_usage_record(usage_event(tenant, cost=5000))
    accounts = resolve_account_ids(record.tenant_id, record.currency)
    txn = build_transaction(record, accounts)

    assert len(txn.entries) == 2
    debits = [e for e in txn.entries if e.direction is EntryDirection.DEBIT]
    credits = [e for e in txn.entries if e.direction is EntryDirection.CREDIT]
    assert len(debits) == 1 and len(credits) == 1
    # Debit posts to the expense account; credit posts to the contra (clearing) account.
    assert debits[0].account_id == accounts.expense_account_id
    assert credits[0].account_id == accounts.contra_account_id
    # Net to zero, exact integer cents.
    net = sum(e.amount.minor_units for e in debits) - sum(e.amount.minor_units for e in credits)
    assert net == 0
    # Both legs are same-tenant, same-currency.
    assert {e.tenant_id for e in txn.entries} == {tenant}
    assert {e.amount.currency for e in txn.entries} == {"USD"}


def test_resolve_account_ids_is_deterministic_and_scoped():
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())

    a1 = resolve_account_ids(tenant_a, "USD")
    a2 = resolve_account_ids(tenant_a, "USD")
    # Deterministic: same inputs -> identical ids.
    assert a1 == a2
    # The two roles are distinct accounts.
    assert a1.expense_account_id != a1.contra_account_id

    # Differs per tenant.
    b = resolve_account_ids(tenant_b, "USD")
    assert a1.expense_account_id != b.expense_account_id
    assert a1.contra_account_id != b.contra_account_id

    # Differs per currency.
    a_eur = resolve_account_ids(tenant_a, "EUR")
    assert a1.expense_account_id != a_eur.expense_account_id
    assert a1.contra_account_id != a_eur.contra_account_id
