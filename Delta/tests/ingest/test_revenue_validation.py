"""X-005 revenue: payload validation + balanced two-leg mapping (UNIT, no DB).

Exercises the pure revenue posting helpers directly:
  * ``build_revenue_record`` — integer-cents discipline (NO float ever) and the
    permanent-failure taxonomy (INVALID_COST / MALFORMED_PAYLOAD / UNKNOWN_TENANT);
  * ``build_revenue_transaction`` — a balanced two-leg txn (DEBIT receivable, CREDIT revenue);
  * ``resolve_revenue_account_ids`` — deterministic per-(tenant, currency) ids that never
    collide with the usage expense/contra accounts.
"""

from __future__ import annotations

import uuid

import pytest

from delta.ingest.errors import DeadLetterReason, PermanentIngestError
from delta.ingest.posting import (
    build_revenue_record,
    build_revenue_transaction,
    revenue_idempotency_key,
)
from delta.ingest.resolver import resolve_account_ids, resolve_revenue_account_ids
from delta.ledger import EntryDirection
from delta.revenue import REVENUE_SOURCE_PRODUCT, RevenueEventType, RevenueRecord


def test_valid_grant_yields_record_with_integer_amount(revenue_event):
    tenant = str(uuid.uuid4())
    record = build_revenue_record(revenue_event(tenant, amount=1999))
    assert isinstance(record, RevenueRecord)
    assert record.amount_cents == 1999
    assert type(record.amount_cents) is int  # noqa: E721 - exact int, never a float
    assert record.tenant_id == tenant
    assert record.event_type is RevenueEventType.SUBSCRIPTION_GRANTED
    assert record.tier == "premium"
    assert record.currency == "USD"  # default applied when omitted


def test_valid_revoke_is_accepted_as_record(revenue_event):
    tenant = str(uuid.uuid4())
    record = build_revenue_record(revenue_event(tenant, event_type="subscription_revoked"))
    assert record.event_type is RevenueEventType.SUBSCRIPTION_REVOKED


def test_explicit_currency_is_respected(revenue_event):
    tenant = str(uuid.uuid4())
    record = build_revenue_record(revenue_event(tenant, currency="EUR"))
    assert record.currency == "EUR"


# --------------------------------------------------------------------------- rejections
def test_float_amount_is_invalid_cost(revenue_event):
    tenant = str(uuid.uuid4())
    with pytest.raises(PermanentIngestError) as exc:
        build_revenue_record(revenue_event(tenant, amount=19.99))
    assert exc.value.reason is DeadLetterReason.INVALID_COST


def test_bool_amount_is_invalid_cost(revenue_event):
    # bool is an int subclass; it must be rejected explicitly (never treated as 0/1 cents).
    tenant = str(uuid.uuid4())
    with pytest.raises(PermanentIngestError) as exc:
        build_revenue_record(revenue_event(tenant, amount=True))
    assert exc.value.reason is DeadLetterReason.INVALID_COST


def test_negative_amount_is_invalid_cost(revenue_event):
    tenant = str(uuid.uuid4())
    with pytest.raises(PermanentIngestError) as exc:
        build_revenue_record(revenue_event(tenant, amount=-1))
    assert exc.value.reason is DeadLetterReason.INVALID_COST


def test_over_max_amount_is_invalid_cost(revenue_event):
    tenant = str(uuid.uuid4())
    with pytest.raises(PermanentIngestError) as exc:
        build_revenue_record(revenue_event(tenant, amount=100_000_000_001))  # > 1e11
    assert exc.value.reason is DeadLetterReason.INVALID_COST


def test_missing_amount_is_malformed(revenue_event):
    tenant = str(uuid.uuid4())
    event = revenue_event(tenant)
    event.pop("amount_cents")
    with pytest.raises(PermanentIngestError) as exc:
        build_revenue_record(event)
    assert exc.value.reason is DeadLetterReason.MALFORMED_PAYLOAD


def test_bad_event_type_is_malformed(revenue_event):
    tenant = str(uuid.uuid4())
    with pytest.raises(PermanentIngestError) as exc:
        build_revenue_record(revenue_event(tenant, event_type="usage"))
    assert exc.value.reason is DeadLetterReason.MALFORMED_PAYLOAD


def test_missing_tenant_is_unknown_tenant_with_null_attribution(revenue_event):
    event = revenue_event(str(uuid.uuid4()))
    event.pop("tenant_id")
    with pytest.raises(PermanentIngestError) as exc:
        build_revenue_record(event)
    assert exc.value.reason is DeadLetterReason.UNKNOWN_TENANT
    assert exc.value.tenant_id is None  # tenant-NULL DLQ row (RLS-invisible)


@pytest.mark.parametrize("bad_key", ["has space", "bad/slash", "x" * 129, ""])
def test_bad_idempotency_key_pattern_is_malformed(revenue_event, bad_key):
    tenant = str(uuid.uuid4())
    with pytest.raises(PermanentIngestError) as exc:
        build_revenue_record(revenue_event(tenant, idempotency_key=bad_key))
    assert exc.value.reason is DeadLetterReason.MALFORMED_PAYLOAD


def test_missing_tier_is_malformed(revenue_event):
    tenant = str(uuid.uuid4())
    event = revenue_event(tenant)
    event.pop("tier")
    with pytest.raises(PermanentIngestError) as exc:
        build_revenue_record(event)
    assert exc.value.reason is DeadLetterReason.MALFORMED_PAYLOAD


def test_missing_occurred_at_is_malformed(revenue_event):
    tenant = str(uuid.uuid4())
    event = revenue_event(tenant)
    event.pop("occurred_at")
    with pytest.raises(PermanentIngestError) as exc:
        build_revenue_record(event)
    assert exc.value.reason is DeadLetterReason.MALFORMED_PAYLOAD


def test_non_dict_payload_is_malformed():
    with pytest.raises(PermanentIngestError) as exc:
        build_revenue_record(["not", "a", "dict"])
    assert exc.value.reason is DeadLetterReason.MALFORMED_PAYLOAD


# --------------------------------------------------------------------------- mapping
def test_build_revenue_transaction_is_balanced_debit_receivable_credit_revenue(revenue_event):
    tenant = str(uuid.uuid4())
    record = build_revenue_record(revenue_event(tenant, amount=5000))
    accounts = resolve_revenue_account_ids(record.tenant_id, record.currency)
    txn = build_revenue_transaction(record, accounts)

    assert len(txn.entries) == 2
    debits = [e for e in txn.entries if e.direction is EntryDirection.DEBIT]
    credits = [e for e in txn.entries if e.direction is EntryDirection.CREDIT]
    assert len(debits) == 1 and len(credits) == 1
    # DEBIT the receivable (asset); CREDIT the revenue account.
    assert debits[0].account_id == accounts.receivable_account_id
    assert credits[0].account_id == accounts.revenue_account_id
    # Net to zero, exact integer cents.
    net = sum(e.amount.minor_units for e in debits) - sum(e.amount.minor_units for e in credits)
    assert net == 0
    assert {e.tenant_id for e in txn.entries} == {tenant}
    assert {e.amount.currency for e in txn.entries} == {"USD"}
    assert txn.description == "Rendly subscription revenue: premium"
    # The agent attribution is the source product; team/project are the nil sentinel.
    assert {e.agent_id for e in txn.entries} == {REVENUE_SOURCE_PRODUCT}


def test_revenue_ids_deterministic_and_replay_stable(revenue_event):
    tenant = str(uuid.uuid4())
    event = revenue_event(tenant, idem="rev-stable-key")
    r1 = build_revenue_record(event)
    r2 = build_revenue_record(event)
    accts = resolve_revenue_account_ids(tenant, "USD")
    # Same (tenant, source_product, idempotency_key) -> identical txn id (replay-stable).
    txn1 = build_revenue_transaction(r1, accts)
    txn2 = build_revenue_transaction(r2, accts)
    assert txn1.txn_id == txn2.txn_id


def test_revenue_idempotency_key_is_source_namespaced(revenue_event):
    tenant = str(uuid.uuid4())
    record = build_revenue_record(revenue_event(tenant, idem="rev-abc"))
    assert revenue_idempotency_key(record) == "revenue:rendly:rev-abc"


def test_revenue_accounts_never_collide_with_usage_accounts():
    tenant = str(uuid.uuid4())
    usage = resolve_account_ids(tenant, "USD")
    revenue = resolve_revenue_account_ids(tenant, "USD")
    ids = {
        usage.expense_account_id,
        usage.contra_account_id,
        revenue.receivable_account_id,
        revenue.revenue_account_id,
    }
    assert len(ids) == 4  # all four distinct — no cross-role collision
