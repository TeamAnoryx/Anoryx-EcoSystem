"""JSON Schema contract conformance — vectors 6 (permissiveness) and 7 (bounds).

Proves: (a) every object def is closed (additionalProperties:false), (b) the
schema validates canonical Pydantic-serialized payloads, and (c) it REJECTS
malformed ones (extra keys, out-of-bounds, bad id formats). Uses the same
jsonschema Draft 2020-12 idiom the Sentinel contracts mandate.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from delta.accounts import Account, AccountType
from delta.budget import BudgetConcept, BudgetPeriod, BudgetScope
from delta.ledger import EntryDirection, LedgerEntry, Transaction
from delta.money import Money

_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "contracts" / "delta-financial.schema.json"
_SCHEMA = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
_NOW = datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)
_T = "12121212-1212-4212-8212-121212121212"
_TEAM = "13131313-1313-4313-8313-131313131313"
_PROJ = "14141414-1414-4414-8414-141414141414"


def _validator(defname: str) -> Draft202012Validator:
    # $ref + $defs sibling at root resolves internal #/$defs/... refs (Draft 2020-12).
    root = {"$ref": f"#/$defs/{defname}", "$defs": _SCHEMA["$defs"]}
    return Draft202012Validator(root, format_checker=Draft202012Validator.FORMAT_CHECKER)


def _entry(direction: EntryDirection, cents: int) -> LedgerEntry:
    return LedgerEntry(
        entry_id="15151515-1515-4515-8515-151515151515",
        tenant_id=_T,
        account_id="16161616-1616-4616-8616-161616161616",
        direction=direction,
        amount=Money(minor_units=cents),
        team_id=_TEAM,
        project_id=_PROJ,
        agent_id="gateway-core",
        timestamp=_NOW,
    )


# --- (a) every object def is closed --------------------------------------------
def test_schema_is_valid_draft202012():
    Draft202012Validator.check_schema(_SCHEMA)


def test_every_object_def_forbids_additional_properties():
    # Vector 6: a missing additionalProperties:false is a silent smuggling channel.
    for name, definition in _SCHEMA["$defs"].items():
        if definition.get("type") == "object":
            assert definition.get("additionalProperties") is False, f"{name} not closed"


# --- (b) canonical payloads validate -------------------------------------------
def test_money_canonical_valid():
    assert _validator("Money").is_valid(Money(minor_units=100).model_dump(mode="json"))


def test_transaction_canonical_valid():
    txn = Transaction(
        txn_id="17171717-1717-4717-8717-171717171717",
        tenant_id=_T,
        entries=[_entry(EntryDirection.DEBIT, 100), _entry(EntryDirection.CREDIT, 100)],
        timestamp=_NOW,
        description="ok",
    )
    errors = list(_validator("Transaction").iter_errors(txn.model_dump(mode="json")))
    assert errors == [], errors


def test_account_canonical_valid():
    acct = Account(
        account_id="18181818-1818-4818-8818-181818181818",
        tenant_id=_T,
        type=AccountType.EXPENSE,
        currency="USD",
        name="AI spend",
    )
    assert _validator("Account").is_valid(acct.model_dump(mode="json"))


def test_budget_concept_canonical_valid():
    bc = BudgetConcept(
        tenant_id=_T,
        team_id=_TEAM,
        project_id=_PROJ,
        agent_id="gateway-core",
        scope=BudgetScope.TEAM,
        period=BudgetPeriod.MONTHLY,
        limit_cost_cents=500000,
    )
    # Wire form omits unset optionals (null != absent); this is what D-002 emits.
    assert _validator("BudgetConcept").is_valid(bc.model_dump(mode="json", exclude_none=True))


# --- (c) malformed payloads rejected -------------------------------------------
def test_extra_key_rejected():
    # Vector 6: additionalProperties:false bites.
    payload = Money(minor_units=1).model_dump(mode="json")
    payload["smuggled"] = "x"
    assert not _validator("Money").is_valid(payload)


def test_money_float_rejected_by_schema():
    # Vector 1/7 at the wire layer: type integer rejects a float.
    assert not _validator("Money").is_valid({"minor_units": 1.5, "currency": "USD"})


def test_money_overflow_rejected_by_schema():
    assert not _validator("Money").is_valid({"minor_units": 100000000001, "currency": "USD"})


def test_missing_tenant_id_rejected():
    # Vector 7: a tenant-scoped shape without tenant_id is invalid.
    payload = Money(minor_units=1).model_dump(mode="json")
    acct = {
        "account_id": "18181818-1818-4818-8818-181818181818",
        "type": "asset",
        "currency": "USD",
        "name": "x",
    }
    assert not _validator("Account").is_valid(acct)
    assert _validator("Money").is_valid(payload)  # control


def test_bad_agent_slug_rejected():
    bc = {
        "tenant_id": _T,
        "team_id": _TEAM,
        "project_id": _PROJ,
        "agent_id": "Gateway_Core",  # uppercase + underscore: not the slug
        "scope": "team",
        "period": "monthly",
        "currency": "USD",
        "limit_cost_cents": 1,
    }
    assert not _validator("BudgetConcept").is_valid(bc)


def test_budget_concept_requires_a_limit():
    # anyOf: neither limit present -> invalid (mirrors the wire schema).
    bc = {
        "tenant_id": _T,
        "team_id": _TEAM,
        "project_id": _PROJ,
        "agent_id": "gateway-core",
        "scope": "team",
        "period": "monthly",
        "currency": "USD",
    }
    assert not _validator("BudgetConcept").is_valid(bc)


def test_bad_account_type_rejected():
    acct = {
        "account_id": "18181818-1818-4818-8818-181818181818",
        "tenant_id": _T,
        "type": "imaginary",
        "currency": "USD",
        "name": "x",
    }
    assert not _validator("Account").is_valid(acct)


@pytest.mark.parametrize(
    "defname",
    [
        "Money",
        "Account",
        "LedgerEntry",
        "Transaction",
        "BudgetConcept",
        "UsageRecord",
        "Allocation",
        "TimeWindow",
        "CostCenter",
        "Project",
        "AllocationTarget",
    ],
)
def test_all_expected_defs_present(defname):
    assert defname in _SCHEMA["$defs"]
