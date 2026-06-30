"""Event -> balanced two-leg transaction -> ledger (ADR-0004 Forks 3+4; vectors 2,3,5).

A Sentinel ``usage`` event becomes ONE balanced transaction with exactly two entries:

    DEBIT   <tenant expense account>          cost_cents
    CREDIT  <tenant spend-clearing contra>    cost_cents      (nets to zero)

Cost is the wire ``cost_estimate_cents`` (a JSON number) quantized to integer cents
via ``Money.from_wire_cents`` — the only sanctioned float touch; negative / non-finite
/ over-range costs are rejected (INVALID_COST). The transaction is balanced by
construction (and re-checked by the D-003 deferred trigger at COMMIT). Account
creation and the posting share ONE tenant session so the composite same-tenant FK is
satisfied atomically (no orphan accounts on a failed post).

Idempotency (Fork 4): the Sentinel ``event_id`` is passed as the ledger
``idempotency_key``; the partial-UNIQUE ``(tenant_id, idempotency_key)`` makes a
replayed event a no-op (zero entries) — exactly one debit survives a replay.
"""

from __future__ import annotations

import re
import uuid

from pydantic import ValidationError

from ..ledger import EntryDirection, LedgerEntry, Transaction
from ..money import DEFAULT_CURRENCY, Money
from ..persistence.database import get_tenant_session
from ..persistence.ledger_store import AppendResult, append_transaction
from .errors import DeadLetterReason, PermanentIngestError
from .resolver import ResolvedAccounts, ensure_accounts

# Deterministic namespace for txn/entry ids derived from (tenant, event_id).
_POSTING_NAMESPACE = uuid.UUID("d0e1f2a3-0004-4000-8000-00000000d004")

# Canonical dashed UUID, matching delta.identifiers._UUID_PATTERN (the RLS join shape).
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

_USAGE_EVENT_TYPE = "usage"


def _is_valid_tenant(value: object) -> bool:
    return isinstance(value, str) and bool(_UUID_RE.match(value))


def build_usage_record(payload: object):
    """Validate a raw event payload into a ``UsageRecord`` or raise PermanentIngestError.

    Imported lazily-typed (returns ``delta.usage.UsageRecord``). Attribution is
    captured best-effort so the dead-letter row is auditable even for malformed input.
    """
    from ..usage import UsageRecord  # local import keeps the module graph shallow

    if not isinstance(payload, dict):
        raise PermanentIngestError(
            DeadLetterReason.MALFORMED_PAYLOAD, "event payload is not a JSON object"
        )

    raw_event_type = payload.get("event_type")
    raw_event_id = payload.get("event_id")
    raw_tenant = payload.get("tenant_id")
    # Only attribute a tenant to the DLQ row when it is a well-formed tenant id, so the
    # row is tenant-visible under RLS; otherwise the row is written tenant-NULL.
    attr_tenant = raw_tenant if _is_valid_tenant(raw_tenant) else None
    attr_event_id = raw_event_id if isinstance(raw_event_id, str) else None
    attr_event_type = raw_event_type if isinstance(raw_event_type, str) else None

    if raw_event_type != _USAGE_EVENT_TYPE:
        raise PermanentIngestError(
            DeadLetterReason.MALFORMED_PAYLOAD,
            f"unsupported event_type {raw_event_type!r} (only 'usage' is ingested)",
            tenant_id=attr_tenant,
            event_id=attr_event_id,
            event_type=attr_event_type,
        )

    if not _is_valid_tenant(raw_tenant):
        raise PermanentIngestError(
            DeadLetterReason.UNKNOWN_TENANT,
            "missing or malformed tenant_id",
            tenant_id=None,
            event_id=attr_event_id,
            event_type=attr_event_type,
        )

    if "cost_estimate_cents" not in payload:
        raise PermanentIngestError(
            DeadLetterReason.MALFORMED_PAYLOAD,
            "missing cost_estimate_cents",
            tenant_id=attr_tenant,
            event_id=attr_event_id,
            event_type=attr_event_type,
        )
    try:
        cost_cents = Money.from_wire_cents(
            payload["cost_estimate_cents"], DEFAULT_CURRENCY
        ).minor_units
    except (ValueError, TypeError) as exc:
        raise PermanentIngestError(
            DeadLetterReason.INVALID_COST,
            f"invalid cost_estimate_cents: {exc}",
            tenant_id=attr_tenant,
            event_id=attr_event_id,
            event_type=attr_event_type,
        ) from exc

    # Defense-in-depth: latency_ms is a REQUIRED integer on the events.schema.json
    # UsageEvent, but UsageRecord does not carry it, so a payload omitting it (or sending a
    # non-integer) would otherwise pass validation silently. Reject it as malformed here.
    # bool is excluded — a JSON true is not a valid latency.
    raw_latency = payload.get("latency_ms")
    if not isinstance(raw_latency, int) or isinstance(raw_latency, bool):
        raise PermanentIngestError(
            DeadLetterReason.MALFORMED_PAYLOAD,
            "missing or non-integer latency_ms",
            tenant_id=attr_tenant,
            event_id=attr_event_id,
            event_type=attr_event_type,
        )

    try:
        record = UsageRecord(
            tenant_id=raw_tenant,
            team_id=payload.get("team_id"),
            project_id=payload.get("project_id"),
            agent_id=payload.get("agent_id"),
            model=payload.get("model"),
            tokens_in=payload.get("tokens_in"),
            tokens_out=payload.get("tokens_out"),
            cost_estimate_cents=cost_cents,
            currency=DEFAULT_CURRENCY,
            request_id=payload.get("request_id"),
            event_id=payload.get("event_id"),
            event_timestamp=payload.get("event_timestamp"),
        )
    except ValidationError as exc:
        raise PermanentIngestError(
            DeadLetterReason.MALFORMED_PAYLOAD,
            "usage event failed schema validation",
            tenant_id=attr_tenant,
            event_id=attr_event_id,
            event_type=attr_event_type,
        ) from exc
    return record


def build_transaction(record, accounts: ResolvedAccounts) -> Transaction:
    """Map a validated ``UsageRecord`` to a balanced two-leg ``Transaction``.

    Ids are deterministic over (tenant, event_id) so a replay names the same txn/entry
    ids (the ledger's idempotency key still does the real dedup work).
    """
    amount = Money(minor_units=record.cost_estimate_cents, currency=record.currency)
    txn_id = str(uuid.uuid5(_POSTING_NAMESPACE, f"{record.tenant_id}:{record.event_id}"))
    debit_id = str(uuid.uuid5(_POSTING_NAMESPACE, f"{record.tenant_id}:{record.event_id}:debit"))
    credit_id = str(uuid.uuid5(_POSTING_NAMESPACE, f"{record.tenant_id}:{record.event_id}:credit"))

    common = {
        "tenant_id": record.tenant_id,
        "amount": amount,
        "team_id": record.team_id,
        "project_id": record.project_id,
        "agent_id": record.agent_id,
        "timestamp": record.event_timestamp,
    }
    debit = LedgerEntry(
        entry_id=debit_id,
        account_id=accounts.expense_account_id,
        direction=EntryDirection.DEBIT,
        **common,
    )
    credit = LedgerEntry(
        entry_id=credit_id,
        account_id=accounts.contra_account_id,
        direction=EntryDirection.CREDIT,
        **common,
    )
    return Transaction(
        txn_id=txn_id,
        tenant_id=record.tenant_id,
        entries=(debit, credit),
        timestamp=record.event_timestamp,
        description=f"AI usage: {record.model}",
    )


async def post_usage(record) -> AppendResult:
    """Post a validated ``UsageRecord`` as one balanced, idempotent debit.

    Opens ONE tenant session: ensures the two canonical accounts exist (no commit),
    then ``append_transaction`` inserts the entries and commits — so account-create +
    posting are atomic and the composite same-tenant FK is satisfied in-transaction.
    Connectivity errors propagate (the caller classifies them transient -> 503); the
    DB is the final authority on balance / tenant / immutability.
    """
    async with get_tenant_session(record.tenant_id) as session:
        accounts = await ensure_accounts(session, record.tenant_id, record.currency)
        txn = build_transaction(record, accounts)
        return await append_transaction(session, txn, idempotency_key=record.event_id)
