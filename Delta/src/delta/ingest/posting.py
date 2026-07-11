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
from ..money import DEFAULT_CURRENCY, MAX_MONEY_MINOR_UNITS, Money
from ..persistence.database import get_tenant_session
from ..persistence.ledger_store import AppendResult, append_transaction
from .errors import DeadLetterReason, PermanentIngestError
from .resolver import (
    ResolvedAccounts,
    ResolvedRevenueAccounts,
    ensure_accounts,
    ensure_revenue_accounts,
)

# Deterministic namespace for txn/entry ids derived from (tenant, event_id).
_POSTING_NAMESPACE = uuid.UUID("d0e1f2a3-0004-4000-8000-00000000d004")

# Distinct deterministic namespace for X-005 revenue txn/entry ids, derived from
# (tenant, source_product, idempotency_key) — separate from the usage namespace above.
_REVENUE_POSTING_NAMESPACE = uuid.UUID("d0e1f2a3-0005-4000-8000-00000000d005")

# Canonical dashed UUID, matching delta.identifiers._UUID_PATTERN (the RLS join shape).
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

# The revenue idempotency-key charset (revenue_idempotency_key pattern, contract-owned).
_REVENUE_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")

_USAGE_EVENT_TYPE = "usage"

# A revenue entry carries no team/project attribution (a monetization event is
# tenant-scoped, not scoped to a team/project/agent). LedgerEntry requires these NOT-NULL
# fields, so we stamp an explicit, canonical nil-UUID sentinel meaning "not attributed"
# (a valid UUID shape; no FK on these columns) and the source product as the agent slug.
_REVENUE_UNATTRIBUTED_ID = "00000000-0000-0000-0000-000000000000"

# Max length of the DLQ source_event_id column (ingest_dead_letter, migration 0002). A
# revenue idempotency_key may be up to 128 chars, so we only attribute it as the DLQ
# correlation id when it fits; a longer key is left NULL there (still fully auditable via
# the JSONB original_payload) rather than overflowing the column and failing the DLQ write.
_DLQ_EVENT_ID_MAX_LENGTH = 64


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


# --------------------------------------------------------------------------- X-005 revenue


def revenue_dlq_event_id(idempotency_key: object) -> str | None:
    """The DLQ correlation id for a revenue event: the idempotency_key when it is a
    well-formed string that fits the source_event_id column, else None (see the
    ``_DLQ_EVENT_ID_MAX_LENGTH`` note)."""
    if isinstance(idempotency_key, str) and len(idempotency_key) <= _DLQ_EVENT_ID_MAX_LENGTH:
        return idempotency_key
    return None


def build_revenue_record(payload: object):
    """Validate a raw X-005 payload into a ``RevenueRecord`` or raise PermanentIngestError.

    Mirrors ``build_usage_record``'s discipline exactly: best-effort attribution for the
    dead-letter row, a specific reason per permanent failure, and NO float anywhere in the
    money path (``amount_cents`` is validated as a true integer, never quantized).
    Returns ``delta.revenue.RevenueRecord``.
    """
    from ..revenue import RevenueEventType, RevenueRecord  # local import keeps the graph shallow

    if not isinstance(payload, dict):
        raise PermanentIngestError(
            DeadLetterReason.MALFORMED_PAYLOAD, "revenue payload is not a JSON object"
        )

    raw_event_type = payload.get("event_type")
    raw_tenant = payload.get("tenant_id")
    raw_idem = payload.get("idempotency_key")
    # Only attribute a tenant to the DLQ row when it is a well-formed tenant id, so the row
    # is tenant-visible under RLS; otherwise it is written tenant-NULL. The idempotency_key
    # doubles as the DLQ correlation id (mirrors usage's event_id), capped to fit the column.
    attr_tenant = raw_tenant if _is_valid_tenant(raw_tenant) else None
    attr_event_id = revenue_dlq_event_id(raw_idem)
    attr_event_type = raw_event_type if isinstance(raw_event_type, str) else None

    valid_event_types = {e.value for e in RevenueEventType}
    if raw_event_type not in valid_event_types:
        raise PermanentIngestError(
            DeadLetterReason.MALFORMED_PAYLOAD,
            f"unsupported revenue event_type {raw_event_type!r}",
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

    # amount_cents — contractually INTEGER minor units. Reject float/bool/str explicitly and
    # bound it here (INVALID_COST), never routing it through the float-accepting
    # Money.from_wire_cents. bool is an int subclass, so it is checked before the int check.
    if "amount_cents" not in payload:
        raise PermanentIngestError(
            DeadLetterReason.MALFORMED_PAYLOAD,
            "missing amount_cents",
            tenant_id=attr_tenant,
            event_id=attr_event_id,
            event_type=attr_event_type,
        )
    raw_amount = payload["amount_cents"]
    if isinstance(raw_amount, bool) or not isinstance(raw_amount, int):
        raise PermanentIngestError(
            DeadLetterReason.INVALID_COST,
            "amount_cents must be an integer (no float/bool); money is never a float in Delta",
            tenant_id=attr_tenant,
            event_id=attr_event_id,
            event_type=attr_event_type,
        )
    if raw_amount < 0 or raw_amount > MAX_MONEY_MINOR_UNITS:
        raise PermanentIngestError(
            DeadLetterReason.INVALID_COST,
            f"amount_cents out of range [0, {MAX_MONEY_MINOR_UNITS}]",
            tenant_id=attr_tenant,
            event_id=attr_event_id,
            event_type=attr_event_type,
        )

    raw_tier = payload.get("tier")
    if not isinstance(raw_tier, str) or not (1 <= len(raw_tier) <= 64):
        raise PermanentIngestError(
            DeadLetterReason.MALFORMED_PAYLOAD,
            "missing or invalid tier (a 1..64-char string is required)",
            tenant_id=attr_tenant,
            event_id=attr_event_id,
            event_type=attr_event_type,
        )

    if not isinstance(raw_idem, str) or not _REVENUE_IDEMPOTENCY_KEY_RE.match(raw_idem):
        raise PermanentIngestError(
            DeadLetterReason.MALFORMED_PAYLOAD,
            "missing or invalid idempotency_key (must match ^[A-Za-z0-9._:-]{1,128}$)",
            tenant_id=attr_tenant,
            event_id=attr_event_id,
            event_type=attr_event_type,
        )

    if "occurred_at" not in payload:
        raise PermanentIngestError(
            DeadLetterReason.MALFORMED_PAYLOAD,
            "missing occurred_at",
            tenant_id=attr_tenant,
            event_id=attr_event_id,
            event_type=attr_event_type,
        )

    # currency is OPTIONAL; the posting path applies DEFAULT_CURRENCY when omitted (same
    # convention as the usage path). A present-but-invalid currency fails schema validation.
    currency = payload.get("currency", DEFAULT_CURRENCY)

    try:
        record = RevenueRecord(
            tenant_id=raw_tenant,
            event_type=raw_event_type,
            tier=raw_tier,
            amount_cents=raw_amount,
            currency=currency,
            idempotency_key=raw_idem,
            occurred_at=payload.get("occurred_at"),
        )
    except ValidationError as exc:
        raise PermanentIngestError(
            DeadLetterReason.MALFORMED_PAYLOAD,
            "revenue event failed schema validation",
            tenant_id=attr_tenant,
            event_id=attr_event_id,
            event_type=attr_event_type,
        ) from exc
    return record


def revenue_idempotency_key(record) -> str:
    """Namespace the ledger idempotency key by source_product to avoid a cross-source
    collision in the ledger's ``(tenant_id, idempotency_key)`` partial-unique index:
    ``revenue:{source_product}:{key}``."""
    from ..revenue import REVENUE_SOURCE_PRODUCT

    return f"revenue:{REVENUE_SOURCE_PRODUCT}:{record.idempotency_key}"


def build_revenue_transaction(record, accounts: ResolvedRevenueAccounts) -> Transaction:
    """Map a validated ``subscription_granted`` record to a balanced two-leg transaction:

        DEBIT   <subscription_receivable ASSET>    amount_cents
        CREDIT  <subscription_revenue   REVENUE>   amount_cents      (nets to zero)

    Recognizes revenue: the debit increases the asset, the credit increases revenue. Ids are
    deterministic over (tenant, source_product, idempotency_key) so a replay names the same
    txn/entry ids (the ledger's namespaced idempotency key does the real dedup).
    """
    from ..revenue import REVENUE_SOURCE_PRODUCT

    amount = Money(minor_units=record.amount_cents, currency=record.currency)
    base = f"{record.tenant_id}:{REVENUE_SOURCE_PRODUCT}:{record.idempotency_key}"
    txn_id = str(uuid.uuid5(_REVENUE_POSTING_NAMESPACE, base))
    debit_id = str(uuid.uuid5(_REVENUE_POSTING_NAMESPACE, f"{base}:debit"))
    credit_id = str(uuid.uuid5(_REVENUE_POSTING_NAMESPACE, f"{base}:credit"))

    common = {
        "tenant_id": record.tenant_id,
        "amount": amount,
        "team_id": _REVENUE_UNATTRIBUTED_ID,
        "project_id": _REVENUE_UNATTRIBUTED_ID,
        "agent_id": REVENUE_SOURCE_PRODUCT,
        "timestamp": record.occurred_at,
    }
    debit = LedgerEntry(
        entry_id=debit_id,
        account_id=accounts.receivable_account_id,
        direction=EntryDirection.DEBIT,
        **common,
    )
    credit = LedgerEntry(
        entry_id=credit_id,
        account_id=accounts.revenue_account_id,
        direction=EntryDirection.CREDIT,
        **common,
    )
    return Transaction(
        txn_id=txn_id,
        tenant_id=record.tenant_id,
        entries=(debit, credit),
        timestamp=record.occurred_at,
        description=f"Rendly subscription revenue: {record.tier}",
    )


async def post_revenue(record) -> AppendResult:
    """Post a validated ``subscription_granted`` record as one balanced, idempotent txn.

    Opens ONE tenant session: ensures the two revenue accounts exist (no commit), builds the
    two-leg transaction, then ``append_transaction`` inserts + commits — so account-create +
    posting are atomic under the composite same-tenant FK. The ledger idempotency key is
    namespaced by source_product to avoid cross-source collision. Connectivity errors
    propagate (the caller classifies them transient -> 503).
    """
    async with get_tenant_session(record.tenant_id) as session:
        accounts = await ensure_revenue_accounts(session, record.tenant_id, record.currency)
        txn = build_revenue_transaction(record, accounts)
        return await append_transaction(
            session, txn, idempotency_key=revenue_idempotency_key(record)
        )
