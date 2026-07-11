"""Subscription registry + anomaly-report orchestration (D-022, ADR-0021).

DTO <-> store mapping + the vendor existence check the DB's FK constraint enforces
structurally at the tenant level but that still needs a friendly 404. Mirrors
``erp.service``: store functions never commit, this layer commits once per mutating
call. Subscription create/cancel and every recorded charge are wired into D-009's
hash-chained audit log (``delta.persistence.audit_log.append_history``) in the SAME
transaction as the store write — a recorded charge is a genuine financial event.

Anomaly detection reuses D-012's ``chargeback.anomaly.detect_anomalies`` UNMODIFIED
(ADR-0021 Fork 1/2) — see that function's own module docstring for the trailing-
average-ratio method itself; this module's job is only to shape a per-subscription
baseline into the inputs that pure function expects.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from ..chargeback.anomaly import detect_anomalies
from ..money import DEFAULT_CURRENCY
from ..persistence.audit_log import append_history
from . import store
from .schemas import (
    ChargeRecordRequest,
    ChargeView,
    SubscriptionAnomalyQuery,
    SubscriptionAnomalyReportView,
    SubscriptionAnomalyRow,
    SubscriptionCancelRequest,
    SubscriptionCreateRequest,
    SubscriptionView,
)

# Generous cap on how many active subscriptions one anomaly report evaluates in a
# single request (mirrors D-012's `_MAX_GROUPS = 100`) — bounds the report to a fixed
# number of subscriptions regardless of how many a tenant has registered.
_MAX_SUBSCRIPTIONS = 100


class VendorNotFoundError(LookupError):
    pass


class SubscriptionNotFoundError(LookupError):
    pass


class SubscriptionAlreadyCancelledError(RuntimeError):
    """A cancel was attempted on a subscription that is no longer 'active'."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _subscription_to_view(record: store.SubscriptionRecord) -> SubscriptionView:
    return SubscriptionView(
        subscription_id=record.subscription_id,
        tenant_id=record.tenant_id,
        vendor_id=record.vendor_id,
        name=record.name,
        expected_amount_minor_units=record.expected_amount_minor_units,
        currency=record.currency,
        cadence=record.cadence,  # type: ignore[arg-type]
        status=record.status,  # type: ignore[arg-type]
        created_by=record.created_by,
        created_at=record.created_at,
        updated_at=record.updated_at,
        cancelled_at=record.cancelled_at,
    )


def _charge_to_view(record: store.ChargeRecord) -> ChargeView:
    return ChargeView(
        charge_id=record.charge_id,
        tenant_id=record.tenant_id,
        subscription_id=record.subscription_id,
        amount_minor_units=record.amount_minor_units,
        currency=record.currency,
        charged_at=record.charged_at,
        recorded_by=record.recorded_by,
        note=record.note,
        created_at=record.created_at,
    )


# ------------------------------------------------------------------------ subscriptions


async def create_subscription(
    session: AsyncSession, req: SubscriptionCreateRequest
) -> SubscriptionView:
    if req.vendor_id is not None:
        status = await store.get_vendor_status(session, vendor_id=req.vendor_id)
        if status is None:
            raise VendorNotFoundError(req.vendor_id)
    # A subscription with an expected amount always carries a currency, and vice
    # versa — same pairing discipline as D-014's asset cost/currency fix, applied
    # here from the start (also backed by a DB CHECK, migration 0014).
    currency = (
        (req.currency or DEFAULT_CURRENCY) if req.expected_amount_minor_units is not None else None
    )
    now = _now()
    record = await store.create_subscription(
        session,
        tenant_id=req.tenant_id,
        vendor_id=req.vendor_id,
        name=req.name,
        expected_amount_minor_units=req.expected_amount_minor_units,
        currency=currency,
        cadence=req.cadence,
        created_by=req.created_by,
        now=now,
    )
    await append_history(
        session,
        tenant_id=req.tenant_id,
        entity_type="subscription",
        entity_id=record.subscription_id,
        action="created",
        actor=req.created_by,
        now=now,
    )
    await session.commit()
    return _subscription_to_view(record)


async def list_subscription_views(
    session: AsyncSession, *, status: str | None, limit: int
) -> list[SubscriptionView]:
    records = await store.list_subscriptions(session, status=status, limit=limit)
    return [_subscription_to_view(r) for r in records]


async def cancel_subscription(
    session: AsyncSession, *, subscription_id: str, req: SubscriptionCancelRequest
) -> SubscriptionView:
    existing = await store.get_subscription(session, subscription_id=subscription_id)
    if existing is None:
        raise SubscriptionNotFoundError(subscription_id)
    now = _now()
    cancelled = await store.try_cancel_subscription(
        session, subscription_id=subscription_id, actor=req.actor, now=now
    )
    if not cancelled:
        raise SubscriptionAlreadyCancelledError(subscription_id)
    await append_history(
        session,
        tenant_id=req.tenant_id,
        entity_type="subscription",
        entity_id=subscription_id,
        action="cancelled",
        actor=req.actor,
        now=now,
    )
    record = await store.get_subscription(session, subscription_id=subscription_id)
    await session.commit()
    if record is None:
        raise SubscriptionNotFoundError(subscription_id)  # unreachable: just wrote it
    return _subscription_to_view(record)


# ------------------------------------------------------------------------------ charges


async def record_charge(
    session: AsyncSession, *, subscription_id: str, req: ChargeRecordRequest
) -> ChargeView:
    existing = await store.get_subscription(session, subscription_id=subscription_id)
    if existing is None:
        raise SubscriptionNotFoundError(subscription_id)
    now = _now()
    record = await store.create_charge(
        session,
        tenant_id=req.tenant_id,
        subscription_id=subscription_id,
        amount_minor_units=req.amount_minor_units,
        currency=req.currency,
        charged_at=req.charged_at,
        recorded_by=req.recorded_by,
        note=req.note,
        now=now,
    )
    await append_history(
        session,
        tenant_id=req.tenant_id,
        entity_type="subscription_charge",
        entity_id=record.charge_id,
        action="recorded",
        actor=req.recorded_by,
        now=now,
        note=req.note,
    )
    await session.commit()
    return _charge_to_view(record)


async def list_charge_views(
    session: AsyncSession, *, subscription_id: str, limit: int
) -> list[ChargeView]:
    records = await store.list_charges(session, subscription_id=subscription_id, limit=limit)
    return [_charge_to_view(r) for r in records]


# ----------------------------------------------------------------------------- anomalies


async def get_anomaly_report(
    session: AsyncSession, query: SubscriptionAnomalyQuery
) -> SubscriptionAnomalyReportView:
    active = await store.list_subscriptions(session, status="active", limit=_MAX_SUBSCRIPTIONS)
    names_by_id = {s.subscription_id: s.name for s in active}

    charges_by_sub = await store.list_recent_charges_by_subscription(
        session,
        subscription_ids=list(names_by_id.keys()),
        window_size=query.baseline_window,
    )

    # Each subscription's baseline is "however many of ITS OWN prior charges exist,"
    # not a shared calendar window like D-012's — so the per-subscription average is
    # precomputed here in Python, then handed to `detect_anomalies` with
    # `baseline_periods=1` (dividing an already-computed average by 1 leaves it
    # unchanged; this is what lets one shared call to that unmodified pure function
    # evaluate every subscription's own, differently-sized baseline in one pass — see
    # ADR-0021 Fork 2).
    current_by_group: dict[str, int] = {}
    baseline_total_by_group: dict[str, float] = {}
    for subscription_id, charges in charges_by_sub.items():
        if not charges:
            continue
        current_by_group[subscription_id] = charges[0].amount_minor_units
        priors = charges[1:]
        if priors:
            baseline_total_by_group[subscription_id] = sum(
                c.amount_minor_units for c in priors
            ) / len(priors)

    results = detect_anomalies(
        current_by_group=current_by_group,
        baseline_total_by_group=baseline_total_by_group,
        baseline_periods=1,
    )

    return SubscriptionAnomalyReportView(
        baseline_window=query.baseline_window,
        anomalies=[
            SubscriptionAnomalyRow(
                subscription_id=r.group_key,
                subscription_name=names_by_id.get(r.group_key, r.group_key),
                current_charge_cents=r.current_spend_cents,
                baseline_avg_cents=r.baseline_avg_cents,
                ratio=r.ratio,
                code=r.code,
                severity=r.severity,
            )
            for r in results
        ],
    )
