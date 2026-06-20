"""Compliance Evidence Engine — read-only evidence generation (F-011, ADR-0013 §3 D2).

Produces an immutable EvidenceProjection over a caller-supplied time window by
issuing a single aggregate read against events_audit_log through the RLS-scoped
sentinel_app session.  ZERO writes are issued anywhere in this module — proven
by a connection-level before-execute listener in the threat-model test suite
(vector 1).

Mandatory framing: "audit-ready" throughout.  Never "compliant".
Every artifact carries: "Certification requires an accredited auditor."
"""

from __future__ import annotations

import types
from dataclasses import dataclass
from datetime import datetime
from typing import Mapping

from sqlalchemy import DateTime, cast, func, select

from compliance.errors import EvidenceWindowError
from compliance.mapping import FrameworkMap
from persistence.database import get_tenant_session
from persistence.models.events_audit_log import EventsAuditLog

# event_timestamp is a String(64) RFC3339-UTC column. Production audit writers
# ALWAYS emit the 'Z' form (e.g. '2026-01-15T12:00:00Z'); a lexicographic string
# compare against a '+00:00'-form bound (datetime.isoformat()) silently drops 'Z'
# rows at the boundary ('Z'=0x5A sorts after '+'=0x2B). Compare on a timestamptz
# CAST instead so the window filter is a true instant comparison, format-agnostic
# (precedent: src/policy/enforcement.py). Security audit F-011 M-1.
_EVENT_TS = cast(EventsAuditLog.event_timestamp, DateTime(timezone=True))

# ---------------------------------------------------------------------------
# Immutable result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChainLink:
    """A single row's hash-chain fields, embedded in an evidence pack (Layer A).

    Contains ONLY the three opaque hash/seq fields — no event payload,
    no PII, no prompt content (R6).  Used by pack.py to embed the
    window's chain segment for offline verifiability (ADR-0013 §6 D5).
    """

    sequence_number: int
    prev_hash: str
    row_hash: str


@dataclass(frozen=True)
class ChainTip:
    """The hash-chain tip visible to this tenant at the evidence window boundary.

    sequence_number: the highest sequence_number row with event_timestamp < t1.
    row_hash: the SHA-256 chain hash of that row (for offline verifiability).
    """

    sequence_number: int
    row_hash: str


@dataclass(frozen=True)
class EvidenceProjection:
    """Immutable snapshot of compliance evidence for a framework over [t0, t1).

    Mandatory disclaimer applies to every instance:
    "Automated evidence for audit preparation.
     Certification requires an accredited auditor."

    Fields
    ------
    framework:
        Framework identifier, e.g. "SOC2" or "ISO27001".
    framework_version:
        Pinned framework revision string from the mapping YAML.
    t0, t1:
        Half-open window [t0, t1): t0 is inclusive, t1 is exclusive.
    event_counts:
        Read-only mapping of event_type -> count within [t0, t1), restricted
        to event types that appear in the framework's evidence_event_types
        union.  Implemented as MappingProxyType so it cannot be mutated.
    total_events_in_window:
        Sum of all values in event_counts.
    chain_tip:
        The highest-sequence_number row visible to this tenant with
        event_timestamp < t1, or None if no rows exist in the window.
    """

    framework: str
    framework_version: str
    t0: datetime
    t1: datetime
    event_counts: Mapping[str, int]
    total_events_in_window: int
    chain_tip: ChainTip | None


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def validate_window(t0: datetime, t1: datetime) -> None:
    """Raise EvidenceWindowError when the window is empty or reversed."""
    if t0 >= t1:
        raise EvidenceWindowError(
            f"Evidence window is empty or reversed: t0={t0.isoformat()!r} must be "
            f"strictly before t1={t1.isoformat()!r}.  Supply a valid half-open "
            f"interval [t0, t1) with t0 < t1."
        )


def _collect_evidence_event_types(framework_map: FrameworkMap) -> frozenset[str]:
    """Return the union of all evidence_event_types across framework controls."""
    result: set[str] = set()
    for control in framework_map.controls:
        result.update(control.evidence_event_types)
    return frozenset(result)


# ---------------------------------------------------------------------------
# DB read helpers  (each < 50 lines; pure reads, zero writes)
# ---------------------------------------------------------------------------


async def _query_counts(
    session,  # AsyncSession
    evidence_types: frozenset[str],
    t0: datetime,
    t1: datetime,
) -> dict[str, int]:
    """Aggregate event_type counts within [t0, t1) for the mapped event types.

    Issues a single GROUP BY query.  event_types not in evidence_types are
    excluded from the result.  The RLS predicate on the session ensures only
    the caller's tenant rows are visible — no application-layer filter is needed
    or added (D1 / ADR-0013 §2).
    """
    if not evidence_types:
        return {}

    stmt = (
        select(EventsAuditLog.event_type, func.count().label("cnt"))
        .where(
            _EVENT_TS >= t0,
            _EVENT_TS < t1,
            EventsAuditLog.event_type.in_(evidence_types),
        )
        .group_by(EventsAuditLog.event_type)
    )
    result = await session.execute(stmt)
    return {row.event_type: row.cnt for row in result}


async def _query_chain_tip(
    session,  # AsyncSession
    t1: datetime,
) -> ChainTip | None:
    """Return the chain tip row visible to this tenant with event_timestamp < t1.

    Selects sequence_number + row_hash for the MAX(sequence_number) row whose
    event_timestamp is strictly less than t1.  Returns None if no rows exist.
    The RLS predicate ensures tenant-scoping at the DB layer (D1).
    """
    stmt = (
        select(EventsAuditLog.sequence_number, EventsAuditLog.row_hash)
        .where(_EVENT_TS < t1)
        .order_by(EventsAuditLog.sequence_number.desc())
        .limit(1)
    )
    result = await session.execute(stmt)
    row = result.one_or_none()
    if row is None:
        return None
    return ChainTip(sequence_number=row.sequence_number, row_hash=row.row_hash)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def generate_evidence(
    framework_map: FrameworkMap,
    t0: datetime,
    t1: datetime,
    *,
    tenant_id: str,
) -> EvidenceProjection:
    """Generate an audit-ready evidence projection for *framework_map* over [t0, t1).

    Reads events_audit_log through the RLS-scoped sentinel_app session
    (get_tenant_session).  Issues ZERO writes — the generation path is
    a pure read (ADR-0013 §3 D2, R1).  Tenant isolation is enforced at
    the DB layer via the RLS policy; no application-layer WHERE tenant_id
    filter is required or added.

    Parameters
    ----------
    framework_map:
        Loaded and validated FrameworkMap (from compliance.mapping.load_framework).
    t0:
        Window start (inclusive, datetime).
    t1:
        Window end (exclusive, datetime).  Half-open [t0, t1).
    tenant_id:
        Server-resolved tenant identifier.  Must be non-empty.
        get_tenant_session() is fail-closed and raises TenantContextRequiredError
        on empty/whitespace input before a DB connection is opened.

    Returns
    -------
    EvidenceProjection
        Immutable evidence snapshot.  event_counts is a MappingProxyType.

    Raises
    ------
    EvidenceWindowError
        If t0 >= t1 (empty or reversed window).
    TenantContextRequiredError
        If tenant_id is empty or whitespace (propagated from get_tenant_session).
    """
    validate_window(t0, t1)

    evidence_types = _collect_evidence_event_types(framework_map)

    async with get_tenant_session(tenant_id) as session:
        counts = await _query_counts(session, evidence_types, t0, t1)
        chain_tip = await _query_chain_tip(session, t1)

    # Ensure all mapped event types appear in the counts dict (zero-fill missing).
    full_counts: dict[str, int] = {et: counts.get(et, 0) for et in evidence_types}

    return EvidenceProjection(
        framework=framework_map.framework,
        framework_version=framework_map.framework_version,
        t0=t0,
        t1=t1,
        event_counts=types.MappingProxyType(full_counts),
        total_events_in_window=sum(full_counts.values()),
        chain_tip=chain_tip,
    )


async def read_chain_segment(
    t0: datetime,
    t1: datetime,
    *,
    tenant_id: str,
) -> tuple[ChainLink, ...]:
    """Return the tenant's own chain links for the window [t0, t1).

    Reads ONLY (sequence_number, prev_hash, row_hash) — no payload columns,
    no PII, no prompt content (R6).  Issues ZERO writes (R1).  Runs under the
    sentinel_app RLS role with GUC = tenant_id so only the caller's own rows
    are returned — cross-tenant leakage is structurally impossible at the DB
    layer (D1 / ADR-0013 §2).

    Where the caller's RLS policy removes other tenants' rows, the returned
    sequence_numbers will be non-contiguous.  The offline chain-linkage check
    in pack.py only asserts consecutive returned links; cross-tenant gaps are
    an honest limitation documented in verify_chain_links_offline.

    Parameters
    ----------
    t0:
        Window start (inclusive).
    t1:
        Window end (exclusive).
    tenant_id:
        Server-resolved tenant identifier.

    Returns
    -------
    tuple[ChainLink, ...]
        Ordered by sequence_number ascending.  Empty when no rows exist in [t0, t1).

    Raises
    ------
    EvidenceWindowError
        If t0 >= t1 (empty or reversed window).
    TenantContextRequiredError
        Propagated from get_tenant_session when tenant_id is empty.
    """
    validate_window(t0, t1)

    stmt = (
        select(
            EventsAuditLog.sequence_number,
            EventsAuditLog.prev_hash,
            EventsAuditLog.row_hash,
        )
        .where(
            _EVENT_TS >= t0,
            _EVENT_TS < t1,
        )
        .order_by(EventsAuditLog.sequence_number.asc())
    )

    async with get_tenant_session(tenant_id) as session:
        result = await session.execute(stmt)
        rows = result.all()

    return tuple(
        ChainLink(
            sequence_number=row.sequence_number,
            prev_hash=row.prev_hash,
            row_hash=row.row_hash,
        )
        for row in rows
    )
