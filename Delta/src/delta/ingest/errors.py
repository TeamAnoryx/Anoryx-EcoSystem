"""Ingest error taxonomy + transient/permanent classification (ADR-0004 Fork 5).

A financial event that cannot be posted is dead-lettered (permanent) or retried
(transient) — never silently dropped, never crash-looped. The split decides the
HTTP status the inbound endpoint returns, which in turn decides whether the
Orchestrator dispatcher retries the row or marks it failed:

  * PERMANENT  -> dead-letter the event, return 4xx (dispatcher marks `failed`).
  * TRANSIENT  -> return 503, no dead-letter (dispatcher retries, bounded).

Connectivity classification follows Sentinel ADR-0026 / the F-007-FU lesson: a DOWN
database surfaces as ``OSError`` (``ConnectionRefusedError``) or
``sqlalchemy.exc.TimeoutError``, not only ``OperationalError``/``InterfaceError`` —
so the transient set MUST include all of them, or a down DB is misclassified as a
permanent failure and a recoverable event is wrongly dead-lettered.
"""

from __future__ import annotations

import asyncio
from enum import StrEnum

from sqlalchemy.exc import InterfaceError, OperationalError
from sqlalchemy.exc import TimeoutError as SATimeoutError


class DeadLetterReason(StrEnum):
    """The closed set of dead-letter reasons (must match migration 0002's CHECK).

    Delta's DLQ holds only events it RECEIVED and could not post. Dispatcher
    retry-exhaustion is NOT a Delta DLQ reason: that is audited by the Orchestrator
    ``forward_outbox`` 'failed' row, so there is deliberately no ``max_attempts_exceeded``
    member here.
    """

    UNKNOWN_TENANT = "unknown_tenant"
    INVALID_COST = "invalid_cost"
    UNRESOLVABLE_ACCOUNT = "unresolvable_account"
    MALFORMED_PAYLOAD = "malformed_payload"


class PermanentIngestError(Exception):
    """A non-retryable failure: the event is dead-lettered, the endpoint returns 4xx.

    Carries the best-effort attribution available at failure time so the dead-letter
    row is auditable even when the event was too malformed to fully parse.
    """

    def __init__(
        self,
        reason: DeadLetterReason,
        message: str,
        *,
        tenant_id: str | None = None,
        event_id: str | None = None,
        event_type: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.tenant_id = tenant_id
        self.event_id = event_id
        self.event_type = event_type


# Connectivity / resource errors that mean "try again later", not "this event is bad".
_TRANSIENT_TYPES: tuple[type[BaseException], ...] = (
    OperationalError,
    InterfaceError,
    SATimeoutError,
    asyncio.TimeoutError,
    TimeoutError,
    ConnectionError,
    OSError,  # a down DB raises ConnectionRefusedError (an OSError subclass)
)


def is_transient(exc: BaseException) -> bool:
    """True if ``exc`` (or a wrapped cause) is a transient connectivity/resource error.

    SQLAlchemy wraps the driver exception; we check the exception and its ``__cause__``
    chain so a driver ``OSError`` wrapped in a SQLAlchemy error is still caught.
    """
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen:
        if isinstance(cur, _TRANSIENT_TYPES):
            return True
        seen.add(id(cur))
        cur = cur.__cause__ or cur.__context__
    return False
