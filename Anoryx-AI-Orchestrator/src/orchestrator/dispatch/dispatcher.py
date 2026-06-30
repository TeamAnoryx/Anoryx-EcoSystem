"""Single-pass forward_outbox -> Delta drain (D-004, ADR-0004 §3).

`dispatch_pending` selects up to ``limit`` 'pending' forward_outbox rows (oldest first),
joins each to its ingest_events row on the UNIQUE ``idempotency_key`` to recover the locked
payload + event_type, signs the serialized payload with the Orchestrator->Delta HMAC
(signer.py), POSTs it to Delta's inbound seam, and records the per-row outcome. It is a
DRAIN, not a daemon: one pass, then it returns a DispatchSummary; a scheduler (parent's
concern, O-004/O-005) decides when to call it again.

Session discipline (ADR-0026): this is an internal GLOBAL forwarder, not tenant request
traffic, so it runs on the privileged (owner / BYPASSRLS) session — forward_outbox is
FORCE ROW LEVEL SECURITY and the app role has no UPDATE grant, so only the owner can read
and transition rows across tenants. get_privileged_session() does NOT autobegin, so every
read/write opens its own explicit `async with session.begin()`. Each row is committed in
its OWN transaction so a mid-batch failure leaves earlier rows durably forwarded and one
poison row cannot roll back the whole batch (partial-batch safety).

Never logs the secret, the signature, or the payload body. last_error stores only a short,
non-sensitive marker (an HTTP status label or a transport exception class name).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

import httpx
from sqlalchemy import text

from orchestrator.dispatch import signer
from orchestrator.persistence.database import get_privileged_session

#: VARCHAR(500) ceiling on forward_outbox.last_error.
_MAX_ERROR_LEN = 500


@dataclass(frozen=True, slots=True)
class DispatchSummary:
    """Per-drain outcome counts. scanned == forwarded + failed + retried + skipped."""

    forwarded: int
    failed: int
    retried: int
    skipped: int
    scanned: int


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def dispatch_pending(
    delta_url: str,
    *,
    http_client: httpx.AsyncClient,
    limit: int = 100,
    max_attempts: int = 5,
) -> DispatchSummary:
    """Drain up to ``limit`` pending forward_outbox 'usage' rows to ``delta_url`` once.

    ``http_client`` is injected so tests can pass an ASGI-bound client to the real Delta
    app. Returns a DispatchSummary tallying the disposition of every scanned row.
    """
    forwarded = failed = retried = skipped = 0
    async with get_privileged_session() as session:
        rows = await _select_pending(session, limit=limit)
        scanned = len(rows)
        for row in rows:
            outcome = await _dispatch_row(
                session,
                row,
                delta_url=delta_url,
                http_client=http_client,
                max_attempts=max_attempts,
            )
            if outcome == "forwarded":
                forwarded += 1
            elif outcome == "failed":
                failed += 1
            elif outcome == "retried":
                retried += 1
            else:  # "skipped"
                skipped += 1
    return DispatchSummary(
        forwarded=forwarded,
        failed=failed,
        retried=retried,
        skipped=skipped,
        scanned=scanned,
    )


async def _select_pending(session, *, limit: int) -> list[dict]:
    """Read pending rows (oldest first) joined to their payload, in one read transaction.

    LEFT JOIN so a forward_outbox row with no matching ingest_events row still appears
    (it becomes a terminal 'skipped'). Results are materialized into plain dicts before the
    read transaction closes.
    """
    async with session.begin():
        result = await session.execute(
            text(
                "SELECT fo.id AS id, fo.idempotency_key AS idempotency_key, "
                "fo.attempt_count AS attempt_count, ie.event_type AS event_type, "
                "ie.payload AS payload "
                "FROM forward_outbox fo "
                "LEFT JOIN ingest_events ie ON ie.idempotency_key = fo.idempotency_key "
                "WHERE fo.status = 'pending' "
                "ORDER BY fo.created_at ASC, fo.id ASC "
                "LIMIT :limit"
            ),
            {"limit": limit},
        )
        return [dict(m) for m in result.mappings().all()]


async def _dispatch_row(
    session,
    row: dict,
    *,
    delta_url: str,
    http_client: httpx.AsyncClient,
    max_attempts: int,
) -> str:
    """Attempt one row's delivery; persist its new state in its own transaction.

    Returns one of: "forwarded", "failed", "retried", "skipped".
    """
    row_id = row["id"]
    event_type = row["event_type"]
    payload = row["payload"]
    current = int(row["attempt_count"])

    # This dispatcher forwards only usage events. A missing ingest_events row (LEFT JOIN
    # miss -> payload/event_type NULL) or any non-usage type is a terminal skip.
    if payload is None or event_type != "usage":
        await _apply(
            session,
            row_id,
            status="skipped",
            attempt_count=current,
            last_attempt_at=None,
            last_error=None,
        )
        return "skipped"

    # JSONB may surface as a str (raw asyncpg) or an already-decoded dict; normalize.
    if isinstance(payload, str):
        payload = json.loads(payload)

    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    attempt = current + 1
    headers = signer.sign(body, attempt=attempt)

    try:
        response = await http_client.post(delta_url, content=body, headers=headers)
    except (httpx.HTTPError, OSError, TimeoutError) as exc:
        # Transport-level failure (connect/read/timeout) — transient.
        return await _record_transient(
            session,
            row_id,
            attempt=attempt,
            max_attempts=max_attempts,
            short_error=type(exc).__name__,
        )

    code = response.status_code
    if 200 <= code < 300:
        # attempt_count records the number of FAILED attempts, not the attempt index that
        # succeeded: it is bumped only by _record_transient on a transient failure, so a
        # first-try success keeps it at `current` (0 = "succeeded with no prior failures").
        await _apply(
            session,
            row_id,
            status="forwarded",
            attempt_count=current,
            last_attempt_at=_now(),
            last_error=None,
        )
        return "forwarded"
    if 400 <= code < 500:
        # Delta dead-lettered it (permanent client-side rejection); do not retry.
        await _apply(
            session,
            row_id,
            status="failed",
            attempt_count=current,
            last_attempt_at=_now(),
            last_error=f"delta {code}",
        )
        return "failed"
    # 5xx (or any other non-2xx/4xx) — transient.
    return await _record_transient(
        session,
        row_id,
        attempt=attempt,
        max_attempts=max_attempts,
        short_error=f"delta {code}",
    )


async def _record_transient(
    session,
    row_id: str,
    *,
    attempt: int,
    max_attempts: int,
    short_error: str,
) -> str:
    """Record a transient failure: bump attempt_count; terminally fail once bounded.

    Bounded retry (vector 8): once attempt_count reaches max_attempts the row becomes
    'failed' and is never re-selected; otherwise it stays 'pending' for the next drain.
    """
    if attempt >= max_attempts:
        status, outcome = "failed", "failed"
    else:
        status, outcome = "pending", "retried"
    await _apply(
        session,
        row_id,
        status=status,
        attempt_count=attempt,
        last_attempt_at=_now(),
        last_error=short_error[:_MAX_ERROR_LEN],
    )
    return outcome


async def _apply(
    session,
    row_id: str,
    *,
    status: str,
    attempt_count: int,
    last_attempt_at: datetime | None,
    last_error: str | None,
) -> None:
    """Persist one row's post-attempt state in its own committed transaction.

    Optimistic-lock guard (``AND status = 'pending'``): a row is only transitioned while
    it is STILL 'pending'. Two overlapping drains can each select the same pending row;
    without this guard a slow drain could overwrite a row a faster drain already moved to
    'forwarded', resurrecting a delivered event as 'pending'/'failed'. The guard makes the
    UPDATE a no-op for any row another scheduler has already transitioned.
    """
    async with session.begin():
        await session.execute(
            text(
                "UPDATE forward_outbox SET status = :status, attempt_count = :attempt_count, "
                "last_attempt_at = :ts, last_error = :err "
                "WHERE id = :id AND status = 'pending'"
            ),
            {
                "status": status,
                "attempt_count": attempt_count,
                "ts": last_attempt_at,
                "err": last_error,
                "id": row_id,
            },
        )
