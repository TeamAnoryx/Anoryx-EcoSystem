"""X-004 — best-effort cross-product safety-event emission: Rendly -> Orchestrator ``/v1/safety/events``.

R-008 (``sentinel_inspector.py`` / ``detectors.py`` / ADR-0008) already inspects every chat
message and, on a non-pass outcome, blocks the send and records it locally in
``inspection_audit_log`` — that behavior is COMPLETE and UNCHANGED by this module. X-004 adds ONE
new thing on top: when the R-008 seam produces a genuine detector ``block`` (a real
``pii``/``injection``/``secret`` category firing, NOT the separate ``seam_unavailable`` outcome,
which has no category to report and is not part of the wire contract's ``outcome`` enum), this
module fires a best-effort, metadata-only notification to the Anoryx-AI-Orchestrator's
cross-product safety-event oversight log (``POST /v1/safety/events``,
``Anoryx-AI-Orchestrator/contracts/openapi.yaml`` ``SafetyEventIngestRequest`` / X-004) so an
operator watching the ecosystem-wide oversight log sees that Rendly blocked something, without
ever seeing WHAT was blocked.

DATA SOVEREIGNTY (ADR-0008 Fork A2, unchanged): detection itself still never leaves this process
— nothing here calls Sentinel's or any other product's detectors, and no message content is
constructed anywhere in this module. Only the closed, bounded, metadata-only fields the wire
contract defines are sent: ``tenant_id``, ``category``, ``outcome`` (always ``"block"`` — this
module never reports a ``"pass"``), ``target`` (the opaque ``channel_id``, never the message),
``idempotency_key``, ``occurred_at``.

FAIL-OPEN / BEST-EFFORT (mirrors Sentinel F-020's ADR-0023 Fork E / D5, "a delivery failure NEVER
touches the user's request path" — the pattern this module replicates in spirit, without pulling
in F-020's queue/worker/DLQ machinery, which Rendly has no infrastructure for and this bounded
slice does not need): ``emit_block_events_best_effort`` is a plain, SYNCHRONOUS function. It never
awaits network I/O itself — it schedules one ``asyncio.create_task`` per blocking category finding
and returns immediately, so calling it from the send pipeline adds no latency and cannot delay,
block, or fail the ``chat.ack`` the caller already fail-closed on. Each scheduled task has its own
bounded timeout and swallows every exception (network error, timeout, non-2xx response, Orchestrator
down, DNS failure, malformed response) — nothing it does can raise into the pipeline, and nothing
it does can change the local block/persist/ack decision, which has ALREADY been made by the time
this module is ever called.

CONFIGURATION / NO-OP DEFAULT (mirrors ``realtime/ice.py``'s env-unconfigured degrade — "nothing
configured -> ... never a hard failure"): both ``RENDLY_ORCHESTRATOR_SAFETY_URL`` (the
Orchestrator's base URL) and ``RENDLY_ORCHESTRATOR_SAFETY_TOKEN`` (the ``safetySourceBearer``
token the Orchestrator resolves to ``source_product: rendly``) must be set for this module to do
anything. Either missing (the default for any deployment that has not wired up Orchestrator
connectivity) -> ``emit_block_events_best_effort`` is a safe, silent no-op; no task is scheduled,
no exception is raised. This is a genuinely OPTIONAL oversight integration, never a dependency of
the send pipeline.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Iterable
from datetime import datetime

import httpx

from .inspector import DetectorFinding

logger = logging.getLogger(__name__)

# Env vars this module reads (mirrors realtime/ice.py's *_ENV constant convention).
ORCHESTRATOR_SAFETY_URL_ENV = "RENDLY_ORCHESTRATOR_SAFETY_URL"
ORCHESTRATOR_SAFETY_TOKEN_ENV = "RENDLY_ORCHESTRATOR_SAFETY_TOKEN"

_SAFETY_EVENTS_PATH = "/v1/safety/events"

# Bounded so a slow/unreachable Orchestrator can never meaningfully delay process shutdown or
# pile up unbounded in-flight requests; well under any caller-facing timeout since this is never
# awaited by the send pipeline in the first place.
_REQUEST_TIMEOUT_SECONDS = 3.0

# Fire-and-forget asyncio.create_task results MUST be referenced until they complete (a task with
# no live reference can be garbage-collected mid-flight — a well-known asyncio pitfall) — this
# module-level set is that reference. Self-cleaning via add_done_callback so it never grows
# unbounded.
_background_tasks: set[asyncio.Task] = set()


def _is_configured(base_url: str | None, token: str | None) -> bool:
    return bool(base_url) and bool(token)


def _build_payload(
    *, tenant_id: str, category: str, target: str, idempotency_key: str, occurred_at: datetime
) -> dict:
    """The exact ``SafetyEventIngestRequest`` shape (closed schema — no extra keys).

    ``occurred_at`` is rendered with an explicit UTC offset (``isoformat()`` on a tz-aware
    ``datetime`` always includes one), matching the contract's requirement. ``source_product`` is
    deliberately NOT included — the Orchestrator resolves it server-side from the authenticated
    bearer, and the contract states it "MUST NOT be supplied in the body."
    """
    return {
        "tenant_id": tenant_id,
        "category": category,
        "outcome": "block",
        "target": target,
        "idempotency_key": idempotency_key,
        "occurred_at": occurred_at.isoformat(),
    }


async def _post_event(payload: dict, *, base_url: str, token: str) -> None:
    """POST one event; swallow everything. Never raises, never retries (deferred — see ADR-0026:
    a lost oversight notification is acceptable, this is visibility, not enforcement)."""
    url = base_url.rstrip("/") + _SAFETY_EVENTS_PATH
    try:
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.post(
                url, json=payload, headers={"Authorization": f"Bearer {token}"}
            )
        if response.status_code != 202:
            # Not a category/content leak (nothing here reveals more than the request already
            # carried) — logged at most, never re-raised.
            logger.warning(
                "safety_event_emit_unexpected_status status=%s category=%s",
                response.status_code,
                payload.get("category"),
            )
    except Exception:  # noqa: BLE001 - best-effort, fail-open (mirrors ADR-0023 Fork E / D5):
        # a delivery failure here must NEVER surface to the caller — the send was already
        # fail-closed blocked/audited before this module was ever invoked.
        logger.warning(
            "safety_event_emit_failed category=%s",
            payload.get("category"),
            exc_info=True,
        )


def emit_block_events_best_effort(
    *,
    tenant_id: str,
    channel_id: str,
    audit_id: str,
    detectors: Iterable[DetectorFinding],
    occurred_at: datetime,
) -> None:
    """Schedule one best-effort oversight notification per BLOCKING detector category.

    Called from ``pipeline.py`` immediately after ``_record_inspection_audit`` on the
    ``outcome.status == "blocked"`` branch ONLY — never on ``seam_unavailable`` (no category to
    report) and never on ``pass`` (this seam reports non-pass outcomes only, matching the wire
    contract's v1 ``outcome`` enum, which accepts only ``"block"``).

    A single inspection can trip more than one category at once (all three detectors always run);
    the wire contract's ``SafetyEventIngestRequest`` carries exactly one category per event, so
    one event is scheduled per blocking finding. ``idempotency_key`` is derived from
    ``audit_id`` (the SAME id the caller just persisted as ``inspection_audit_log.audit_id``) plus
    the category, so it is stable and unique per (inspection-audit-row, category) and safe to
    retry on the Orchestrator side without creating a duplicate (``disposition: duplicate``).

    A completely SYNCHRONOUS function: it never awaits, so calling it adds zero latency to the
    caller and cannot itself raise (the only failure mode — no running event loop — is caught and
    logged, never propagated). No-op (schedules nothing) if the Orchestrator target is
    unconfigured.
    """
    base_url = os.environ.get(ORCHESTRATOR_SAFETY_URL_ENV)
    token = os.environ.get(ORCHESTRATOR_SAFETY_TOKEN_ENV)
    if not _is_configured(base_url, token):
        return  # unconfigured -> safe no-op (mirrors realtime/ice.py's degrade-not-block posture)
    assert base_url is not None and token is not None  # narrowed by _is_configured, for mypy/ruff

    for finding in detectors:
        if finding.outcome != "block":
            continue
        payload = _build_payload(
            tenant_id=tenant_id,
            category=finding.category,
            target=channel_id,
            idempotency_key=f"rendly-inspection-{audit_id}-{finding.category}",
            occurred_at=occurred_at,
        )
        coro = _post_event(payload, base_url=base_url, token=token)
        try:
            task = asyncio.create_task(coro)
        except RuntimeError:
            # No running event loop. Every real caller is inside an async WS frame handler, so
            # this is defensive only (e.g. a misuse from sync code) — never raise into the caller.
            # Explicitly close the never-scheduled coroutine so it doesn't trigger a "coroutine
            # was never awaited" RuntimeWarning (create_task evaluates the coroutine object
            # BEFORE it can fail to schedule it).
            coro.close()
            logger.warning("safety_event_emit_skipped_no_event_loop category=%s", finding.category)
            continue
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)
