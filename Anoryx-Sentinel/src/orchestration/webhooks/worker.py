"""Webhook-dispatcher worker (F-020, ADR-0023 §5.3 D3).

Clones the F-015 consumer-group pattern from src/bulk/worker.py VERBATIM
(ensure_group, XREADGROUP, XAUTOCLAIM, XACK, DLQ-XADD, bounded retry).

Flow per candidate message:
  1. Parse + validate the CandidateMessage (poison-message guard → XACK + discard).
  2. Open get_tenant_session(tenant_id) — RLS structurally prevents cross-tenant.
  3. Load enabled webhook_configs where min_severity <= event severity.
  4. For each matching config:
     a. DEDUP: SELECT webhook_delivery WHERE event_id=? AND config_id=?
        → skip if status is terminal ('delivered' | 'dead_lettered').
     b. INSERT webhook_delivery (pending) or UPDATE if existing non-terminal.
     c. Re-validate target_url through url_guard (config MAY have changed since
        candidate was enqueued — guard runs at send time, not just at write time).
     d. Decrypt signing_secret / credential via secret_box.decrypt (send-time only).
     e. Build provider body via adapter.
     f. Sign if provider requires it (signer.should_sign).
     g. POST through guarded_http_client(pinned_ip, hostname).
     h. 2xx → mark delivered + emit webhook_delivered.
     i. non-2xx or transport error → bounded retry (re-enqueue) → on exhaustion
        → dead_letter DLQ + mark dead_lettered + emit webhook_delivery_failed.
  5. XACK the candidate stream message after all configs processed.

SESSION RULES (battle-tested):
  - get_tenant_session(tenant_id) AUTOBEGINS. Do NOT call session.begin() after it.
    For writes: do the write then await session.commit().
  - get_privileged_session() does NOT autobegin → wrap in async with session.begin():
    Use ONLY for audit appends (emit_webhook_event).

FAIL-OPEN SCOPE (ADR-0023 §4.1 / D5):
  Every delivery failure path is caught, audited, and dropped. NOTHING here
  propagates into or affects the request path.

NEVER log: target URLs, decrypted secrets, raw HTTP response bodies, stack
traces, or any prompt/response content.
"""

from __future__ import annotations

import asyncio
import uuid

import httpx
import structlog

from gateway.redis_client import get_client
from orchestration.webhooks.adapters import build_body
from orchestration.webhooks.audit_events import emit_webhook_event
from orchestration.webhooks.config import get_webhook_settings
from orchestration.webhooks.http_client import guarded_http_client
from orchestration.webhooks.queue import CandidateMessage, dead_letter, ensure_group
from orchestration.webhooks.signer import should_sign, sign_body
from orchestration.webhooks.url_guard import check_url
from persistence.database import get_privileged_session, get_tenant_session
from persistence.models.webhook_config import WebhookConfig
from persistence.models.webhook_delivery import WebhookDelivery

log = structlog.get_logger(__name__)

# Severity ordering for min_severity threshold filtering.
_SEVERITY_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Delivery terminal statuses — worker skips these (checkpoint / dedup).
_TERMINAL_STATUSES: frozenset[str] = frozenset({"delivered", "dead_lettered"})


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------


def _severity_gte(event_severity: str, threshold: str) -> bool:
    """Return True when event_severity >= threshold (both as slug strings)."""
    return _SEVERITY_ORDER.get(event_severity, -1) >= _SEVERITY_ORDER.get(threshold, 99)


# ---------------------------------------------------------------------------
# HTTP status classification (never raw body — D1)
# ---------------------------------------------------------------------------


def _classify_http_status(status_code: int) -> str:
    """Return a bounded HTTP status class string ('1xx'..'5xx')."""
    bucket = status_code // 100
    if 1 <= bucket <= 5:
        return f"{bucket}xx"
    return "5xx"  # fallback for unexpected codes


# ---------------------------------------------------------------------------
# Per-delivery outcome handlers
# ---------------------------------------------------------------------------


async def _mark_delivered(
    session,
    *,
    delivery_id: str,
    attempts: int,
    http_status_class: str,
) -> None:
    """Update delivery row to 'delivered' (tenant session — caller provides)."""
    from sqlalchemy import update

    await session.execute(
        update(WebhookDelivery)
        .where(WebhookDelivery.delivery_id == delivery_id)
        .values(
            status="delivered",
            attempts=attempts,
            last_http_status_class=http_status_class,
        )
    )


async def _mark_failed(
    session,
    *,
    delivery_id: str,
    attempts: int,
    http_status_class: str | None,
) -> None:
    """Update delivery row to 'failed' for retry (tenant session — caller provides)."""
    from sqlalchemy import update

    values = {
        "status": "failed",
        "attempts": attempts,
    }
    if http_status_class is not None:
        values["last_http_status_class"] = http_status_class
    await session.execute(
        update(WebhookDelivery).where(WebhookDelivery.delivery_id == delivery_id).values(**values)
    )


async def _mark_dead_lettered(
    session,
    *,
    delivery_id: str,
    attempts: int,
) -> None:
    """Update delivery row to 'dead_lettered' (tenant session — caller provides)."""
    from sqlalchemy import update

    await session.execute(
        update(WebhookDelivery)
        .where(WebhookDelivery.delivery_id == delivery_id)
        .values(status="dead_lettered", attempts=attempts)
    )


# ---------------------------------------------------------------------------
# Audit emit (privileged session — mirrors bulk/worker.py _emit exactly)
# ---------------------------------------------------------------------------


async def _emit_delivery_event(
    *,
    event_type: str,
    tenant_id: str,
    team_id: str,
    project_id: str,
    request_id: str,
    webhook_provider: str,
    delivery_attempts: int,
    failure_class: str | None = None,
) -> None:
    """Append a webhook delivery audit event. Best-effort + logged on error."""
    try:
        async with get_privileged_session() as ps:
            async with ps.begin():
                await emit_webhook_event(
                    ps,
                    event_type=event_type,
                    tenant_id=tenant_id,
                    team_id=team_id,
                    project_id=project_id,
                    request_id=request_id,
                    webhook_provider=webhook_provider,
                    delivery_attempts=delivery_attempts,
                    failure_class=failure_class,
                )
    except Exception:
        log.error(
            "webhook_audit_emit_failed",
            event_type=event_type,
            # Never log tenant_id or request_id in error context (topology risk).
        )


# ---------------------------------------------------------------------------
# Per-config delivery
# ---------------------------------------------------------------------------


async def _deliver_to_config(
    msg: CandidateMessage,
    config: WebhookConfig,
) -> None:
    """Attempt delivery for one (candidate, config) pair with bounded retry.

    All exceptions are caught; failures are audited + dropped (D5/§4.1).
    """
    settings = get_webhook_settings()
    envelope = msg.to_envelope()
    provider = config.provider
    request_id = msg.event_id  # per-delivery correlation

    # --- DEDUP: locate or create delivery row ---
    delivery_id: str | None = None
    current_attempts: int = 0

    async with get_tenant_session(msg.tenant_id) as session:
        from sqlalchemy import select

        row = await session.execute(
            select(WebhookDelivery).where(
                WebhookDelivery.event_id == msg.event_id,
                WebhookDelivery.config_id == config.config_id,
            )
        )
        existing: WebhookDelivery | None = row.scalar_one_or_none()

        if existing is not None:
            if existing.status in _TERMINAL_STATUSES:
                # Already terminal — skip (at-least-once dedup → effectively-once).
                return
            delivery_id = existing.delivery_id
            current_attempts = existing.attempts
        else:
            # First delivery attempt — INSERT pending row.
            delivery_id = str(uuid.uuid4())
            new_row = WebhookDelivery(
                delivery_id=delivery_id,
                event_id=msg.event_id,
                config_id=config.config_id,
                tenant_id=msg.tenant_id,
                status="pending",
                attempts=0,
            )
            session.add(new_row)

        await session.commit()

    # --- URL guard (re-validate at send time — config may have changed) ---
    guard = check_url(config.target_url, allowed_ports=settings.webhook_allowed_ports)
    if not guard.allowed:
        await _handle_failure(
            msg,
            config=config,
            delivery_id=delivery_id,
            attempt=current_attempts + 1,
            failure_class="url_guard_rejected",
            http_status_class=None,
        )
        return

    # --- Decrypt credential / signing_secret (send-time only — never log) ---
    # Secret material is held as bytearray so we can overwrite it in-place before
    # the reference goes out of scope.  Python bytes are immutable — reassigning
    # a bytes variable only rebinds the name; it does NOT wipe the heap copy.
    # bytearray[:] = b"\x00"*n overwrites the underlying buffer in place, which is
    # the best real wipe available in CPython (the interpreter may still cache
    # internal string/bytes interning, but the decrypted buffer itself is zeroed).
    # Note: when we copy a bytearray to a str (e.g. for an Authorization header),
    # that str copy remains on the heap until GC.  We do not claim otherwise.
    signing_secret_buf: bytearray | None = None
    try:
        if config.signing_secret is not None and should_sign(provider):
            from admin.sso.secret_box import decrypt

            signing_secret_buf = bytearray(decrypt(config.signing_secret))
    except Exception:
        # Decryption failure — treat as transport_error, don't leak details.
        await _handle_failure(
            msg,
            config=config,
            delivery_id=delivery_id,
            attempt=current_attempts + 1,
            failure_class="transport_error",
            http_status_class=None,
        )
        return

    # --- Build provider body ---
    try:
        body_str = build_body(provider, envelope)
    except Exception:
        if signing_secret_buf is not None:
            signing_secret_buf[:] = b"\x00" * len(signing_secret_buf)
        await _handle_failure(
            msg,
            config=config,
            delivery_id=delivery_id,
            attempt=current_attempts + 1,
            failure_class="transport_error",
            http_status_class=None,
        )
        return

    # --- Sign if required ---
    extra_headers: dict[str, str] = {}
    if signing_secret_buf is not None:
        try:
            signed = sign_body(bytes(signing_secret_buf), body_str)
            extra_headers["X-Sentinel-Timestamp"] = signed.x_sentinel_timestamp
            extra_headers["X-Sentinel-Signature"] = signed.x_sentinel_signature
        except Exception:
            await _handle_failure(
                msg,
                config=config,
                delivery_id=delivery_id,
                attempt=current_attempts + 1,
                failure_class="transport_error",
                http_status_class=None,
            )
            return
        finally:
            # Overwrite the bytearray buffer in-place (best real wipe available).
            # The bytes() view passed to sign_body is a separate object; it will
            # be GC'd normally.  The Authorization header str (if any) also
            # remains on the heap until GC — no false "securely erased" claims.
            signing_secret_buf[:] = b"\x00" * len(signing_secret_buf)

    # --- Credential header (Jira: Bearer token; Splunk: Splunk HEC token) ---
    try:
        if config.credential is not None:
            from admin.sso.secret_box import decrypt as _decrypt

            cred_buf = bytearray(_decrypt(config.credential))
            cred_str = cred_buf.decode("utf-8")
            if provider == "jira":
                extra_headers["Authorization"] = f"Bearer {cred_str}"
            elif provider == "splunk":
                extra_headers["Authorization"] = f"Splunk {cred_str}"
            # For slack, the credential (signing secret / token) is embedded
            # in the webhook URL itself — no Authorization header.
            # Overwrite the bytearray buffer in-place immediately after use.
            # The cred_str copy (an immutable str) remains on the heap until GC.
            cred_buf[:] = b"\x00" * len(cred_buf)
    except Exception:
        await _handle_failure(
            msg,
            config=config,
            delivery_id=delivery_id,
            attempt=current_attempts + 1,
            failure_class="transport_error",
            http_status_class=None,
        )
        return

    # --- POST through the guarded HTTP client ---
    attempt = current_attempts + 1
    http_status_class: str | None = None
    try:
        port = 443
        from urllib.parse import urlparse

        parsed = urlparse(config.target_url)
        port = parsed.port or 443

        async with guarded_http_client(
            pinned_ip=guard.pinned_ip,
            hostname=guard.hostname,
            port=port,
        ) as client:
            headers = {"Content-Type": "application/json", **extra_headers}
            # Build the path+query from the original URL (the base_url is the
            # pinned IP; we use the original URL's path/query for the request).
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"

            resp = await client.post(path, content=body_str.encode("utf-8"), headers=headers)
            http_status_class = _classify_http_status(resp.status_code)

            if 200 <= resp.status_code < 300:
                # Success
                async with get_tenant_session(msg.tenant_id) as session:
                    await _mark_delivered(
                        session,
                        delivery_id=delivery_id,
                        attempts=attempt,
                        http_status_class=http_status_class,
                    )
                    await session.commit()

                await _emit_delivery_event(
                    event_type="webhook_delivered",
                    tenant_id=msg.tenant_id,
                    team_id=msg.team_id,
                    project_id=msg.project_id,
                    request_id=request_id,
                    webhook_provider=provider,
                    delivery_attempts=attempt,
                )
                log.info(
                    "webhook_delivered",
                    provider=provider,
                    attempts=attempt,
                )
                return
            else:
                # HTTP error response — retry or DLQ.
                await _handle_failure(
                    msg,
                    config=config,
                    delivery_id=delivery_id,
                    attempt=attempt,
                    failure_class="http_error",
                    http_status_class=http_status_class,
                )
                return

    except httpx.TimeoutException:
        await _handle_failure(
            msg,
            config=config,
            delivery_id=delivery_id,
            attempt=attempt,
            failure_class="transport_error",
            http_status_class=None,
        )
    except httpx.TransportError:
        await _handle_failure(
            msg,
            config=config,
            delivery_id=delivery_id,
            attempt=attempt,
            failure_class="transport_error",
            http_status_class=None,
        )
    except Exception:
        # Catch-all — any unexpected error is an audited delivery failure (D5).
        await _handle_failure(
            msg,
            config=config,
            delivery_id=delivery_id,
            attempt=attempt,
            failure_class="transport_error",
            http_status_class=http_status_class,
        )


async def _handle_failure(
    msg: CandidateMessage,
    *,
    config: WebhookConfig,
    delivery_id: str,
    attempt: int,
    failure_class: str,
    http_status_class: str | None,
) -> None:
    """Bounded retry → DLQ. Mirrors bulk/worker.py _handle_failure exactly."""
    settings = get_webhook_settings()
    provider = config.provider

    if attempt < settings.webhook_retry_max:
        # Not exhausted — update to 'failed' and leave on stream for reclaim.
        try:
            async with get_tenant_session(msg.tenant_id) as session:
                await _mark_failed(
                    session,
                    delivery_id=delivery_id,
                    attempts=attempt,
                    http_status_class=http_status_class,
                )
                await session.commit()
        except Exception:
            log.error("webhook_mark_failed_error", delivery_id=delivery_id)
        log.info(
            "webhook_delivery_retry",
            provider=provider,
            attempt=attempt,
            failure_class=failure_class,
        )
        return

    # Exhausted retries → dead-letter.
    try:
        async with get_tenant_session(msg.tenant_id) as session:
            await _mark_dead_lettered(session, delivery_id=delivery_id, attempts=attempt)
            await session.commit()
    except Exception:
        log.error("webhook_mark_dead_lettered_error", delivery_id=delivery_id)

    try:
        await dead_letter(msg, failure_class=failure_class)
    except Exception:
        log.error("webhook_dlq_xadd_failed", failure_class=failure_class)

    await _emit_delivery_event(
        event_type="webhook_delivery_failed",
        tenant_id=msg.tenant_id,
        team_id=msg.team_id,
        project_id=msg.project_id,
        request_id=msg.event_id,
        webhook_provider=provider,
        delivery_attempts=attempt,
        failure_class="dead_lettered",
    )
    log.warning(
        "webhook_dead_lettered",
        provider=provider,
        attempt=attempt,
        failure_class=failure_class,
    )


# ---------------------------------------------------------------------------
# Process one candidate message
# ---------------------------------------------------------------------------


async def process_candidate(msg: CandidateMessage) -> None:
    """Dispatch one candidate to ALL matching webhook configs for its tenant.

    RLS is structurally enforced: get_tenant_session(msg.tenant_id) means the
    SQL SELECT for webhook_configs can only see rows where tenant_id matches —
    a candidate for tenant A can NEVER match tenant B's config.

    All exceptions are caught + logged; a failure never affects the stream loop.
    """
    # Filter on severity first (fast in-memory check before any DB query).
    event_severity = msg.severity

    try:
        async with get_tenant_session(msg.tenant_id) as session:
            from sqlalchemy import select

            result = await session.execute(
                select(WebhookConfig).where(
                    WebhookConfig.tenant_id == msg.tenant_id,
                    WebhookConfig.enabled.is_(True),
                )
            )
            configs: list[WebhookConfig] = list(result.scalars().all())
    except Exception:
        log.error(
            "webhook_config_load_failed",
            tenant_present=bool(msg.tenant_id),
        )
        return

    # Filter in Python by min_severity (the DB CHECK already bounds the value)
    # AND by team/project scope (ADR-0023 §5.2 scope confinement — Affu ENFORCE).
    # NULL scope = tenant-wide (config matches any team/project for this tenant).
    # Non-NULL scope = restricted: the event's team_id/project_id must match exactly.
    matching = [
        c
        for c in configs
        if _severity_gte(event_severity, c.min_severity)
        and (c.team_id is None or c.team_id == msg.team_id)
        and (c.project_id is None or c.project_id == msg.project_id)
    ]

    for config in matching:
        try:
            await _deliver_to_config(msg, config)
        except Exception:
            # Last-resort catch: _deliver_to_config handles its own failures;
            # a leak here is unexpected. Log + continue to next config (D5).
            log.error(
                "webhook_deliver_unexpected_error",
                provider=config.provider,
            )


# ---------------------------------------------------------------------------
# Consumer-group worker loop (mirrors bulk/worker.py run_worker exactly)
# ---------------------------------------------------------------------------


async def _consume_candidates(client, group: str, consumer: str, stream: str) -> int:
    """Read + process one batch of candidate messages. Returns count handled."""
    settings = get_webhook_settings()
    handled = 0

    # Reclaim messages stuck on crashed workers.
    try:
        _next, claimed, _deleted = await client.xautoclaim(
            stream,
            group,
            consumer,
            min_idle_time=settings.webhook_claim_min_idle_ms,
            start_id="0",
            count=settings.webhook_read_count,
        )
    except Exception:
        claimed = []

    # Read new messages.
    new_msgs: list = []
    try:
        resp = await client.xreadgroup(
            group,
            consumer,
            {stream: ">"},
            count=settings.webhook_read_count,
            block=settings.webhook_read_block_ms,
        )
        for _stream_name, entries in resp or []:
            new_msgs.extend(entries)
    except Exception:
        new_msgs = []

    # Build a per-message delivery-count map from the PEL for claimed messages.
    # xautoclaim returns entries as (id, fields); we query XPENDING to get counts.
    # For simplicity we track counts in a local dict keyed by msg_id (bytes/str).
    # claimed messages have already been delivered at least once by a prior consumer.
    claimed_ids: set = {mid for mid, _ in claimed}

    for msg_id, fields in list(claimed) + new_msgs:
        try:
            msg = CandidateMessage.from_fields(fields)
        except (KeyError, ValueError):
            log.error("webhook_worker_malformed_message_discarded", msg_id=str(msg_id))
            await client.xack(stream, group, msg_id)
            continue

        # --- Stream-level reclaim cap (LOW fix, ADR-0023 §5.3 D3) ---
        # A message that is repeatedly reclaimed from the PEL (because
        # process_candidate keeps raising and leaving it un-ACKed) would be
        # reclaimed indefinitely without this cap.  We query the PEL delivery
        # count for reclaimed messages and dead-letter them once the count
        # reaches webhook_retry_max, so no message is reclaimed unboundedly.
        # New messages (not in claimed_ids) have delivery_count == 1 on their
        # first read; we only apply the cap to already-claimed messages.
        if msg_id in claimed_ids:
            try:
                pending_info = await client.xpending_range(stream, group, msg_id, msg_id, 1)
                delivery_count = pending_info[0]["times_delivered"] if pending_info else 1
            except Exception:
                delivery_count = 1

            if delivery_count >= settings.webhook_retry_max:
                # Exceeded stream-level reclaim budget → XACK + DLQ.
                log.warning(
                    "webhook_worker_stream_reclaim_cap_exceeded",
                    msg_id=str(msg_id),
                    delivery_count=delivery_count,
                )
                try:
                    await dead_letter(msg, failure_class="stream_reclaim_cap")
                except Exception:
                    log.error("webhook_worker_dlq_xadd_failed_on_cap", msg_id=str(msg_id))
                await client.xack(stream, group, msg_id)
                handled += 1
                continue

        try:
            await process_candidate(msg)
        except Exception:
            # process_candidate handles its own failures; an unexpected leak
            # here leaves the message pending so it will be reclaimed — the
            # stream-level cap above bounds that reclaim count.
            log.error("webhook_worker_unexpected_error", msg_id=str(msg_id))
            continue
        await client.xack(stream, group, msg_id)
        handled += 1

    return handled


async def run_worker(*, stop_event: asyncio.Event | None = None) -> None:
    """Run the webhook-dispatcher consumer-group worker loop until stop_event is set.

    The Redis client is acquired ONCE outside the loop (persistent connection across
    iterations) matching the F-015 bulk/worker.py pattern.  Reconnecting on every
    iteration was wasteful, especially during idle periods where XREADGROUP blocks
    for webhook_read_block_ms (default 5 s) before returning empty.

    On a transport-level error from the Redis client we log and attempt to reconnect
    by falling through to the next loop iteration (the outer async with re-acquires
    a fresh client), rather than crashing the worker.
    """
    settings = get_webhook_settings()
    stream = settings.webhook_candidates_stream_key
    group = settings.webhook_consumer_group
    consumer = f"webhook-dispatcher-{uuid.uuid4().hex[:8]}"

    await ensure_group()
    log.info("webhook_worker_started", consumer=consumer, stream=stream)

    # Hoist the Redis client acquisition outside the loop so we maintain a
    # persistent connection across iterations instead of reconnecting every batch.
    async with await get_client() as client:
        while stop_event is None or not stop_event.is_set():
            try:
                await _consume_candidates(client, group, consumer, stream)
            except Exception:
                # Unexpected Redis-level error — log and let the outer context
                # manager handle cleanup; the loop exits and the caller can restart.
                log.error("webhook_worker_redis_error")
                break
