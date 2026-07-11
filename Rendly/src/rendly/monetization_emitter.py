"""X-005 (Rendly side) — best-effort forwarding of a REAL premium grant/revocation to
Delta's revenue ledger: Rendly -> Delta ``POST /v1/ingest/revenue``.

R-025 (``premium.py`` / ADR-0025) shipped the pure-domain, fail-CLOSED feature-GATE half of
"Premium features + monetization (B2C, via Delta)": ``PremiumTier``, a revocable
``PremiumEntitlement`` grant, and ``has_feature_access``. Its ADR EXPLICITLY deferred real money
movement to X-005 (THIS module): "Real money movement for a Rendly subscription is its own,
separate, still-unshipped cross-product task (X-005)." X-005 adds exactly ONE thing on the Rendly
side: the EMITTER that maps a real ``PremiumEntitlement`` -> Delta's ``RevenueIngestRecord`` wire
shape and forwards it, best-effort, to Delta's revenue-ingest endpoint so a grant (or revocation)
lands as a monetization event in Delta's ledger.

WHAT THIS MODULE IS NOT (named, not silently implied away — see ADR-0028):
  * NOT a payment processor / checkout / billing-lifecycle flow (no Stripe, no invoice, no
    renewal/dunning/proration). Nothing here collects money; it forwards a grant that has ALREADY
    been decided elsewhere. Real payment collection remains deferred, exactly as R-025 left it.
  * NOT persistence for ``PremiumEntitlement`` or for the emitted events. There is no grant/revoke
    table, no delivery ledger, no outbox. A caller supplies the entitlement each time (mirroring
    R-025's own no-persistence discipline).
  * NOT a REST/wire surface of Rendly's own. ``contracts/openapi.yaml`` is unchanged.

The Delta contract this conforms to (``Delta/contracts/delta-financial.schema.json`` ->
``RevenueIngestRecord``; READ-only reference, a different subproject this builder never edits):
``tenant_id``, ``event_type`` (``subscription_granted``|``subscription_revoked``), ``tier`` (the
opaque Rendly tier name), ``amount_cents`` (INTEGER minor units, never a float), an optional
``currency`` (OMITTED here so Delta applies its own default), ``idempotency_key``, ``occurred_at``
(ISO-8601 with an explicit UTC offset). ``source_product`` is deliberately NOT in the body — Delta
resolves it from the authenticated HMAC key, exactly as X-004's Orchestrator seam resolves
``source_product`` from its bearer.

AUTH (Delta's existing inbound-ingest convention, replicated exactly): a shared-secret HMAC-SHA256
signature over the literal bytes ``f"{timestamp}.{body}"`` (``sha256=`` hex prefix, a unix-seconds
timestamp, a ±300s replay window Delta enforces), sent as ``X-Orchestrator-Signature`` /
``X-Orchestrator-Timestamp``. This module signs the EXACT body bytes it POSTs, so Delta's verify
(over the raw received body) matches regardless of key ordering.

FAIL-OPEN / BEST-EFFORT (mirrors X-004's ``safety_event_emitter`` and, in spirit, Sentinel
F-020 / ADR-0023 Fork E's "a delivery failure NEVER touches the request path"): a delivery failure
(Delta down, network partition, timeout, non-2xx) is swallowed and logged, never raised, never
retried. ADR-0028 is honest that this makes a LOST revenue event possible and names guaranteed/
reliable delivery (an outbox/retry/DLQ) as DEFERRED — this seam is monetization WIRING, not the
system of record (Delta's ledger is), and it is idempotent on retry via a deterministic key, so a
future reliable-delivery layer can be added without changing this module's payload shape.

CONFIGURATION / NO-OP DEFAULT (mirrors ``realtime/ice.py`` and X-004's env-unconfigured degrade):
both ``RENDLY_DELTA_REVENUE_INGEST_URL`` (Delta's base URL) and
``RENDLY_DELTA_REVENUE_HMAC_SECRET`` (Rendly's own copy of the shared per-source revenue-ingest
secret) must be set for this module to emit anything. Either missing -> a safe, silent no-op; no
request, no exception. This is the correct default for every deployment that has not wired up
Delta connectivity.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from datetime import datetime
from typing import Literal

import httpx

from .common import require_aware_utc
from .premium import PremiumEntitlement, PremiumTier

logger = logging.getLogger(__name__)

# Env vars this module reads (mirrors safety_event_emitter's *_ENV constant convention).
REVENUE_INGEST_URL_ENV = "RENDLY_DELTA_REVENUE_INGEST_URL"
REVENUE_HMAC_SECRET_ENV = "RENDLY_DELTA_REVENUE_HMAC_SECRET"

_REVENUE_INGEST_PATH = "/v1/ingest/revenue"

# Bounded so a slow/unreachable Delta can never meaningfully delay the caller (this is awaited, so
# unlike X-004's fire-and-forget scheduler it DOES sit in the caller's coroutine — the timeout is
# the cap on how long a lost-delivery best-effort attempt can cost).
_REQUEST_TIMEOUT_SECONDS = 3.0

# The two Delta monetization event classes (RevenueEventType in the Delta contract). v1 posts a
# ledger transaction for `subscription_granted` ONLY; `subscription_revoked` is accepted and
# durably recorded by Delta but does NOT reverse the granting transaction in v1 (Delta's documented
# v1 behavior — see ADR-0028). Rendly emits both; Delta decides what to post.
RevenueEventType = Literal["subscription_granted", "subscription_revoked"]

# STATIC PLACEHOLDER per-tier list price, in INTEGER CENTS. This is NOT a dynamically-fetched price,
# NOT a plan-catalog lookup, and NOT a per-tenant negotiated rate — dynamic pricing / a plan catalog
# is explicitly OUT OF SCOPE for X-005 (see ADR-0028). It is a single hard-coded monthly list price
# so the emitter can name an amount at all; a real pricing source is a later task's job.
# `PremiumTier.FREE` deliberately has NO entry: a free entitlement is not a monetization event
# (there is nothing to bill), so `build_subscription_event` returns None for it.
_TIER_PRICE_CENTS: dict[PremiumTier, int] = {
    PremiumTier.PREMIUM: 1499,  # $14.99/mo — a static placeholder list price, not a live rate.
}

# A fixed namespace for the deterministic uuid5 idempotency key (a random-but-constant UUID; its
# only job is to scope the uuid5 hash to this seam). Never rotate it — rotating it would change
# every derived key and break Delta-side dedup of already-emitted events.
_IDEMPOTENCY_NAMESPACE = uuid.UUID("6f2a9c1e-4b73-5d84-9e10-2c7f8a3b1d05")
_IDEMPOTENCY_PREFIX = "rendly-sub-"


def _is_configured(base_url: str | None, secret: str | None) -> bool:
    return bool(base_url) and bool(secret)


def _idempotency_key(entitlement: PremiumEntitlement, event_type: RevenueEventType) -> str:
    """A DETERMINISTIC, stable dedup key per (entitlement identity + event_type).

    Derived by uuid5 over ``tenant_id : user_id : tier : granted_at : event_type`` — so a RETRY of
    the same grant (same entitlement, same event_type) reproduces the exact same key and Delta
    dedups it as an idempotent replay (never a second ledger transaction), while a different
    event_type (grant vs revoke) or a different tier yields a different key. ``granted_at`` (not
    ``occurred_at``) anchors the key to the GRANT's identity, so re-emitting the same grant at a
    different wall-clock ``occurred_at`` still dedups.

    The result — ``rendly-sub-`` + a dashed uuid5 hex — satisfies Delta's
    ``^[A-Za-z0-9._:-]{1,128}$`` pattern and is well under 128 chars.
    """
    composite = ":".join(
        (
            entitlement.tenant_id,
            entitlement.user_id,
            entitlement.tier.value,
            entitlement.granted_at.isoformat(),
            event_type,
        )
    )
    return _IDEMPOTENCY_PREFIX + str(uuid.uuid5(_IDEMPOTENCY_NAMESPACE, composite))


def build_subscription_event(
    entitlement: PremiumEntitlement,
    *,
    event_type: RevenueEventType,
    occurred_at: datetime,
) -> dict | None:
    """Map a real ``PremiumEntitlement`` -> a schema-valid ``RevenueIngestRecord`` dict.

    Returns ``None`` for a ``PremiumTier.FREE`` entitlement — a free grant is not a monetization
    event, so there is nothing to send. For a priced tier, returns the closed
    ``RevenueIngestRecord`` shape (no extra keys, and ``currency`` deliberately OMITTED so Delta
    applies its default; ``source_product`` deliberately ABSENT — Delta resolves it from the
    authenticated HMAC key).

    ``occurred_at`` MUST be timezone-aware UTC (mirrors ``premium.py``'s ``require_aware_utc``
    discipline): a naive datetime would serialize without the explicit UTC offset the Delta
    contract requires, so it is rejected here rather than sent malformed. ``amount_cents`` is an
    INTEGER from the static price map — never a float (this is Delta; money is integer minor units).
    """
    require_aware_utc(occurred_at, "occurred_at")
    amount_cents = _TIER_PRICE_CENTS.get(entitlement.tier)
    if amount_cents is None:
        # FREE tier (or any future unpriced tier): nothing billable -> no revenue event.
        return None
    return {
        "tenant_id": entitlement.tenant_id,
        "event_type": event_type,
        "tier": entitlement.tier.value,
        "amount_cents": amount_cents,
        "idempotency_key": _idempotency_key(entitlement, event_type),
        "occurred_at": occurred_at.isoformat(),
    }


async def _post_event(payload: dict, *, base_url: str, secret: str) -> None:
    """POST one revenue event, HMAC-signed; swallow everything. Never raises, never retries.

    Signs the EXACT body bytes it sends (``content=body``), so Delta's HMAC verify over the raw
    received body matches. The signature timestamp is the wall-clock send time (unix seconds) so it
    falls inside Delta's ±300s replay window when the request arrives.
    """
    url = base_url.rstrip("/") + _REVENUE_INGEST_PATH
    body = json.dumps(payload, separators=(",", ":"))
    timestamp = str(int(time.time()))
    digest = hmac.new(
        secret.encode("utf-8"), f"{timestamp}.{body}".encode("utf-8"), hashlib.sha256
    ).hexdigest()
    headers = {
        "Content-Type": "application/json",
        "X-Orchestrator-Signature": f"sha256={digest}",
        "X-Orchestrator-Timestamp": timestamp,
    }
    try:
        async with httpx.AsyncClient(timeout=_REQUEST_TIMEOUT_SECONDS) as client:
            response = await client.post(url, content=body, headers=headers)
        # Delta's revenue ingest answers 200 (synchronous accept/idempotent-replay), NOT 202 — but
        # any 2xx is treated as delivered; anything else is logged, never raised.
        if not (200 <= response.status_code < 300):
            logger.warning(
                "revenue_event_emit_unexpected_status status=%s event_type=%s",
                response.status_code,
                payload.get("event_type"),
            )
    except Exception:  # noqa: BLE001 - best-effort, fail-open (mirrors X-004 / ADR-0023 Fork E):
        # a delivery failure here must NEVER surface to the caller. See ADR-0028's honesty boundary:
        # a lost revenue event is an accepted risk at this wiring seam (Delta's ledger, not this
        # emitter, is the system of record), traded for not coupling a grant to Delta's uptime.
        logger.warning(
            "revenue_event_emit_failed event_type=%s",
            payload.get("event_type"),
            exc_info=True,
        )


async def emit_subscription_event(
    entitlement: PremiumEntitlement,
    *,
    event_type: RevenueEventType,
    occurred_at: datetime,
) -> None:
    """Best-effort, FAIL-OPEN forward of a real premium grant/revocation to Delta's ledger.

    No-op (sends nothing, raises nothing) when EITHER env var is unset (Delta connectivity not
    wired up — the default today) or when ``build_subscription_event`` returns ``None`` (a FREE-tier
    entitlement, nothing billable). Otherwise HMAC-signs and POSTs, swallowing every transport /
    non-2xx outcome (see ``_post_event``).

    ``occurred_at`` must be timezone-aware UTC — a naive datetime is a caller programming error and
    is rejected by ``build_subscription_event`` (this fail-open promise covers DELIVERY, not
    malformed inputs, exactly as ``premium.py`` rejects a naive timestamp rather than coercing it).
    """
    base_url = os.environ.get(REVENUE_INGEST_URL_ENV)
    secret = os.environ.get(REVENUE_HMAC_SECRET_ENV)
    if not _is_configured(base_url, secret):
        return  # unconfigured -> safe no-op (mirrors realtime/ice.py's degrade-not-block posture)
    assert base_url is not None and secret is not None  # narrowed by _is_configured, for mypy/ruff

    payload = build_subscription_event(entitlement, event_type=event_type, occurred_at=occurred_at)
    if payload is None:
        return  # FREE tier -> nothing to bill, nothing to emit.

    await _post_event(payload, base_url=base_url, secret=secret)
