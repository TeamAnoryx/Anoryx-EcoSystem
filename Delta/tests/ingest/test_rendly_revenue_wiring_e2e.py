"""X-005 — Rendly <-> Delta monetization wiring validated (ADR-0021, non-stubbed).

Both halves of X-005 were built independently against the SAME Delta contract
(``Delta/contracts/delta-financial.schema.json``'s ``RevenueIngestRecord`` /
``POST /v1/ingest/revenue``): Rendly's ``monetization_emitter.py`` (its own non-stubbed
test, ``Rendly/tests/domain/test_monetization_emitter.py``, proves the real emitter maps a
real ``PremiumEntitlement`` to a schema-shaped wire dict and HMAC-signs it, against an
in-process ``httpx.MockTransport`` standing in for Delta — which Rendly cannot reach in that
suite) and Delta's ``ingest/router.py`` + ``ingest/posting.py`` (its own non-stubbed test,
``Delta/tests/ingest/test_revenue_db.py``, proves real HMAC verify / posting / idempotency /
RLS isolation from a HAND-BUILT, schema-valid revenue dict). Neither proves the two are
actually wire-compatible with EACH OTHER.

This file closes that gap for X-005, mirroring X-004's
``Anoryx-AI-Orchestrator/tests/integration/test_rendly_wiring_e2e.py`` exactly: it drives
Rendly's REAL domain objects and REAL emitter payload builder in-process -- a real
``Profile`` -> real ``bind_premium_entitlement`` -> real ``build_subscription_event`` (the
exact PURE function ``emit_subscription_event`` calls in production to build the wire body
before the fire-and-forget POST) -- to obtain a genuine production-shaped
``RevenueIngestRecord`` dict WITHOUT hand-constructing the payload, then serializes it,
HMAC-signs it with the shared per-source revenue secret, and POSTs it into Delta's REAL
``POST /v1/ingest/revenue`` on the REAL ASGI app against REAL Postgres. Assertions read the
committed ledger back through a delta_app (RLS) session, so the exact double-entry posting
model (DEBIT receivable ASSET / CREDIT revenue REVENUE), integer-cents, idempotency, and
tenant scoping are observed at the database -- not asserted from the HTTP response alone.
``rendly`` is installed editable alongside Delta in the CI ``ledger-db`` lane's venv (see
``.github/workflows/delta-ci.yml``'s ``pip install -e "../Rendly[dev]"`` line).

Scope boundary (honesty, ADR-0021): this proves the REVENUE-EVENT SHAPE + HMAC-AUTH TRANSPORT
are compatible end-to-end -- that a payload Rendly's own ``build_subscription_event`` genuinely
produces from a real premium grant is accepted, persisted as a balanced revenue-recognition
transaction, and correctly deduplicated by Delta's real app. It does NOT re-drive Rendly's own
fire-and-forget ``emit_subscription_event`` async delivery / env-gating / exception-swallowing
path (``Rendly/tests/domain/test_monetization_emitter.py`` already proves that in-product) or
Delta's own posting internals beyond confirming the round trip
(``Delta/tests/ingest/test_revenue_db.py`` already proves reversal-absence, DLQ, and the
usage-secret rejection in depth). Rendly's fail-open, no-op-when-unconfigured delivery posture
(ADR-0028 Fork E) is unaffected: this test calls the PURE ``build_subscription_event`` directly,
exactly as X-004 imported Rendly's pure ``_build_payload``.

Skipped as a module when the Delta DB env is absent so the pure-unit modules still run.
Requires DATABASE_URL + APP_DATABASE_URL (+ DELTA_PROVISION_APP_ROLE on an ephemeral DB).
"""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

pytestmark = pytest.mark.skipif(
    not os.environ.get("APP_DATABASE_URL"),
    reason="Delta DB (APP_DATABASE_URL / DATABASE_URL) not configured",
)

# The PREMIUM static placeholder list price the real Rendly emitter stamps (its own
# _TIER_PRICE_CENTS[PremiumTier.PREMIUM]); asserted at the ledger, not hard-typed into the body.
_PREMIUM_PRICE_CENTS = 1499


def _asyncpg(url: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", url)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


def _body(event: dict) -> bytes:
    """Serialize the event ONCE; the SAME bytes are signed and transmitted (so a byte-identical
    replay reproduces the exact request Delta dedups on)."""
    return json.dumps(event).encode("utf-8")


async def _post(client, sign_revenue, event: dict):
    body = _body(event)
    return await client.post("/v1/ingest/revenue", content=body, headers=sign_revenue(body))


def _real_rendly_revenue_payload(
    *,
    tier,
    event_type: str,
    tenant_id: str,
    occurred_at: datetime,
) -> dict | None:
    """Return the GENUINE ``RevenueIngestRecord`` dict Rendly's real emitter produces -- nothing
    below is hand-typed.

    Builds a REAL Rendly ``Profile`` for *tenant_id*, binds a REAL ``PremiumEntitlement`` via
    Rendly's REAL ``bind_premium_entitlement`` at *tier*, then feeds it through Rendly's REAL
    PURE ``build_subscription_event`` -- the exact function ``emit_subscription_event`` calls in
    production to build the wire body. Returns the dict (or ``None`` for a FREE-tier grant, which
    the real emitter refuses to bill).
    """
    from rendly.enums import OrgRole
    from rendly.monetization_emitter import build_subscription_event
    from rendly.premium import bind_premium_entitlement
    from rendly.profile import Profile

    # A real Profile (extra=forbid, frozen). user_id/tenant_id are well-formed Rendly UUIDs;
    # tenant_id is shared with the Delta assertion below so RLS scopes the readback to it.
    profile = Profile(
        user_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        org_role=OrgRole.MEMBER,
    )
    entitlement = bind_premium_entitlement(profile, tier=tier, granted_at=occurred_at)
    return build_subscription_event(entitlement, event_type=event_type, occurred_at=occurred_at)


async def _revenue_entries(tenant_id: str) -> list[dict]:
    """Every ledger entry for ``tenant_id`` joined to its account type (delta_app / RLS)."""
    engine = create_async_engine(_asyncpg(os.environ["APP_DATABASE_URL"]), poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            await conn.execute(
                text("SELECT set_config('app.current_tenant_id', :t, true)"), {"t": tenant_id}
            )
            rows = (
                (
                    await conn.execute(
                        text(
                            "SELECT le.direction, le.amount_minor_units, a.type AS account_type "
                            "FROM delta.ledger_entries le "
                            "JOIN delta.accounts a ON a.account_id = le.account_id "
                            "ORDER BY le.direction"
                        )
                    )
                )
                .mappings()
                .all()
            )
            return [dict(r) for r in rows]
    finally:
        await engine.dispose()


async def _txn_count(tenant_id: str) -> int:
    engine = create_async_engine(_asyncpg(os.environ["APP_DATABASE_URL"]), poolclass=NullPool)
    try:
        async with engine.connect() as conn:
            await conn.execute(
                text("SELECT set_config('app.current_tenant_id', :t, true)"), {"t": tenant_id}
            )
            return int(
                (await conn.execute(text("SELECT count(*) FROM delta.transactions"))).scalar_one()
            )
    finally:
        await engine.dispose()


# --------------------------------------------------------------------------- happy path + replay
async def test_real_rendly_premium_grant_posts_balanced_revenue_and_is_idempotent(
    client, sign_revenue
):
    """A genuinely Rendly-produced ``subscription_granted`` event (real Profile -> real
    entitlement -> real ``build_subscription_event``) is accepted by Delta's real app, posts
    EXACTLY one balanced revenue-recognition transaction (DEBIT receivable ASSET / CREDIT revenue
    REVENUE, both == the PREMIUM price), and a byte-identical replay dedups -- no second row."""
    from rendly.premium import PremiumTier

    tenant_id = str(uuid.uuid4())
    occurred_at = datetime(2026, 7, 11, 12, 0, 0, tzinfo=timezone.utc)
    payload = _real_rendly_revenue_payload(
        tier=PremiumTier.PREMIUM,
        event_type="subscription_granted",
        tenant_id=tenant_id,
        occurred_at=occurred_at,
    )
    assert payload is not None, "a PREMIUM grant must produce a billable revenue event"
    # The whole point: this dict is Rendly's real output, and it honors the contract boundaries
    # (source_product server-resolved, currency Delta-defaulted) WITHOUT us hand-typing it.
    assert "source_product" not in payload
    assert "currency" not in payload
    assert payload["amount_cents"] == _PREMIUM_PRICE_CENTS
    assert payload["tier"] == "premium"

    resp = await _post(client, sign_revenue, payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["status"] == "accepted"
    assert data["applied"] is True
    assert data["idempotent_replay"] is False
    assert isinstance(data["txn_id"], str)

    entries = await _revenue_entries(tenant_id)
    assert len(entries) == 2
    by_dir = {e["direction"]: e for e in entries}
    # EXACTLY: DEBIT the receivable ASSET, CREDIT the revenue REVENUE account.
    assert by_dir["debit"]["account_type"] == "asset"
    assert by_dir["credit"]["account_type"] == "revenue"
    # Integer cents == the PREMIUM price, balanced (debit == credit), no float leak.
    assert by_dir["debit"]["amount_minor_units"] == _PREMIUM_PRICE_CENTS
    assert by_dir["credit"]["amount_minor_units"] == _PREMIUM_PRICE_CENTS
    assert by_dir["debit"]["amount_minor_units"] == by_dir["credit"]["amount_minor_units"]
    assert type(by_dir["debit"]["amount_minor_units"]) is int  # noqa: E721
    assert await _txn_count(tenant_id) == 1

    # Idempotency: re-POST the byte-identical signed request (Rendly's deterministic uuid5 key
    # makes a retry reproduce the same idempotency_key) -> accepted, but applied=False and
    # idempotent_replay=True, and NO new ledger entries (still exactly two, still one txn).
    replay = await _post(client, sign_revenue, payload)
    assert replay.status_code == 200, replay.text
    replay_data = replay.json()
    assert replay_data["applied"] is False
    assert replay_data["idempotent_replay"] is True
    assert len(await _revenue_entries(tenant_id)) == 2
    assert await _txn_count(tenant_id) == 1


# --------------------------------------------------------------------------- FREE tier boundary
async def test_free_tier_entitlement_produces_no_event_so_nothing_is_billed(client, sign_revenue):
    """A real FREE-tier ``PremiumEntitlement`` -> ``build_subscription_event`` returns ``None`` ->
    there is NO payload to POST. This documents the "FREE bills nothing" boundary at the wiring
    level: the emitter would send nothing, and the ledger stays empty for that tenant."""
    from rendly.premium import PremiumTier

    tenant_id = str(uuid.uuid4())
    occurred_at = datetime(2026, 7, 11, 12, 0, 0, tzinfo=timezone.utc)
    payload = _real_rendly_revenue_payload(
        tier=PremiumTier.FREE,
        event_type="subscription_granted",
        tenant_id=tenant_id,
        occurred_at=occurred_at,
    )
    # Rendly's real emitter refuses to bill a free grant -> no wire dict at all.
    assert payload is None
    # Nothing was POSTed, so the tenant's ledger is empty (the honest representation of
    # "not billable" -- ADR-0028 Fork D rejected emitting a $0 event).
    assert await _revenue_entries(tenant_id) == []
    assert await _txn_count(tenant_id) == 0


# --------------------------------------------------------------------------- revoke (v1 no-op)
async def test_real_rendly_subscription_revoked_accepts_but_posts_nothing(client, sign_revenue):
    """A genuinely Rendly-produced ``subscription_revoked`` event (real entitlement -> real
    ``build_subscription_event``) is durably accepted (200, applied=False) but posts NOTHING:
    v1 records a revoke without reversing the granting transaction (ADR-0021 / ADR-0028's
    deferred no-reversal boundary)."""
    from rendly.premium import PremiumTier

    tenant_id = str(uuid.uuid4())
    occurred_at = datetime(2026, 7, 11, 12, 0, 0, tzinfo=timezone.utc)
    payload = _real_rendly_revenue_payload(
        tier=PremiumTier.PREMIUM,
        event_type="subscription_revoked",
        tenant_id=tenant_id,
        occurred_at=occurred_at,
    )
    assert payload is not None
    assert payload["event_type"] == "subscription_revoked"

    resp = await _post(client, sign_revenue, payload)
    assert resp.status_code == 200, resp.text
    assert resp.json() == {
        "status": "accepted",
        "applied": False,
        "idempotent_replay": False,
        "txn_id": None,
    }
    # v1 revoke is a durable-accept no-op: NO ledger entries, NO transaction.
    assert await _revenue_entries(tenant_id) == []
    assert await _txn_count(tenant_id) == 0
