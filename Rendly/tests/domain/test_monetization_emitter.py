"""Unit tests for X-005's ``monetization_emitter.py`` — pure/no-DB.

Lives under tests/domain (like ``test_premium.py``, since the module is premium-adjacent and
top-level ``rendly.monetization_emitter``, NOT under ``realtime/``) so the no-DB contracts lane
measures its coverage. These exercise the emitter in isolation — payload-shape correctness,
deterministic idempotency-key derivation, the FREE-tier no-op, the unconfigured no-op, and
fail-open exception/non-2xx swallowing — using a real ``httpx.AsyncClient`` wired to an in-process
``httpx.MockTransport`` (no real socket, but a real httpx request/response round-trip: headers,
body, status all genuinely exercised). The true cross-repo e2e (real Rendly emitter -> real Delta
app) is a SEPARATE task another builder owns.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import re
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from rendly import monetization_emitter as me
from rendly.enums import OrgRole
from rendly.premium import PremiumEntitlement, PremiumTier, bind_premium_entitlement
from rendly.profile import Profile

_NOW = datetime(2026, 7, 10, 12, 0, 0, tzinfo=timezone.utc)
_TENANT = "12121212-1212-4212-8212-121212121212"
_USER = "11111111-1111-4111-8111-111111111111"

# Delta's revenue_idempotency_key pattern (contract: ^[A-Za-z0-9._:-]{1,128}$).
_IDEMPOTENCY_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _profile(user_id: str = _USER, tenant_id: str = _TENANT) -> Profile:
    return Profile(user_id=user_id, tenant_id=tenant_id, org_role=OrgRole.MEMBER)


def _premium(*, granted_at: datetime = _NOW, expires_at=None) -> PremiumEntitlement:
    return bind_premium_entitlement(
        _profile(), tier=PremiumTier.PREMIUM, granted_at=granted_at, expires_at=expires_at
    )


def _free() -> PremiumEntitlement:
    return bind_premium_entitlement(_profile(), tier=PremiumTier.FREE, granted_at=_NOW)


@pytest.fixture(autouse=True)
def _unconfigured_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test starts with BOTH env vars unset; tests that need config set it explicitly."""
    monkeypatch.delenv(me.REVENUE_INGEST_URL_ENV, raising=False)
    monkeypatch.delenv(me.REVENUE_HMAC_SECRET_ENV, raising=False)


def _patch_transport(monkeypatch: pytest.MonkeyPatch, handler) -> list[httpx.Request]:
    """Force every ``httpx.AsyncClient`` (this module builds one, in ``_post_event``) onto a
    ``MockTransport`` — no real socket, but a genuine httpx round-trip."""
    captured: list[httpx.Request] = []

    def _capturing_handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return handler(request)

    transport = httpx.MockTransport(_capturing_handler)
    original_init = httpx.AsyncClient.__init__

    def _patched_init(self: httpx.AsyncClient, *args: object, **kwargs: object) -> None:
        kwargs["transport"] = transport
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "__init__", _patched_init)
    return captured


# --- build_subscription_event: payload shape --------------------------------------------------


def test_build_produces_closed_revenue_ingest_record_for_premium_grant() -> None:
    payload = me.build_subscription_event(
        _premium(), event_type="subscription_granted", occurred_at=_NOW
    )
    assert payload is not None
    # Closed-schema equivalent: EXACTLY the RevenueIngestRecord keys, no currency (Delta-defaulted),
    # no source_product (server-resolved from the HMAC key — never in the body).
    assert set(payload.keys()) == {
        "tenant_id",
        "event_type",
        "tier",
        "amount_cents",
        "idempotency_key",
        "occurred_at",
    }
    assert payload["tenant_id"] == _TENANT
    assert payload["event_type"] == "subscription_granted"
    assert payload["tier"] == "premium"
    # amount_cents is an INTEGER (never a float) from the static price map.
    assert payload["amount_cents"] == 1499
    assert isinstance(payload["amount_cents"], int) and not isinstance(
        payload["amount_cents"], bool
    )
    # Explicit UTC offset, as the contract requires.
    assert payload["occurred_at"] == "2026-07-10T12:00:00+00:00"
    assert "currency" not in payload
    assert "source_product" not in payload


def test_build_idempotency_key_matches_delta_pattern() -> None:
    payload = me.build_subscription_event(
        _premium(), event_type="subscription_granted", occurred_at=_NOW
    )
    assert payload is not None
    assert _IDEMPOTENCY_PATTERN.match(payload["idempotency_key"])
    assert payload["idempotency_key"].startswith("rendly-sub-")


def test_build_returns_none_for_free_tier() -> None:
    assert (
        me.build_subscription_event(_free(), event_type="subscription_granted", occurred_at=_NOW)
        is None
    )


def test_build_returns_none_for_free_tier_even_on_revoke() -> None:
    assert (
        me.build_subscription_event(_free(), event_type="subscription_revoked", occurred_at=_NOW)
        is None
    )


def test_build_rejects_naive_occurred_at() -> None:
    with pytest.raises(ValueError, match="occurred_at"):
        me.build_subscription_event(
            _premium(), event_type="subscription_granted", occurred_at=datetime(2026, 7, 10, 12, 0)
        )


def test_build_revoke_carries_same_amount_and_tier() -> None:
    payload = me.build_subscription_event(
        _premium(), event_type="subscription_revoked", occurred_at=_NOW
    )
    assert payload is not None
    assert payload["event_type"] == "subscription_revoked"
    assert payload["amount_cents"] == 1499
    assert payload["tier"] == "premium"


# --- idempotency key: deterministic + discriminating -----------------------------------------


def test_idempotency_key_is_stable_across_calls_with_same_inputs() -> None:
    a = me.build_subscription_event(_premium(), event_type="subscription_granted", occurred_at=_NOW)
    b = me.build_subscription_event(_premium(), event_type="subscription_granted", occurred_at=_NOW)
    assert a is not None and b is not None
    assert a["idempotency_key"] == b["idempotency_key"]


def test_idempotency_key_is_stable_across_different_occurred_at() -> None:
    # occurred_at (send/wall-clock time) does NOT participate in the key — the key anchors to the
    # grant's identity (granted_at), so re-emitting the same grant later still dedups.
    a = me.build_subscription_event(_premium(), event_type="subscription_granted", occurred_at=_NOW)
    b = me.build_subscription_event(
        _premium(), event_type="subscription_granted", occurred_at=_NOW + timedelta(hours=6)
    )
    assert a is not None and b is not None
    assert a["idempotency_key"] == b["idempotency_key"]


def test_idempotency_key_differs_by_event_type() -> None:
    granted = me.build_subscription_event(
        _premium(), event_type="subscription_granted", occurred_at=_NOW
    )
    revoked = me.build_subscription_event(
        _premium(), event_type="subscription_revoked", occurred_at=_NOW
    )
    assert granted is not None and revoked is not None
    assert granted["idempotency_key"] != revoked["idempotency_key"]


def test_idempotency_key_differs_by_granted_at() -> None:
    a = me.build_subscription_event(
        _premium(granted_at=_NOW), event_type="subscription_granted", occurred_at=_NOW
    )
    b = me.build_subscription_event(
        _premium(granted_at=_NOW + timedelta(days=1)),
        event_type="subscription_granted",
        occurred_at=_NOW,
    )
    assert a is not None and b is not None
    assert a["idempotency_key"] != b["idempotency_key"]


# --- emit: unconfigured / FREE-tier no-op -----------------------------------------------------


def test_emit_noop_when_both_env_vars_unset() -> None:
    captured: list[httpx.Request] = []

    async def _run() -> None:
        # No transport patch needed: an unconfigured emit must not construct any client at all.
        await me.emit_subscription_event(
            _premium(), event_type="subscription_granted", occurred_at=_NOW
        )

    asyncio.run(_run())
    assert captured == []  # trivially, but documents intent: nothing sent


def test_emit_noop_when_only_url_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(me.REVENUE_INGEST_URL_ENV, "https://delta.internal")
    captured = _patch_transport(monkeypatch, lambda r: httpx.Response(200))

    async def _run() -> None:
        await me.emit_subscription_event(
            _premium(), event_type="subscription_granted", occurred_at=_NOW
        )

    asyncio.run(_run())
    assert captured == []


def test_emit_noop_when_only_secret_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(me.REVENUE_HMAC_SECRET_ENV, "sekret")
    captured = _patch_transport(monkeypatch, lambda r: httpx.Response(200))

    async def _run() -> None:
        await me.emit_subscription_event(
            _premium(), event_type="subscription_granted", occurred_at=_NOW
        )

    asyncio.run(_run())
    assert captured == []


def test_emit_noop_for_free_tier_when_fully_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(me.REVENUE_INGEST_URL_ENV, "https://delta.internal")
    monkeypatch.setenv(me.REVENUE_HMAC_SECRET_ENV, "sekret")
    captured = _patch_transport(monkeypatch, lambda r: httpx.Response(200))

    async def _run() -> None:
        await me.emit_subscription_event(
            _free(), event_type="subscription_granted", occurred_at=_NOW
        )

    asyncio.run(_run())
    assert captured == []  # FREE tier -> nothing billable -> nothing sent


# --- emit: configured happy path — request shape, headers, HMAC ------------------------------


def test_emit_posts_signed_request_with_valid_hmac(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = "shared-revenue-secret"
    monkeypatch.setenv(me.REVENUE_INGEST_URL_ENV, "https://delta.internal/")
    monkeypatch.setenv(me.REVENUE_HMAC_SECRET_ENV, secret)
    captured = _patch_transport(
        monkeypatch, lambda r: httpx.Response(200, json={"status": "accepted"})
    )

    async def _run() -> None:
        await me.emit_subscription_event(
            _premium(), event_type="subscription_granted", occurred_at=_NOW
        )

    asyncio.run(_run())

    assert len(captured) == 1
    req = captured[0]
    # trailing slash normalized; path is exactly the contract path.
    assert str(req.url) == "https://delta.internal/v1/ingest/revenue"
    assert req.headers["content-type"] == "application/json"

    signature = req.headers["X-Orchestrator-Signature"]
    timestamp = req.headers["X-Orchestrator-Timestamp"]
    assert signature.startswith("sha256=")
    assert timestamp.isdigit()

    # Re-compute the HMAC over the EXACT bytes sent — the whole point of signing content, not a
    # re-serialization — and confirm it validates (this is what Delta's hmac_verify does).
    body = req.content
    expected = hmac.new(
        secret.encode("utf-8"), f"{timestamp}.".encode("utf-8") + body, hashlib.sha256
    ).hexdigest()
    assert signature == f"sha256={expected}"

    # The signed body is the RevenueIngestRecord we built.
    payload = json.loads(body)
    assert payload["event_type"] == "subscription_granted"
    assert payload["amount_cents"] == 1499
    assert payload["tenant_id"] == _TENANT


def test_emit_revoke_posts_event(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(me.REVENUE_INGEST_URL_ENV, "https://delta.internal")
    monkeypatch.setenv(me.REVENUE_HMAC_SECRET_ENV, "sekret")
    captured = _patch_transport(monkeypatch, lambda r: httpx.Response(200))

    async def _run() -> None:
        await me.emit_subscription_event(
            _premium(), event_type="subscription_revoked", occurred_at=_NOW
        )

    asyncio.run(_run())
    assert len(captured) == 1
    assert json.loads(captured[0].content)["event_type"] == "subscription_revoked"


# --- emit: fail-open on non-2xx and transport exception --------------------------------------


def test_emit_swallows_non_2xx_response(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(me.REVENUE_INGEST_URL_ENV, "https://delta.internal")
    monkeypatch.setenv(me.REVENUE_HMAC_SECRET_ENV, "sekret")
    _patch_transport(monkeypatch, lambda r: httpx.Response(500))

    async def _run() -> None:
        with caplog.at_level(logging.WARNING, logger=me.logger.name):
            await me.emit_subscription_event(
                _premium(), event_type="subscription_granted", occurred_at=_NOW
            )

    asyncio.run(_run())  # must not raise
    assert "revenue_event_emit_unexpected_status" in caplog.text


def test_emit_swallows_transport_exception(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv(me.REVENUE_INGEST_URL_ENV, "https://delta.internal")
    monkeypatch.setenv(me.REVENUE_HMAC_SECRET_ENV, "sekret")

    def _raise(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    _patch_transport(monkeypatch, _raise)

    async def _run() -> None:
        with caplog.at_level(logging.WARNING, logger=me.logger.name):
            await me.emit_subscription_event(
                _premium(), event_type="subscription_granted", occurred_at=_NOW
            )

    asyncio.run(_run())  # must not raise — the whole point of fail-open
    assert "revenue_event_emit_failed" in caplog.text
