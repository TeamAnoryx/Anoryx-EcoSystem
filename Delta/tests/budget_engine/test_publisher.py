"""O-004 publisher: status classification + request shape (ADR-0005 §3.4, vector 9)."""

from __future__ import annotations

import httpx
import pytest

from delta.budget_engine import publisher as P
from delta.budget_engine.config import EngineSettings
from delta.budget_engine.publisher import (
    Distributed,
    PermanentPublishError,
    TransientPublishError,
    publish_signed_policy,
)

_SETTINGS = EngineSettings(
    enabled=True, distribution_url="http://orch:8000", service_token="svc-tok"
)
_SIGNED = {"policy_type": "budget_limit", "signature": "a.b.c"}


class _FakeResp:
    def __init__(self, status_code: int, payload: dict | None = None, bad_json: bool = False):
        self.status_code = status_code
        self._payload = payload
        self._bad = bad_json

    def json(self):
        if self._bad:
            raise ValueError("not json")
        return self._payload if self._payload is not None else {}


def _install_client(monkeypatch, *, resp=None, exc=None):
    captured: dict = {}

    class _FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc_info):
            return False

        async def post(self, url, json=None, headers=None):
            captured.update(url=url, json=json, headers=headers)
            if exc is not None:
                raise exc
            return resp

    monkeypatch.setattr(P.httpx, "AsyncClient", _FakeClient)
    return captured


async def test_202_returns_distribution_id(monkeypatch):
    cap = _install_client(
        monkeypatch, resp=_FakeResp(202, {"distribution_id": "dist-1", "state": "pending"})
    )
    out = await publish_signed_policy(_SIGNED, _SETTINGS)
    assert isinstance(out, Distributed)
    assert out.distribution_id == "dist-1"
    # Request shape: sign_on_behalf=false, Bearer token, the distribution endpoint.
    assert cap["url"] == "http://orch:8000/v1/policies/distributions"
    assert cap["json"] == {"policy": _SIGNED, "sign_on_behalf": False}
    assert cap["headers"] == {"Authorization": "Bearer svc-tok"}


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
async def test_transient_statuses_raise_transient(monkeypatch, status):
    _install_client(monkeypatch, resp=_FakeResp(status))
    with pytest.raises(TransientPublishError):
        await publish_signed_policy(_SIGNED, _SETTINGS)


@pytest.mark.parametrize("status", [400, 401, 403, 409, 422])
async def test_other_4xx_raise_permanent(monkeypatch, status):
    _install_client(monkeypatch, resp=_FakeResp(status))
    with pytest.raises(PermanentPublishError):
        await publish_signed_policy(_SIGNED, _SETTINGS)


async def test_transport_error_is_transient(monkeypatch):
    _install_client(monkeypatch, exc=httpx.ConnectError("connection refused"))
    with pytest.raises(TransientPublishError):
        await publish_signed_policy(_SIGNED, _SETTINGS)


async def test_timeout_is_transient(monkeypatch):
    _install_client(monkeypatch, exc=httpx.ReadTimeout("timed out"))
    with pytest.raises(TransientPublishError):
        await publish_signed_policy(_SIGNED, _SETTINGS)


async def test_202_without_distribution_id_is_transient(monkeypatch):
    _install_client(monkeypatch, resp=_FakeResp(202, {}))
    with pytest.raises(TransientPublishError):
        await publish_signed_policy(_SIGNED, _SETTINGS)


async def test_202_unparseable_body_is_transient(monkeypatch):
    _install_client(monkeypatch, resp=_FakeResp(202, bad_json=True))
    with pytest.raises(TransientPublishError):
        await publish_signed_policy(_SIGNED, _SETTINGS)
