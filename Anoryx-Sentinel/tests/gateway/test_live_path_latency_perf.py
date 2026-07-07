"""F-023 (ADR-0029) live-path load test — perf-load-engineer's first numeric budget.

  LIVE PROXY PATH — p95 added latency < 200ms, 100 concurrent requests.

Not run by default (`pytest.mark.perf`, deselected by pyproject.toml's
`addopts = "-m 'not perf'"`) — a wall-clock threshold assertion is inherently
noisier on a shared/loaded CI runner than the rest of the suite, and this test
exists to be invoked explicitly (`pytest -m perf tests/gateway/`) by the
perf-load-engineer agent or an operator, not to risk flaking the required PR
gate. Honest scope: this measures SENTINEL'S OWN added latency — auth,
rate-limiting, F-008 policy enforcement (the real code path, including the
F-023 eval_cache, exercised on a mocked-but-real DB session so a cache MISS
still runs the genuine evaluate_model_policies() query shape), request/response
translation, and audit emission — with the upstream provider AND the DB/Redis
network calls stubbed at the same repository/session boundary
tests/gateway/conftest.py already uses. It is not an end-to-end measurement
against a live Postgres/Redis/upstream network hop.

Runs a REAL uvicorn server on loopback (not httpx's in-process ASGITransport):
several of the gateway's middleware layers subclass Starlette's
BaseHTTPMiddleware, which is documented to raise a spurious
"cancel scope in a different task" error under ASGITransport when many
requests are dispatched truly simultaneously in one process (an artifact of
ASGITransport's request handling, not a bug reachable by real traffic — a real
server's socket-driven scheduling doesn't hit it). A real server + real HTTP
client sidesteps that harness artifact entirely.

Honest limitation (worth restating from ADR-0029): this spins up ONE worker
(the deployment's SENTINEL_WORKERS scales horizontally in production/Helm —
see ADR-0027 — not exercised here). On a single worker, the request pipeline's
CPU-bound portion (Pydantic validation, four stacked BaseHTTPMiddleware layers,
structlog serialization) is served by one asyncio event loop, so p95 scales
with concurrency roughly linearly rather than staying flat: this measures a
single worker's capacity ceiling, not a multi-replica deployment's. Passes
comfortably at the tens-of-concurrent-requests range on a single worker; at
the full 100-concurrent budget the result depends on host CPU throughput and
worker count — exactly why this is a `perf` test invoked deliberately against
a real target, not a blocking CI assertion on shared/arbitrary hardware.
"""

from __future__ import annotations

import asyncio
import socket
import time
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import uvicorn
from httpx import AsyncClient

from gateway.config import _reset_settings
from tests.gateway.conftest import (
    TEST_AGENT_ID,
    TEST_PLAINTEXT_KEY,
    TEST_PROJECT_ID,
    TEST_TEAM_ID,
    TEST_TENANT_ID,
    make_fake_key_row,
)

_CONCURRENCY = 100
_P95_BUDGET_MS = 200.0


def _headers():
    return {
        "X-Anoryx-Tenant-Id": TEST_TENANT_ID,
        "X-Anoryx-Team-Id": TEST_TEAM_ID,
        "X-Anoryx-Project-Id": TEST_PROJECT_ID,
        "X-Anoryx-Agent-Id": TEST_AGENT_ID,
        "Authorization": f"Bearer {TEST_PLAINTEXT_KEY}",
        "Content-Type": "application/json",
    }


def _body():
    return {"model": "gpt-3.5-turbo", "messages": [{"role": "user", "content": "Hello!"}]}


def _upstream_response():
    resp = MagicMock()
    resp.status_code = 200
    resp.json = MagicMock(
        return_value={
            "id": "chatcmpl-perf",
            "object": "chat.completion",
            "created": 1700000000,
            "model": "gpt-3.5-turbo",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": "Hi!"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
    )
    return resp


def _empty_scalars_session():
    """A MagicMock tenant session whose execute() answers every PolicyRepository
    SELECT with zero rows — exercises the REAL evaluate_model_policies() /
    eval_cache MISS code path (not a stub of the function itself), matching a
    tenant with no F-008 policies configured (implicit ModelAllow, no budgets)."""
    result = MagicMock()
    result.scalars.return_value.all.return_value = []
    session = MagicMock()
    session.execute = AsyncMock(return_value=result)
    return session


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _percentile(sorted_values: list[float], pct: float) -> float:
    if not sorted_values:
        return 0.0
    idx = min(len(sorted_values) - 1, int(round(pct * (len(sorted_values) - 1))))
    return sorted_values[idx]


@pytest.mark.perf
@pytest.mark.asyncio
async def test_live_path_p95_under_200ms(settings_env, monkeypatch):
    """100 concurrent /v1/chat/completions requests; p95 added latency < 200ms.

    Rate limiting is a SEPARATE, already-tested concern (tests/gateway/
    test_rate_limit_threat_model.py) — raise the limits here well above
    _CONCURRENCY so this test measures gateway+policy overhead, not induced
    429s from a single virtual key bursting past its normal RPM/burst budget.
    """
    monkeypatch.setenv("RATE_LIMIT_RPM", str(_CONCURRENCY * 10))
    monkeypatch.setenv("RATE_LIMIT_BURST", str(_CONCURRENCY * 2))
    _reset_settings()
    key_row = make_fake_key_row()
    auth_repo = MagicMock()
    auth_repo.lookup_by_plaintext = AsyncMock(return_value=key_row)
    session = _empty_scalars_session()

    @asynccontextmanager
    async def _priv_cm():
        yield MagicMock()

    @asynccontextmanager
    async def _tenant_cm(tenant_id):
        yield session

    from persistence.repositories.tenant_routing_policy_repository import default_policy

    async def _fake_get_for_tenant(self, tenant_id, caller_tenant_id):
        return default_policy(tenant_id)

    import gateway.upstream.openai_proxy as proxy_mod

    proxy_mod._http_client = None
    mock_client = MagicMock()
    mock_client.post = AsyncMock(return_value=_upstream_response())

    with (
        patch("gateway.middleware.auth.get_privileged_session", _priv_cm),
        patch("gateway.middleware.auth.VirtualApiKeyRepository", return_value=auth_repo),
        patch("gateway.routes.chat_completions.emit_terminal_record", new=AsyncMock()),
        patch("gateway.router.selection.emit_routing_decision", new=AsyncMock()),
        patch("persistence.database.get_tenant_session", _tenant_cm),
        patch(
            "persistence.repositories.tenant_routing_policy_repository."
            "TenantRoutingPolicyRepository.get_for_tenant",
            new=_fake_get_for_tenant,
        ),
        # F-005 (PII/injection/secret) hooks are orthogonal to F-023's target —
        # a cold-start Presidio/spaCy model load would dominate the measured
        # latency with a one-time cost unrelated to the gateway+policy overhead
        # this budget is about. An empty HookRegistry (no hooks) isolates that.
        patch("gateway.routes.chat_completions._get_default_registry", return_value=None),
        patch("gateway.upstream.openai_proxy._http_client", mock_client),
    ):
        from gateway.main import create_app

        app = create_app()
        port = _free_port()
        config = uvicorn.Config(
            app, host="127.0.0.1", port=port, log_level="warning", lifespan="off"
        )
        server = uvicorn.Server(config)
        server_task = asyncio.create_task(server.serve())
        try:
            for _ in range(500):
                if server.started:
                    break
                await asyncio.sleep(0.02)
            else:
                raise RuntimeError("uvicorn server did not start in time")

            async with AsyncClient(base_url=f"http://127.0.0.1:{port}") as ac:

                async def _timed_request() -> float:
                    start = time.perf_counter()
                    resp = await ac.post("/v1/chat/completions", headers=_headers(), json=_body())
                    elapsed_ms = (time.perf_counter() - start) * 1000
                    assert resp.status_code == 200, resp.text
                    return elapsed_ms

                latencies = await asyncio.gather(*(_timed_request() for _ in range(_CONCURRENCY)))
        finally:
            server.should_exit = True
            await server_task

    latencies.sort()
    p50 = _percentile(latencies, 0.50)
    p95 = _percentile(latencies, 0.95)
    p99 = _percentile(latencies, 0.99)

    assert p95 < _P95_BUDGET_MS, (
        f"live proxy path p95 added latency {p95:.1f}ms >= {_P95_BUDGET_MS}ms budget "
        f"(p50={p50:.1f}ms p99={p99:.1f}ms n={_CONCURRENCY})"
    )
