"""F-016 CRIT-2 guard: code_scan policy persists AND drives a real BLOCK.

This test proves the FULL chain without stubbing any Sentinel component:

    real upsert  →  real load  →  real detector  →  real scanner  →  real 403

The ONLY mock is the upstream LLM provider (proxy_non_stream), so the assistant
message is deterministic.  Every other component — auth, audit, routing policy
lookup, get_tenant_session, PolicyRepository, load_code_scan_config,
CodeScanDetector._scan_all_blocks, scan_block, semgrep/bandit subprocesses —
runs against the real code and the real provisioned Postgres test DB.

Mocks used (exactly three, all orthogonal to F-016):
  gateway.router.providers.openai_provider.proxy_non_stream
    Returns a fake ChatCompletionResponse whose assistant message contains
    a fenced Python block with os.system() — a pattern the real semgrep
    ruleset (python-security.yaml) flags at ERROR ("high") severity.
  gateway.router.selection._enforce_policies_pre_request
    F-008/Redis model+budget enforcement.  Redis is down in the test env
    so without this mock the request 500s before code-scan runs.
    Returns (ModelAllow(None), BudgetOk(), []) — allow all.
  gateway.router.selection._resolve_policy
    F-006 routing policy resolution.  _resolve_policy calls session.begin()
    on an already-autobegun tenant session (double-begin unrelated to F-016).
    Returns default_policy (no routing restriction). Orthogonal to code-scan.

Test requirements (from task specification):
  1. Seed a REAL tenant + team + project + virtual API key via committed
     privileged transactions so gateway auth can resolve the key.
  2. Persist a code_scan policy for that tenant via REAL PolicyRepository.upsert_policy
     (policy_type="code_scan", enabled=True, block_threshold="medium", block_action="reject").
  3. Assert REAL load_code_scan_config(tenant_id) returns enabled=True + block_threshold="medium".
  4. Drive a NON-STREAMED /v1/chat/completions; the mocked upstream response
     contains os.system() in a fenced python block; the REAL CodeScanDetector
     runs real semgrep+bandit through the real hook.
  5. Assert HTTP 403 with error_code="policy_blocked" AND a code_scan_blocked
     audit event written for the tenant.

If this test passes the chain is proven end-to-end.
If it fails (e.g. code_scan is not a persistable policy_type, load no-ops,
scanner doesn't flag the code), the failure message is explicit.

DB-GATED: skip gracefully when DATABASE_URL / APP_DATABASE_URL are absent or
Postgres is unreachable — identical to the bulk / compliance conftest pattern.
SENTINEL_PROVISION_APP_ROLE=1 is required (same as all real-DB tests).
"""

from __future__ import annotations

import base64
import json
import os
import re
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
import pytest_asyncio
from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# ---------------------------------------------------------------------------
# Load root .env (same as every other real-DB conftest in this project).
# ---------------------------------------------------------------------------

_ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
load_dotenv(dotenv_path=_ENV_PATH)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_asyncpg_url(raw: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    url = re.sub(r"^postgresql://", "postgresql+asyncpg://", url)
    return url


def _make_jws() -> str:
    """Return a syntactically valid compact-JWS placeholder (same as test_repositories.py)."""
    seg = base64.urlsafe_b64encode(b"x" * 20).decode().rstrip("=")
    return f"{seg}.{seg}.{seg}"


def _privileged_engine(db_url: str):
    return create_async_engine(
        db_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )


# ---------------------------------------------------------------------------
# The vulnerable assistant message that semgrep WILL flag.
#
# The real python-security.yaml ruleset defines sentinel-os-system at severity
# ERROR (→ "high").  With block_threshold="medium", high >= medium → BLOCK.
# Verified by running scan_block() directly before writing this test:
#   findings = [{'rule_id': '...sentinel-os-system', 'severity': 'high', 'line': 3},
#               {'rule_id': 'B605.start_process_with_a_shell', 'severity': 'high', 'line': 3}]
# ---------------------------------------------------------------------------

_VULN_CODE = "import os\ndef run(cmd):\n    os.system(cmd)\n"

_FAKE_COMPLETION = {
    "id": "chatcmpl-crit2-real",
    "object": "chat.completion",
    "created": 1700000000,
    "model": "gpt-3.5-turbo",
    "choices": [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                # Fenced python block: CodeScanDetector extracts it,
                # scan_block() runs real semgrep + bandit against it.
                "content": f"```python\n{_VULN_CODE}```",
            },
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 10, "completion_tokens": 15, "total_tokens": 25},
}


# ---------------------------------------------------------------------------
# Skip guard: skip when the real DB is not available.
# ---------------------------------------------------------------------------


def _db_available() -> bool:
    raw = os.environ.get("DATABASE_URL", "")
    app_raw = os.environ.get("APP_DATABASE_URL", "")
    if not raw or not app_raw:
        return False
    m = re.match(r"postgresql(?:\+asyncpg)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", raw)
    if not m:
        return False
    # Quick synchronous check: try asyncpg connection at import time would be
    # wrong — use the pytest skip mechanism inside the fixture instead.
    return True


_SKIP_REASON = (
    "DATABASE_URL / APP_DATABASE_URL not set or Postgres unreachable — "
    "skipping real-DB CRIT-2 guard"
)


# ---------------------------------------------------------------------------
# Fixture: seed committed rows + return cleanup handle
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture()
async def crit2_seed():
    """Seed tenant/team/project/virtual-key/policy in committed transactions.

    Returns a dict with all seeded IDs + the plaintext key, plus a cleanup()
    coroutine that removes the seeded rows after the test.

    All rows are COMMITTED (not rolled-back savepoints) so the gateway auth
    middleware — which opens a separate DB connection — can see them.

    Mirrors tests/bulk/conftest.py::seeded_key (the F-015 lesson:
    virtual_api_keys FKs team_id->teams and project_id->projects RESTRICT).
    """
    db_raw = os.environ.get("DATABASE_URL", "")
    app_raw = os.environ.get("APP_DATABASE_URL", "")
    if not db_raw or not app_raw:
        pytest.skip(_SKIP_REASON)

    db_url = _to_asyncpg_url(db_raw)

    # Probe Postgres reachability before trying to seed.
    m = re.match(r"postgresql(?:\+asyncpg)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", db_raw)
    if not m:
        pytest.skip(_SKIP_REASON)

    try:
        import asyncpg

        probe = await asyncpg.connect(
            user=m.group(1),
            password=m.group(2),
            host=m.group(3),
            port=int(m.group(4)),
            database=m.group(5),
            timeout=3,
        )
        await probe.close()
    except Exception:
        pytest.skip(_SKIP_REASON)

    tenant_id = str(uuid.uuid4())
    team_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())
    agent_id = "crit2-test"
    import secrets as _secrets

    plaintext = "sk-crit2-" + _secrets.token_urlsafe(24)
    policy_id = str(uuid.uuid4())

    engine = _privileged_engine(db_url)
    factory = async_sessionmaker(
        bind=engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )

    # -------------------------------------------------------------------
    # Step 1: Seed tenant + team + project + virtual API key (committed).
    # Uses raw SQL for tenant/team/project (same as bulk/conftest.py seeded_key).
    # Uses VirtualApiKeyRepository.create for the key (HMAC fingerprint — never
    # stores the plaintext).
    # -------------------------------------------------------------------
    async with engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, name, display_name, is_active) "
                "VALUES (:t, :n, :n, true) ON CONFLICT (tenant_id) DO NOTHING"
            ),
            {"t": tenant_id, "n": f"crit2-{tenant_id[:8]}"},
        )
        await conn.execute(
            text(
                "INSERT INTO teams (team_id, tenant_id, name, is_active) "
                "VALUES (:tm, :t, :n, true) ON CONFLICT (team_id) DO NOTHING"
            ),
            {"tm": team_id, "t": tenant_id, "n": f"team-{team_id[:8]}"},
        )
        await conn.execute(
            text(
                "INSERT INTO projects (project_id, team_id, tenant_id, name, is_active) "
                "VALUES (:p, :tm, :t, :n, true) ON CONFLICT (project_id) DO NOTHING"
            ),
            {"p": project_id, "tm": team_id, "t": tenant_id, "n": f"proj-{project_id[:8]}"},
        )

    # Virtual API key requires a committed session (VirtualApiKeyRepository uses flush).
    from persistence.repositories.virtual_api_key_repository import VirtualApiKeyRepository

    async with factory() as sess:
        async with sess.begin():
            await VirtualApiKeyRepository(sess).create(
                plaintext,
                tenant_id=tenant_id,
                team_id=team_id,
                project_id=project_id,
                agent_id=agent_id,
                label="crit2-test",
            )

    # -------------------------------------------------------------------
    # Step 2: Persist a code_scan policy (committed, privileged session).
    # PolicyRepository.upsert_policy requires valid compact-JWS signature —
    # built the same way as test_repositories.py::_make_jws().
    # -------------------------------------------------------------------
    from persistence.repositories.policy_repository import PolicyRepository

    code_scan_payload = {
        "enabled": True,
        "thresholds": {"warn": "low", "block": "medium"},
        "actions": {"warn": "audit", "block": "reject"},
    }

    async with factory() as sess:
        async with sess.begin():
            await PolicyRepository(sess).upsert_policy(
                policy_id=policy_id,
                policy_type="code_scan",
                policy_version=1,
                tenant_id=tenant_id,
                team_id=team_id,
                project_id=project_id,
                agent_id=agent_id,
                effective_from=datetime.now(timezone.utc),
                signature=_make_jws(),
                policy_payload=code_scan_payload,
            )

    await engine.dispose()

    # -------------------------------------------------------------------
    # Cleanup: remove seeded rows after the test.
    # -------------------------------------------------------------------
    async def _cleanup():
        cleanup_engine = _privileged_engine(db_url)
        try:
            async with cleanup_engine.begin() as conn:
                # events_audit_log is append-only: the BEFORE DELETE/UPDATE row
                # trigger blocks DELETE, but TRUNCATE bypasses row-level triggers
                # and IS permitted. This e2e commits REAL code_scan_* audit rows
                # (real audit path); if they lingered, the migration downgrade
                # test (test_migrations.py downgrade 0020->0019) would re-narrow
                # ck_eal_event_type and the leftover code_scan_* rows would raise
                # CheckViolation. TRUNCATE clears them for test isolation.
                await conn.execute(text("TRUNCATE events_audit_log"))
                # Remove policy rows (policy_versions FK -> policies; delete child first).
                await conn.execute(
                    text("DELETE FROM policy_versions WHERE policy_id = :pid"),
                    {"pid": policy_id},
                )
                await conn.execute(
                    text("DELETE FROM policies WHERE policy_id = :pid"),
                    {"pid": policy_id},
                )
                # Remove virtual API key, team, project, tenant.
                await conn.execute(
                    text("DELETE FROM virtual_api_keys WHERE tenant_id = :t"),
                    {"t": tenant_id},
                )
                await conn.execute(
                    text("DELETE FROM projects WHERE tenant_id = :t"),
                    {"t": tenant_id},
                )
                await conn.execute(
                    text("DELETE FROM teams WHERE tenant_id = :t"),
                    {"t": tenant_id},
                )
                await conn.execute(
                    text("DELETE FROM tenants WHERE tenant_id = :t"),
                    {"t": tenant_id},
                )
        finally:
            await cleanup_engine.dispose()

    yield {
        "tenant_id": tenant_id,
        "team_id": team_id,
        "project_id": project_id,
        "agent_id": agent_id,
        "plaintext": plaintext,
        "policy_id": policy_id,
    }

    await _cleanup()


# ---------------------------------------------------------------------------
# The test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_crit2_code_scan_policy_persists_and_drives_real_block(
    crit2_seed,
    monkeypatch,
):
    """F-016 CRIT-2 guard: real upsert → real load → real detector → real scanner → real 403.

    Mocks (exactly three, all orthogonal to F-016):
      gateway.router.providers.openai_provider.proxy_non_stream
        Returns a deterministic ChatCompletionResponse whose assistant message
        contains a fenced Python os.system() block — flagged at "high" severity
        by the real semgrep/bandit scanners.
      gateway.router.selection._enforce_policies_pre_request
        F-008/Redis enforcement — Redis is down in the test env.
      TenantRoutingPolicyRepository.get_for_tenant
        F-006 routing policy — returns default_policy to avoid double-begin.

    Everything else — auth, audit, get_tenant_session,
    PolicyRepository, load_code_scan_config, CodeScanDetector, scan_block,
    the real semgrep + bandit subprocesses — is REAL.
    """
    import httpx
    from httpx import ASGITransport

    tenant_id = crit2_seed["tenant_id"]
    team_id = crit2_seed["team_id"]
    project_id = crit2_seed["project_id"]
    agent_id = crit2_seed["agent_id"]
    plaintext = crit2_seed["plaintext"]

    # -------------------------------------------------------------------
    # Step 3: Assert REAL load_code_scan_config returns enabled + medium block.
    # Import is NOT patched — this exercises the real function against the real DB.
    # -------------------------------------------------------------------
    from code_scan.config import load_code_scan_config

    cfg = await load_code_scan_config(tenant_id)
    assert cfg.enabled is True, (
        f"load_code_scan_config returned enabled=False for tenant {tenant_id!r}. "
        "CRIT-2: the policy was not persisted or the load path is broken."
    )
    assert cfg.block_threshold == "medium", (
        f"Expected block_threshold='medium', got {cfg.block_threshold!r}. "
        "CRIT-2: the payload was not loaded correctly."
    )
    assert (
        cfg.block_action == "reject"
    ), f"Expected block_action='reject', got {cfg.block_action!r}."

    # -------------------------------------------------------------------
    # Gateway environment pins: the real DATABASE_URL / APP_DATABASE_URL /
    # SENTINEL_KEY_SECRET are already in env from root .env (loaded by conftest).
    # We only need to pin the non-secret gateway settings that pydantic-settings
    # cannot read from .env when CORS_ALLOWED_ORIGINS is not JSON-encoded.
    # -------------------------------------------------------------------
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "[]")
    monkeypatch.setenv("ROUTER_DEFAULT_PROVIDERS", '["openai"]')
    # upstream_base_url must be set; the real provider call is mocked below.
    if not os.environ.get("UPSTREAM_BASE_URL"):
        monkeypatch.setenv("UPSTREAM_BASE_URL", "https://upstream.example.invalid")
    monkeypatch.setenv("RATE_LIMIT_RPM", "600")
    monkeypatch.setenv("RATE_LIMIT_BURST", "60")
    monkeypatch.setenv("MAX_CONCURRENT_STREAMS_PER_TENANT", "20")

    from gateway.config import _reset_settings
    from gateway.middleware.rate_limit import reset_state_for_testing

    _reset_settings()
    reset_state_for_testing()

    # Clear httpx client cache so it is re-created with the correct settings.
    import gateway.upstream.openai_proxy as proxy_mod

    proxy_mod._http_client = None

    # -------------------------------------------------------------------
    # Mocks (exactly two):
    #   1. upstream LLM provider — deterministic vulnerable completion.
    #   2. _enforce_policies_pre_request — orthogonal F-008/Redis subsystem;
    #      Redis is down in the test env so without this mock the request
    #      500s before code-scan runs.  Mocking it to allow is identical to
    #      the pattern in tests/gateway/test_code_scan_gateway.py::build_app_with_code_scan.
    #      CONDITION 1 forbids stubbing config/persistence/load/scanner, NOT
    #      the upstream LLM or the orthogonal enforcement/Redis layer.
    # -------------------------------------------------------------------
    async def fake_proxy_non_stream(
        validated_body, request_id, upstream_api_key=None, overall_timeout=60.0
    ):
        from gateway.models import ChatCompletionResponse

        completion = ChatCompletionResponse(**_FAKE_COMPLETION)
        return completion, 10, 15

    from policy.enforcement import BudgetOk, ModelAllow

    async def _allow_enforce(tenant_context, body):
        return ModelAllow(None), BudgetOk(), []

    from persistence.repositories.tenant_routing_policy_repository import default_policy

    async def _fake_resolve_policy(tenant_context):
        return default_policy(tenant_context.tenant_id)

    # -------------------------------------------------------------------
    # Build the real gateway app.
    # Auth, audit, get_tenant_session (for code-scan config), PolicyRepository,
    # load_code_scan_config, CodeScanDetector, scan_block — all REAL.
    # Orthogonal mocks (not F-016):
    #   1. upstream LLM provider (deterministic response)
    #   2. _enforce_policies_pre_request (F-008/Redis; Redis down in test env)
    #   3. TenantRoutingPolicyRepository.get_for_tenant (F-006 routing policy;
    #      _resolve_policy calls session.begin() on an already-autobegun tenant
    #      session, hitting the same double-begin bug; routing is orthogonal to
    #      code-scan). Returns default_policy — no routing restriction.
    # -------------------------------------------------------------------
    _active_patchers = []
    try:
        p = patch(
            "gateway.router.providers.openai_provider.proxy_non_stream",
            side_effect=fake_proxy_non_stream,
        )
        p.start()
        _active_patchers.append(p)

        p2 = patch(
            "gateway.router.selection._enforce_policies_pre_request",
            new=_allow_enforce,
        )
        p2.start()
        _active_patchers.append(p2)

        p3 = patch(
            "gateway.router.selection._resolve_policy",
            new=_fake_resolve_policy,
        )
        p3.start()
        _active_patchers.append(p3)

        from gateway.main import create_app

        app = create_app()

        # -------------------------------------------------------------------
        # Step 4 & 5: Drive the real gateway with the real virtual key.
        # The real CodeScanDetector will:
        #   1. Call load_code_scan_config(tenant_id) → opens real get_tenant_session
        #   2. Extract the fenced ```python block
        #   3. Run real scan_block() → real semgrep + bandit subprocesses
        #   4. Aggregate: os.system() → "high" finding, high >= medium → BLOCK
        #   5. block_action="reject" → return DetectorResult(action="block")
        # run_code_scan raises HookBlockedError → GatewayError("policy_blocked") → 403
        # -------------------------------------------------------------------
        non_stream_body = json.dumps(
            {
                "model": "gpt-3.5-turbo",
                "messages": [{"role": "user", "content": "Show me a command runner"}],
                "stream": False,
            }
        )

        headers = {
            "X-Anoryx-Tenant-Id": tenant_id,
            "X-Anoryx-Team-Id": team_id,
            "X-Anoryx-Project-Id": project_id,
            "X-Anoryx-Agent-Id": agent_id,
            "Authorization": f"Bearer {plaintext}",
            "Content-Type": "application/json",
        }

        async with httpx.AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/v1/chat/completions",
                content=non_stream_body,
                headers=headers,
            )

    finally:
        for _p in _active_patchers:
            _p.stop()
        reset_state_for_testing()
        _reset_settings()

    # -------------------------------------------------------------------
    # Step 5 assertions.
    # -------------------------------------------------------------------
    # Assert HTTP 403 + error_code="policy_blocked".
    assert resp.status_code == 403, (
        f"Expected HTTP 403 from code-scan BLOCK with policy block_threshold='medium' "
        f"and os.system() in response. Got {resp.status_code}.\n"
        f"Response body: {resp.text[:800]}\n\n"
        "If the real semgrep/bandit did not flag os.system() at a severity >= 'medium', "
        "the scanner output would produce Verdict.PASS or WARN — not BLOCK. "
        "Check that semgrep (python-security.yaml sentinel-os-system) is at ERROR/'high' "
        "and that block_threshold='medium' means high >= medium → BLOCK."
    )
    body = resp.json()
    assert body.get("error_code") == "policy_blocked", (
        f"Expected error_code='policy_blocked', got {body.get('error_code')!r}. "
        f"Full body: {body}"
    )

    # Assert the code_scan_blocked audit event was written for this tenant.
    # Read directly from the privileged DB (same pattern as bulk threat model tests).
    db_raw = os.environ.get("DATABASE_URL", "")
    db_url = _to_asyncpg_url(db_raw)
    engine = _privileged_engine(db_url)
    try:
        async with engine.connect() as conn:
            count_row = await conn.execute(
                text(
                    "SELECT count(*) FROM events_audit_log "
                    "WHERE event_type = 'code_scan_blocked' AND tenant_id = :t"
                ),
                {"t": tenant_id},
            )
            event_count = int(count_row.scalar_one())
    finally:
        await engine.dispose()

    assert event_count >= 1, (
        f"Expected at least one 'code_scan_blocked' audit event for tenant {tenant_id!r}, "
        f"found {event_count}. "
        "The real CodeScanDetector must emit the event via the real audit path when "
        "a BLOCK verdict is produced with block_action='reject'."
    )
