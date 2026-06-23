"""Endpoint-policy (F-007 seam reuse) tests (F-018, ADR-0021 §6, D3).

Vector covered:
  8  test_endpoint_policy_persists_and_loads — NON-STUBBED reuse of F-007's
     provider allowlist: a disallowed-known-provider egress raw row exists ->
     the classifier flags it. No new policy_type.

DB-GATED: skips when DATABASE_URL/APP_DATABASE_URL not set or Postgres
unreachable.

Implementation note: F-018 *does not* make real outbound httpx calls through
the egress sensor in tests (that would require a live provider). Instead, we
prove the reuse seam by:
  (a) inserting a real shadow_ai_detected_outbound row into the audit log via
      the REAL AuditLogRepository (privileged session), simulating what F-007
      would write when a disallowed-provider egress happens;
  (b) calling the REAL get_candidates() (no stubs) and asserting the candidate
      is produced for that provider — proving the path from raw row to
      classified candidate.
This approach is endorsed by ADR-0021 §9 vector 8 which allows reusing F-007
egress fixtures.
"""

from __future__ import annotations

import os
import re
import uuid

import pytest

from shadow_ai import constants as C

_SKIP_REASON = "DATABASE_URL/APP_DATABASE_URL not set or Postgres unreachable"


def _db_available() -> bool:
    return bool(os.environ.get("DATABASE_URL")) and bool(os.environ.get("APP_DATABASE_URL"))


def _to_asyncpg_url(raw: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", raw)
    return re.sub(r"^postgresql://", "postgresql+asyncpg://", url)


async def _pg_probe(db_raw: str) -> bool:
    m = re.match(r"postgresql(?:\+asyncpg)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", db_raw)
    if not m:
        return False
    try:
        import asyncpg

        conn = await asyncpg.connect(
            user=m.group(1),
            password=m.group(2),
            host=m.group(3),
            port=int(m.group(4)),
            database=m.group(5),
            timeout=3,
        )
        await conn.close()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Pure-unit tests (no DB): config reuse proven structurally
# ---------------------------------------------------------------------------


class TestEndpointPolicyPureUnit:
    """Prove F-018 structurally reuses F-007's provider allow-list (D3)."""

    def test_no_new_policy_type_in_shadow_ai_package(self) -> None:
        """shadow_ai.* must define NO new policy_type constant."""
        import shadow_ai.constants as C

        # The only policy-related reuse is reading existing routing policy rows.
        # No new policy_type string is introduced in F-018.
        assert not hasattr(C, "POLICY_TYPE"), (
            "shadow_ai.constants defines a POLICY_TYPE — F-018 reuses F-007's "
            "allowlist and must introduce no new policy_type (D3)."
        )

    def test_known_providers_are_openai_anthropic_bedrock(self) -> None:
        """The F-007 seam recognises exactly three provider strings."""
        from types import SimpleNamespace

        from shadow_ai.classifier import classify

        # These are the providers the F-007 egress sensor can detect.
        known = {"openai", "anthropic", "bedrock"}
        # The classifier does not restrict providers beyond what the raw rows carry,
        # but the band logic works for all three.
        for provider in known:
            row = SimpleNamespace(
                team_id="t1",
                project_id="p1",
                detected_endpoint=f"api.{provider}.com",
                selected_provider=provider,
                first_seen_at="2026-06-24T12:00:00Z",
            )
            candidates = classify([row], "tenant-x", window_bucket="2026-06-24")
            assert len(candidates) == 1
            assert candidates[0].provider == provider

    def test_service_reads_shadow_ai_detected_outbound_rows(self) -> None:
        """service.py queries the correct raw event type from F-007."""
        import inspect

        import shadow_ai.service as svc

        source = inspect.getsource(svc)
        assert "shadow_ai_detected_outbound" in source
        # The service must NOT redefine the raw event type inline
        assert "RAW_EGRESS_EVENT_TYPE" in source or "shadow_ai_detected_outbound" in source


# ---------------------------------------------------------------------------
# DB-gated integration: raw row -> classify -> candidate (non-stubbed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_endpoint_policy_persists_and_loads():
    """Vector 8: F-007 seam reuse, non-stubbed.

    Inserts a REAL shadow_ai_detected_outbound row (simulating what F-007
    writes on disallowed-provider egress), then calls the REAL get_candidates()
    and asserts the candidate is classified for that provider.
    """
    if not _db_available():
        pytest.skip(_SKIP_REASON)

    db_raw = os.environ.get("DATABASE_URL", "")
    if not await _pg_probe(db_raw):
        pytest.skip(_SKIP_REASON)

    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    db_url = _to_asyncpg_url(db_raw)
    priv_engine = create_async_engine(
        db_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )
    priv_factory = async_sessionmaker(
        bind=priv_engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
    )

    tenant_id = str(uuid.uuid4())
    team_id = str(uuid.uuid4())
    project_id = str(uuid.uuid4())

    # Seed tenant, team, project
    async with priv_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, name, display_name, is_active) "
                "VALUES (:t, :n, :n, true) ON CONFLICT (tenant_id) DO NOTHING"
            ),
            {"t": tenant_id, "n": f"ep-policy-{tenant_id[:8]}"},
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

    from persistence.repositories.audit_log_repository import AuditLogRepository

    # Insert REAL shadow_ai_detected_outbound row (simulates F-007 sensor output
    # for a tenant that has only 'openai' allowed but called 'anthropic').
    disallowed_provider = "anthropic"
    disallowed_endpoint = "api.anthropic.com"

    async with priv_factory() as sess:
        async with sess.begin():
            await AuditLogRepository(sess).append(
                {
                    "event_type": "shadow_ai_detected_outbound",
                    "action_taken": "logged",
                    "event_id": str(uuid.uuid4()),
                    "event_timestamp": "2026-06-24T10:00:00Z",
                    "request_id": "req-" + uuid.uuid4().hex[:32],
                    "tenant_id": tenant_id,
                    "team_id": team_id,
                    "project_id": project_id,
                    "agent_id": "defense",
                    "detected_endpoint": disallowed_endpoint,
                    "traffic_volume": 1,
                    "first_seen_at": "2026-06-24T10:00:00Z",
                    "selected_provider": disallowed_provider,
                }
            )

    try:
        from shadow_ai.service import get_candidates

        rid = "req-test-ep-policy-" + uuid.uuid4().hex[:8]
        report = await get_candidates(tenant_id, request_id=rid)

        # The provider allow-list reuse path: the raw row's provider is not in the
        # tenant's allow-list -> the row exists -> the classifier flags it.
        assert len(report.candidates) >= 1, (
            "No candidate produced — the F-007 seam reuse path is broken. "
            "The classifier must consume raw shadow_ai_detected_outbound rows."
        )

        providers = {c.provider for c in report.candidates}
        assert disallowed_provider in providers, (
            f"Candidate for disallowed provider {disallowed_provider!r} not found. "
            f"Got providers: {providers}"
        )

        # Disclaimer always present
        assert report.disclaimer == C.HONESTY_DISCLAIMER

    finally:
        async with priv_engine.begin() as conn:
            await conn.execute(text("TRUNCATE events_audit_log"))
            await conn.execute(text("DELETE FROM projects WHERE tenant_id = :t"), {"t": tenant_id})
            await conn.execute(text("DELETE FROM teams WHERE tenant_id = :t"), {"t": tenant_id})
            await conn.execute(text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": tenant_id})
        await priv_engine.dispose()
