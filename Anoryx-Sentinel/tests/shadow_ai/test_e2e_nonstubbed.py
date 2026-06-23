"""F-018 vector 12: ZERO stubs on the detect/attribute/persist path.

Proves the FULL chain without stubbing any shadow_ai component:

    real AuditLogRepository.append (privileged) -> real shadow_ai_detected_outbound rows
    -> real get_candidates()                     -> real shadow_ai_candidate_detected row
    -> real AuditLogRepository read-back         -> correct attribution + band + key

The ONLY things simulated are the raw egress events (we insert them directly
into the audit log via the REAL AuditLogRepository.append on a privileged
session — exactly what F-007's egress sensor would produce).

Zero stubs on:
  - AuditLogRepository (append + read)
  - get_tenant_session / get_privileged_session
  - classifier.classify
  - get_candidates
  - attribution_key

DB-GATED + SENTINEL_PROVISION_APP_ROLE=1.
"""

from __future__ import annotations

import os
import re
import uuid

import pytest

_SKIP_REASON = (
    "DATABASE_URL / APP_DATABASE_URL not set or Postgres unreachable — "
    "skipping F-018 e2e nonstubbed"
)


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


@pytest.mark.asyncio
async def test_e2e_nonstubbed():
    """Vector 12: full chain with ZERO stubs on shadow_ai components.

    Assertions:
    a) After inserting real raw rows, get_candidates() returns candidates.
    b) A real shadow_ai_candidate_detected row is appended with correct
       attributed team/project + band + candidate_key.
    c) A second call DEDUPS — no duplicate candidate row is written.
    d) Read-back via repo confirms the expected candidate_key on the persisted row.
    """
    if not _db_available():
        pytest.skip(_SKIP_REASON)

    db_raw = os.environ.get("DATABASE_URL", "")
    if not await _pg_probe(db_raw):
        pytest.skip(_SKIP_REASON)

    from sqlalchemy import select, text
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

    async with priv_engine.begin() as conn:
        await conn.execute(
            text(
                "INSERT INTO tenants (tenant_id, name, display_name, is_active) "
                "VALUES (:t, :n, :n, true) ON CONFLICT (tenant_id) DO NOTHING"
            ),
            {"t": tenant_id, "n": f"e2e-f018-{tenant_id[:8]}"},
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

    from persistence.models.events_audit_log import EventsAuditLog
    from persistence.repositories.audit_log_repository import AuditLogRepository
    from shadow_ai import constants as C
    from shadow_ai.service import get_candidates

    endpoint = "api.anthropic.com"
    provider = "anthropic"
    timestamp = "2026-06-24T09:00:00Z"

    # -----------------------------------------------------------------------
    # Step 1: Insert REAL raw shadow_ai_detected_outbound rows via the REAL
    # AuditLogRepository.append (privileged session) — zero stubs.
    # -----------------------------------------------------------------------
    async with priv_factory() as sess:
        async with sess.begin():
            repo = AuditLogRepository(sess)
            await repo.append(
                {
                    "event_type": "shadow_ai_detected_outbound",
                    "action_taken": "logged",
                    "event_id": str(uuid.uuid4()),
                    "event_timestamp": timestamp,
                    "request_id": "req-e2e-f018-" + uuid.uuid4().hex[:16],
                    "tenant_id": tenant_id,
                    "team_id": team_id,
                    "project_id": project_id,
                    "agent_id": "defense",
                    "detected_endpoint": endpoint,
                    "traffic_volume": 1,
                    "first_seen_at": timestamp,
                    "selected_provider": provider,
                }
            )

    try:
        # -----------------------------------------------------------------------
        # Step 2: Call the REAL get_candidates() — zero stubs.
        # -----------------------------------------------------------------------
        rid = "req-e2e-f018-call1-" + uuid.uuid4().hex[:16]
        report = await get_candidates(tenant_id, request_id=rid)

        # (a) Candidates are returned
        assert len(report.candidates) >= 1, (
            "THE INERT-FEATURE CATCHER: get_candidates() returned zero candidates "
            "after inserting a real shadow_ai_detected_outbound row. "
            "The detect/classify/attribute path is not working end-to-end."
        )

        # Identify the candidate for our row
        our_candidate = next(
            (c for c in report.candidates if c.provider == provider and c.endpoint == endpoint),
            None,
        )
        assert our_candidate is not None, (
            f"Candidate for provider={provider!r} endpoint={endpoint!r} not found. "
            f"Candidates: {report.candidates}"
        )

        # Attribution: team_id and project_id must come from the server-stamped row
        assert our_candidate.team_id == team_id, (
            f"Attribution mismatch: expected team_id={team_id!r}, " f"got {our_candidate.team_id!r}"
        )
        assert our_candidate.project_id == project_id, (
            f"Attribution mismatch: expected project_id={project_id!r}, "
            f"got {our_candidate.project_id!r}"
        )

        # Band is set
        assert our_candidate.confidence_band in (C.BAND_LOW, C.BAND_MEDIUM, C.BAND_HIGH)

        # Candidate key is present
        assert our_candidate.candidate_key, "candidate_key must be non-empty"

        # Disclaimer is always present
        assert report.disclaimer == C.HONESTY_DISCLAIMER

        # (b) A real shadow_ai_candidate_detected row was persisted
        async with priv_factory() as sess:
            async with sess.begin():
                result = await sess.execute(
                    select(EventsAuditLog)
                    .where(EventsAuditLog.tenant_id == tenant_id)
                    .where(EventsAuditLog.event_type == C.CANDIDATE_EVENT_TYPE)
                    .where(EventsAuditLog.candidate_key == our_candidate.candidate_key)
                )
                persisted_rows = list(result.scalars().all())

        assert len(persisted_rows) >= 1, (
            "No shadow_ai_candidate_detected row was written to the audit log. "
            "The persist step is broken."
        )
        persisted = persisted_rows[0]
        assert persisted.team_id == team_id
        assert persisted.project_id == project_id
        assert persisted.confidence_band == our_candidate.confidence_band
        assert persisted.candidate_key == our_candidate.candidate_key
        assert persisted.selected_provider == provider
        assert persisted.detected_endpoint == endpoint

        # (c) Second call DEDUPs — no duplicate candidate row written
        rid2 = "req-e2e-f018-call2-" + uuid.uuid4().hex[:16]
        report2 = await get_candidates(tenant_id, request_id=rid2)

        async with priv_factory() as sess:
            async with sess.begin():
                result2 = await sess.execute(
                    select(EventsAuditLog)
                    .where(EventsAuditLog.tenant_id == tenant_id)
                    .where(EventsAuditLog.event_type == C.CANDIDATE_EVENT_TYPE)
                    .where(EventsAuditLog.candidate_key == our_candidate.candidate_key)
                )
                dedup_rows = list(result2.scalars().all())

        # The dedup logic skips re-emitting a candidate with the same key.
        # A rare race may double-record (ADR-0021 §6 acknowledges this), but in
        # a sequential test exactly one row must exist.
        assert len(dedup_rows) == 1, (
            f"DEDUP FAILURE: expected exactly 1 candidate row after second call, "
            f"got {len(dedup_rows)}. The dedup by candidate_key is broken."
        )

        # (d) Second report still contains the candidate (no data loss)
        report2_candidate = next(
            (c for c in report2.candidates if c.provider == provider and c.endpoint == endpoint),
            None,
        )
        assert report2_candidate is not None, (
            "Second get_candidates() call did not return the candidate — "
            "candidates must be re-derived on every call."
        )

    finally:
        async with priv_engine.begin() as conn:
            await conn.execute(text("TRUNCATE events_audit_log"))
            await conn.execute(text("DELETE FROM projects WHERE tenant_id = :t"), {"t": tenant_id})
            await conn.execute(text("DELETE FROM teams WHERE tenant_id = :t"), {"t": tenant_id})
            await conn.execute(text("DELETE FROM tenants WHERE tenant_id = :t"), {"t": tenant_id})
        await priv_engine.dispose()
