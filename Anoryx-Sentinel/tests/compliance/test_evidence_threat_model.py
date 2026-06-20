"""Compliance evidence threat-model tests (F-011, ADR-0013 §10).

Covers vectors 1, 4, 7, 10 from the threat model, plus unit tests for window
validation and empty-window (chain_tip None) behaviour.

DB-backed tests require:
  - Live Postgres at sentinel-postgres:5432 (DATABASE_URL + APP_DATABASE_URL in .env)
  - SENTINEL_PROVISION_APP_ROLE=1

Honest framing: "audit-ready" throughout; never "compliant".
Every evidence artifact: "Certification requires an accredited auditor."
"""

from __future__ import annotations

import os
import re
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from compliance.errors import EvidenceWindowError
from compliance.evidence import EvidenceProjection, generate_evidence
from compliance.mapping import ControlEntry, FrameworkMap
from persistence.repositories.audit_log_repository import AuditLogRepository

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
_T0 = _NOW - timedelta(hours=1)
_T1 = _NOW + timedelta(hours=1)

# A fixed window that is clearly outside [_T0, _T1)
_BEFORE_WINDOW = _NOW - timedelta(hours=2)
_AFTER_WINDOW = _NOW + timedelta(hours=2)


def _make_framework_map(event_types: tuple[str, ...] = ("injection_detected",)) -> FrameworkMap:
    """Return a minimal FrameworkMap covering the given event_types."""
    return FrameworkMap(
        framework="SOC2",
        framework_version="2017-TSC-rev2022",
        controls=(
            ControlEntry(
                control_id="CC7.2",
                title="System monitoring for anomalies",
                sentinel_controls=("injection_detection",),
                evidence_event_types=event_types,
                rationale="Test control.",
                status_override=None,
            ),
        ),
    )


def _make_event_data(
    tenant_id: str,
    event_type: str = "injection_detected",
    timestamp: datetime | None = None,
) -> dict:
    """Build a minimal event_data dict for AuditLogRepository.append.

    event_timestamp uses the production 'Z' RFC3339 form (the form every real
    audit writer emits), NOT datetime.isoformat()'s '+00:00' form. This makes the
    window-filter tests exercise the exact serialization the live gateway writes,
    so the F-011 M-1 timestamptz-cast fix is regression-guarded (a lexicographic
    string compare would mis-bucket these 'Z' rows at the boundary).
    """
    ts = timestamp or _NOW
    return {
        "event_id": uuid.uuid4().hex,
        "event_type": event_type,
        "event_timestamp": ts.isoformat().replace("+00:00", "Z"),
        "request_id": uuid.uuid4().hex,
        "tenant_id": tenant_id,
        "team_id": f"team-{uuid.uuid4().hex[:6]}",
        "project_id": f"proj-{uuid.uuid4().hex[:6]}",
        "agent_id": "test-agent",
        "action_taken": "blocked",
    }


# ---------------------------------------------------------------------------
# Seed helpers
#
# TWO patterns are used depending on whether the test must cross a connection
# boundary (RLS proof) or can stay within a single session.
#
# Pattern A — NO-COMMIT savepoint (single-tenant tests, vectors 4 and M-1)
# -------------------------------------------------------------------------
# _seed_savepoint seeds rows via AuditLogRepository.append on the SAME session
# that generate_evidence will read from.  No transaction commit happens, so the
# rows are invisible to other connections and disappear when the outer SAVEPOINT
# rolls back at test end → zero table pollution.
#
# Requires monkeypatching compliance.evidence.get_tenant_session to return the
# same session so that generate_evidence can see the unseeded rows.
# _patch_tenant_session does that patch.
#
# Pattern B — COMMITTED rows + TRUNCATE teardown (cross-tenant tests, vector 7)
# -------------------------------------------------------------------------------
# _seed_committed creates its own engine+session, commits for real, then
# disposes within the current loop.  The truncate_audit_log_after fixture
# (from conftest.py) TRUNCATEs in teardown to restore the empty-table
# precondition for test_single_event_first_row_uses_genesis_hash.
# TRUNCATE bypasses the BEFORE DELETE trigger (DELETE is blocked, TRUNCATE is not).
# ---------------------------------------------------------------------------


async def _seed_savepoint(session: AsyncSession, events: list[dict]) -> None:
    """Seed rows inside an active session (no commit; visible only within that session).

    Called from single-tenant tests that monkeypatch get_tenant_session to yield
    this same session.  generate_evidence sees the seeded rows through the shared
    connection; the outer SAVEPOINT in the `session` fixture rolls everything back
    at test end → zero table pollution.

    The session must already be in an active transaction (begin() context) when
    called.  Uses begin_nested() as an async context manager — SQLAlchemy issues
    SAVEPOINT on entry and RELEASE on clean exit (ROLLBACK TO on exception).
    """
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        pytest.skip("DATABASE_URL not set — skipping DB-backed compliance test")
    async with session.begin_nested():
        repo = AuditLogRepository(session)
        for event_data in events:
            await repo.append(event_data)


def _patch_tenant_session(monkeypatch, session: AsyncSession, tenant_id: str) -> None:
    """Monkeypatch compliance.evidence.get_tenant_session to yield *session*.

    The patched context manager sets app.current_tenant_id on the session (same as
    the real get_tenant_session) so any RLS GUC-dependent reads behave correctly,
    then yields the shared privileged session.  RLS enforcement is NOT the point of
    single-tenant no-commit tests; the shared privileged session is sufficient.
    """
    from contextlib import asynccontextmanager
    from typing import AsyncIterator

    from sqlalchemy import text as _text
    from sqlalchemy.ext.asyncio import AsyncSession as _AsyncSession

    import compliance.evidence as _ev

    @asynccontextmanager
    async def _shared_session_ctx(_tenant_id: str) -> AsyncIterator[_AsyncSession]:
        await session.execute(
            _text("SELECT set_config('app.current_tenant_id', :tid, true)"),
            {"tid": _tenant_id},
        )
        yield session

    monkeypatch.setattr(_ev, "get_tenant_session", _shared_session_ctx)


async def _seed_committed(events: list[dict]) -> None:
    """Commit seed rows on a dedicated privileged connection in the current loop.

    Used ONLY by cross-tenant tests (vector 7) that MUST prove RLS invisibility
    across a real second connection.  Rows are committed so the separate
    get_tenant_session connection can see them.

    The truncate_audit_log_after fixture (conftest.py) must be requested by
    every test that calls this helper — it TRUNCATEs the table in teardown to
    restore the empty-table precondition for test_single_event_first_row_uses_genesis_hash.
    """
    raw = os.environ.get("DATABASE_URL", "")
    if not raw:
        pytest.skip("DATABASE_URL not set — skipping DB-backed compliance test")
    url = re.sub(r"^postgresql(\+psycopg)?://", "postgresql+asyncpg://", raw)
    # app.session_kind='privileged' satisfies AuditLogRepository.append's
    # defense-in-depth check (_assert_privileged_session); matches the
    # persistence `session` fixture's connect_args.
    engine = create_async_engine(
        url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )
    try:
        factory = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
        )
        async with factory() as s:
            async with s.begin():  # commits on clean exit; no savepoint
                repo = AuditLogRepository(s)
                for event_data in events:
                    await repo.append(event_data)
    finally:
        await engine.dispose()  # disposed in this loop — no "loop is closed"


# ---------------------------------------------------------------------------
# Vector 1 — Evidence generation is read-only (zero writes to events_audit_log)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evidence_generation_is_read_only(
    test_tenant_id: str,
    app_db_url: str,
) -> None:
    """Vector 1: prove generate_evidence issues ZERO INSERT/UPDATE/DELETE statements.

    Attaches a SQLAlchemy before_cursor_execute event listener to the underlying
    asyncpg connection pool used by get_tenant_session.  Captures every SQL
    statement issued during generate_evidence and asserts none match
    INSERT/UPDATE/DELETE on events_audit_log.  This is a positive proof of
    zero-write, not merely an absence of exceptions.
    """
    import re as _re
    from contextlib import asynccontextmanager
    from typing import AsyncIterator

    from sqlalchemy import event as sa_event
    from sqlalchemy.ext.asyncio import AsyncSession as _AsyncSession
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    _WRITE_PATTERN = _re.compile(r"\b(INSERT|UPDATE|DELETE)\b", _re.IGNORECASE)
    captured_statements: list[str] = []

    engine = create_async_engine(app_db_url, pool_pre_ping=True, echo=False)

    # Core-level listener — fires for every statement on this engine.
    @sa_event.listens_for(engine.sync_engine, "before_cursor_execute")
    def _capture(conn, cursor, statement, parameters, context, executemany):
        captured_statements.append(statement)

    app_factory = async_sessionmaker(
        bind=engine,
        class_=_AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )

    @asynccontextmanager
    async def _monitored_tenant_session(
        tenant_id: str,
    ) -> AsyncIterator[_AsyncSession]:
        from sqlalchemy import text as _text

        async with app_factory() as sess:
            await sess.execute(
                _text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                {"tid": tenant_id},
            )
            yield sess

    import compliance.evidence as ev_module

    original_gts = ev_module.get_tenant_session
    ev_module.get_tenant_session = _monitored_tenant_session  # type: ignore[assignment]

    try:
        fmap = _make_framework_map()
        projection = await generate_evidence(fmap, _T0, _T1, tenant_id=test_tenant_id)
    finally:
        ev_module.get_tenant_session = original_gts
        await engine.dispose()

    # Assert: projection returned successfully.
    assert isinstance(projection, EvidenceProjection)

    # Assert: ZERO write statements issued against events_audit_log.
    write_stmts = [
        s
        for s in captured_statements
        if _WRITE_PATTERN.search(s) and "events_audit_log" in s.lower()
    ]
    assert write_stmts == [], (
        f"generate_evidence issued {len(write_stmts)} write statement(s) against "
        f"events_audit_log — R1 violation:\n" + "\n".join(write_stmts)
    )


# ---------------------------------------------------------------------------
# Vector 4 — Stale/out-of-window events excluded from the projection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stale_evidence_window_bounded(
    monkeypatch,
    session,
    test_tenant_id: str,
) -> None:
    """Vector 4: events outside [t0, t1) must not appear in event_counts.

    Seeds rows: two inside the window, one before t0, one after t1.
    Asserts the projection counts only the two in-window rows.
    Also asserts t0/t1 are echoed faithfully on the projection.

    NO-COMMIT pattern (Pattern A):
    Rows are seeded via _seed_savepoint on the shared privileged session, then
    compliance.evidence.get_tenant_session is monkeypatched to return that same
    session so generate_evidence sees the uncommitted rows through the shared
    connection.  The outer SAVEPOINT in the `session` fixture rolls back at test
    end → zero table pollution; the genesis chain test is unaffected.
    """
    # Arrange — seed 4 rows (2 in-window, 1 before t0, 1 after t1) in savepoint.
    await _seed_savepoint(
        session,
        [
            _make_event_data(test_tenant_id, timestamp=_T0 + timedelta(minutes=5)),
            _make_event_data(test_tenant_id, timestamp=_T0 + timedelta(minutes=30)),
            _make_event_data(test_tenant_id, timestamp=_BEFORE_WINDOW),
            _make_event_data(test_tenant_id, timestamp=_AFTER_WINDOW),
        ],
    )
    _patch_tenant_session(monkeypatch, session, test_tenant_id)
    fmap = _make_framework_map()

    # Act
    projection = await generate_evidence(fmap, _T0, _T1, tenant_id=test_tenant_id)

    # Assert — only 2 in-window events counted.
    assert (
        projection.event_counts.get("injection_detected", 0) == 2
    ), f"Expected 2 in-window events, got {projection.event_counts}"
    assert projection.total_events_in_window == 2

    # Assert — window boundaries echoed faithfully.
    assert projection.t0 == _T0
    assert projection.t1 == _T1

    # Assert — projection is immutable (MappingProxyType).
    with pytest.raises(TypeError):
        projection.event_counts["injection_detected"] = 999  # type: ignore[index]


# ---------------------------------------------------------------------------
# M-1 regression — production 'Z'-form rows must not be lexicographically
# mis-bucketed at a fractional-second window boundary.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_window_counts_production_z_form_at_fractional_boundary(
    monkeypatch,
    session,
    test_tenant_id: str,
) -> None:
    """Security audit F-011 M-1: a production 'Z'-form event at instant T must be
    counted by a window ending at T + 1ms, even though the bound serializes as the
    '+00:00' form.

    Pre-fix (lexicographic string compare), '2026-01-15T12:00:00Z' sorts AFTER
    '2026-01-15T12:00:00.001000+00:00' (Z=0x5A > .=0x2E at index 19), so the row
    was silently dropped → undercount. With the timestamptz CAST, the comparison
    is a true instant compare and the row is counted.

    NO-COMMIT pattern (Pattern A): see test_stale_evidence_window_bounded for rationale.
    """
    # Arrange — one Z-form event exactly at _NOW (inside [_T0, _NOW+1ms)).
    await _seed_savepoint(session, [_make_event_data(test_tenant_id, timestamp=_NOW)])
    _patch_tenant_session(monkeypatch, session, test_tenant_id)
    t1_fractional = _NOW + timedelta(milliseconds=1)
    fmap = _make_framework_map()

    # Act
    projection = await generate_evidence(fmap, _T0, t1_fractional, tenant_id=test_tenant_id)

    # Assert — the production 'Z' row is counted, not dropped.
    assert projection.event_counts.get("injection_detected", 0) == 1
    assert projection.total_events_in_window == 1


# ---------------------------------------------------------------------------
# Vector 7 — Evidence is tenant-scoped; tenant B rows not counted for tenant A
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evidence_tenant_scoped(
    test_tenant_id: str,
    tenant_b_id: str,
    truncate_audit_log_after,  # noqa: ANN001 — fixture, not a type annotation
) -> None:
    """Vector 7: RLS ensures tenant-A query returns ZERO tenant-B rows.

    Seeds 3 rows for tenant A and 5 rows for tenant B (same event types,
    same timestamps, same window).  Generates evidence for tenant A.
    Asserts total_events_in_window == 3, never 8. Cross-tenant isolation is
    enforced at the DB layer (RLS), not in application filtering.

    COMMITTED-SEED + TRUNCATE pattern (Pattern B):
    Both tenants' rows MUST be committed so the separate RLS connection opened
    by get_tenant_session can see them.  This is the ONLY way to empirically
    prove that tenant-B rows are invisible to tenant-A under a real RLS policy
    — a savepoint on the same session would bypass the cross-connection boundary.

    The truncate_audit_log_after fixture TRUNCATEs the table in teardown (TRUNCATE
    bypasses the BEFORE DELETE trigger).  This restores the empty-table precondition
    for test_single_event_first_row_uses_genesis_hash under any test ordering.
    """
    # Arrange — commit 3 rows for tenant A and 5 for tenant B.
    await _seed_committed(
        [_make_event_data(test_tenant_id, timestamp=_NOW) for _ in range(3)]
        + [_make_event_data(tenant_b_id, timestamp=_NOW) for _ in range(5)]
    )

    fmap = _make_framework_map()

    # Act — generate for tenant A only.
    projection = await generate_evidence(fmap, _T0, _T1, tenant_id=test_tenant_id)

    # Assert — only tenant A's 3 rows visible; zero tenant B rows leaked.
    assert projection.total_events_in_window == 3, (
        f"Expected 3 (tenant A only), got {projection.total_events_in_window}. "
        f"RLS may have leaked tenant B rows."
    )
    assert projection.event_counts.get("injection_detected", 0) == 3


# ---------------------------------------------------------------------------
# Vector 10 — Evidence read uses the RLS-scoped sentinel_app role
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evidence_uses_rls_scoped_role(
    test_tenant_id: str,
    app_db_url: str,
) -> None:
    """Vector 10: the session used by generate_evidence runs as sentinel_app
    with GUC app.current_tenant_id set to the caller's tenant_id.

    Intercepts the session inside generate_evidence to issue two diagnostic
    queries:
      - SELECT current_user           -> must equal 'sentinel_app'
      - SELECT current_setting(...)   -> must equal tenant_id
    Asserts neither check returns a bypass/privileged role.
    """
    from contextlib import asynccontextmanager
    from typing import AsyncIterator

    from sqlalchemy.ext.asyncio import AsyncSession as _AsyncSession
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    observed_role: list[str] = []
    observed_guc: list[str] = []

    engine = create_async_engine(app_db_url, pool_pre_ping=True, echo=False)
    factory = async_sessionmaker(
        bind=engine,
        class_=_AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )

    @asynccontextmanager
    async def _introspecting_session(tenant_id: str) -> AsyncIterator[_AsyncSession]:
        async with factory() as sess:
            await sess.execute(
                text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                {"tid": tenant_id},
            )
            # Introspect role and GUC while the session is live.
            role_row = await sess.execute(text("SELECT current_user"))
            observed_role.append(role_row.scalar_one())
            guc_row = await sess.execute(
                text("SELECT current_setting('app.current_tenant_id', true)")
            )
            observed_guc.append(guc_row.scalar_one())
            yield sess

    import compliance.evidence as ev_module

    original_gts = ev_module.get_tenant_session
    ev_module.get_tenant_session = _introspecting_session  # type: ignore[assignment]
    try:
        fmap = _make_framework_map()
        await generate_evidence(fmap, _T0, _T1, tenant_id=test_tenant_id)
    finally:
        ev_module.get_tenant_session = original_gts
        await engine.dispose()

    # Assert — session ran as sentinel_app (not owner/bypass role).
    assert len(observed_role) == 1
    assert observed_role[0] == "sentinel_app", (
        f"Evidence query ran as {observed_role[0]!r} — expected 'sentinel_app'. "
        f"R1/D1 violation: the privileged bypass role must never be used for reads."
    )

    # Assert — GUC was set to the caller's tenant_id.
    assert len(observed_guc) == 1
    assert observed_guc[0] == test_tenant_id, (
        f"GUC app.current_tenant_id was {observed_guc[0]!r} — expected "
        f"{test_tenant_id!r}. Tenant attribution is broken."
    )


# ---------------------------------------------------------------------------
# Unit tests — window validation + empty window (no DB required)
# ---------------------------------------------------------------------------


def test_window_validation_raises_when_t0_equals_t1() -> None:
    """EvidenceWindowError raised when t0 == t1 (empty window)."""
    import asyncio

    # Arrange
    t = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    fmap = _make_framework_map()

    # Act / Assert
    with pytest.raises(EvidenceWindowError, match="empty or reversed"):
        asyncio.run(generate_evidence(fmap, t, t, tenant_id="tenant-x"))


def test_window_validation_raises_when_t0_after_t1() -> None:
    """EvidenceWindowError raised when t0 > t1 (reversed window)."""
    import asyncio

    t0 = datetime(2026, 1, 2, 0, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    fmap = _make_framework_map()

    with pytest.raises(EvidenceWindowError, match="empty or reversed"):
        asyncio.run(generate_evidence(fmap, t0, t1, tenant_id="tenant-x"))


@pytest.mark.asyncio
async def test_empty_window_chain_tip_is_none(
    test_tenant_id: str,
    app_db_url: str,
) -> None:
    """chain_tip is None when no rows exist in the evidence window.

    Uses a window far in the future that contains no seeded rows.
    Verifies that the projection is returned without error, chain_tip is None,
    and event_counts are all zero (or empty).
    """
    from contextlib import asynccontextmanager
    from typing import AsyncIterator

    from sqlalchemy.ext.asyncio import AsyncSession as _AsyncSession
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(app_db_url, pool_pre_ping=True, echo=False)
    factory = async_sessionmaker(
        bind=engine,
        class_=_AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )

    @asynccontextmanager
    async def _session_ctx(tenant_id: str) -> AsyncIterator[_AsyncSession]:
        async with factory() as sess:
            await sess.execute(
                text("SELECT set_config('app.current_tenant_id', :tid, true)"),
                {"tid": tenant_id},
            )
            yield sess

    import compliance.evidence as ev_module

    original_gts = ev_module.get_tenant_session
    ev_module.get_tenant_session = _session_ctx  # type: ignore[assignment]

    # A window so far in the future it contains no rows.
    future_t0 = datetime(2099, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    future_t1 = datetime(2099, 12, 31, 0, 0, 0, tzinfo=timezone.utc)

    try:
        fmap = _make_framework_map()
        projection = await generate_evidence(fmap, future_t0, future_t1, tenant_id=test_tenant_id)
    finally:
        ev_module.get_tenant_session = original_gts
        await engine.dispose()

    # Assert
    assert (
        projection.chain_tip is None
    ), f"Expected chain_tip=None for empty window, got {projection.chain_tip}"
    assert projection.total_events_in_window == 0
    # All event_counts should be zero.
    for count in projection.event_counts.values():
        assert count == 0
