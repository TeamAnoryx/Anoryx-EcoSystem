"""F-007-FU: F-009 team-RPM double-begin fail-open (ADR-0026).

Vectors:
  1  team-RPM ceiling REALLY read via a real autobegin-ing get_tenant_session
     (non-stubbed; FAILS on pre-fix code where begin() raised → swallowed → None).
  2  a non-connectivity (begin()-class) error PROPAGATES (narrowed except guard).
  2b a genuine DB-connectivity error is a deliberate, bounded fail-open AND is not
     cached (pre-fix cached the None, poisoning the TTL).
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

import pytest
from sqlalchemy.exc import InvalidRequestError, OperationalError

import gateway.middleware.rate_limit as rl


def _op_error() -> OperationalError:
    return OperationalError("SELECT team_rpm_limit", {}, Exception("connection refused"))


async def test_team_rpm_limit_read_on_real_db(routing_policy, monkeypatch):
    """Vector 1 (non-stubbed): the team-RPM ceiling is read via the genuine
    autobegin session. Pre-fix begin() raised and the broad except swallowed it →
    None (tier silently disabled), so asserting the real value FAILS pre-fix and
    PASSES after the fix."""
    from persistence.database import get_tenant_session

    # Use the genuine autobegin-ing session — this is the path that raised pre-fix.
    monkeypatch.setattr(rl, "_get_tenant_session", get_tenant_session)
    rl._team_limit_cache.clear()

    tid = str(uuid.uuid4())
    team = str(uuid.uuid4())
    async with routing_policy(tenant_id=tid, team_id=team, team_rpm_limit=5):
        limit = await rl._fetch_team_rpm_limit_from_db(tid, team)

    assert limit == 5


async def test_team_rpm_fails_open_on_db_connectivity_error(monkeypatch):
    """Vector 2b: a genuine DB-connectivity error → deliberate fail-open
    (limit=None), and is NOT cached so recovery is immediate. Pre-fix cached the
    None → the no-cache assertion discriminates."""

    @asynccontextmanager
    async def _boom(_tid):
        raise _op_error()
        yield  # pragma: no cover

    monkeypatch.setattr(rl, "_get_tenant_session", _boom)
    rl._team_limit_cache.clear()

    tid, team = "t-conn", "team-conn"
    limit = await rl._fetch_team_rpm_limit_from_db(tid, team)

    assert limit is None
    assert (tid, team) not in rl._team_limit_cache  # not cached on connectivity error


async def test_team_rpm_logic_error_propagates(monkeypatch):
    """Vector 2 (R1 add-on): a non-connectivity (begin()-class) error must
    PROPAGATE, not be swallowed. Pre-fix the broad except caught it → returned None
    (no raise) → this FAILS; post-fix the narrowed except lets it raise."""

    @asynccontextmanager
    async def _boom(_tid):
        raise InvalidRequestError("a transaction is already begun on this Session")
        yield  # pragma: no cover

    monkeypatch.setattr(rl, "_get_tenant_session", _boom)
    rl._team_limit_cache.clear()

    with pytest.raises(InvalidRequestError):
        await rl._fetch_team_rpm_limit_from_db("t-logic", "team-logic")


async def test_team_rpm_fails_open_on_db_pool_timeout(monkeypatch):
    """Vector 2c (reviewer High): a connection-pool checkout timeout
    (sqlalchemy.exc.TimeoutError — a direct SQLAlchemyError subclass, NOT a
    DBAPIError) is also a connectivity-class failure → deliberate fail-open (None),
    not cached, never blocks. Without it in the except set it would propagate to a
    request-blocking 500."""
    from sqlalchemy.exc import TimeoutError as SATimeoutError

    @asynccontextmanager
    async def _boom(_tid):
        raise SATimeoutError("QueuePool limit of size 5 overflow 10 reached, connection timed out")
        yield  # pragma: no cover

    monkeypatch.setattr(rl, "_get_tenant_session", _boom)
    rl._team_limit_cache.clear()
    tid, team = "t-pool", "team-pool"
    limit = await rl._fetch_team_rpm_limit_from_db(tid, team)
    assert limit is None
    assert (tid, team) not in rl._team_limit_cache  # not cached on a pool-timeout either


@pytest.mark.parametrize(
    "exc",
    [ConnectionRefusedError("connection refused"), TimeoutError("command timed out")],
    ids=["connection_refused", "builtin_timeout"],
)
async def test_team_rpm_fails_open_on_raw_oserror(monkeypatch, exc):
    """Vector 2d (audit High): a DOWN Postgres surfaces as a builtin
    ConnectionRefusedError (an OSError), and a command_timeout as the builtin
    TimeoutError (also OSError) — neither is a SQLAlchemy wrapper class. Both are the
    dominant real connectivity failures and MUST fail open (None, not cached), never
    propagate to a request-blocking 500. (The original narrow set missed these.)"""

    @asynccontextmanager
    async def _boom(_tid):
        raise exc
        yield  # pragma: no cover

    monkeypatch.setattr(rl, "_get_tenant_session", _boom)
    rl._team_limit_cache.clear()
    tid, team = "t-os", "team-os"
    limit = await rl._fetch_team_rpm_limit_from_db(tid, team)
    assert limit is None
    assert (tid, team) not in rl._team_limit_cache
