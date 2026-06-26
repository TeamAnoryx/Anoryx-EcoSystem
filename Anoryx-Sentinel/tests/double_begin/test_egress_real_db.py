"""F-007-FU: F-018 shadow-AI egress double-begin fail-open (ADR-0026).

Vectors:
  3  bind_egress_context REALLY resolves the allow-list via a real autobegin-ing
     get_tenant_session (non-stubbed; FAILS on pre-fix code where begin() raised →
     monitor dark).
  4  a non-connectivity (begin()-class) error PROPAGATES out of bind_egress_context
     (the narrowed except must not swallow it).
  4b a genuine DB-connectivity error FLAGS rather than going dark — binds an EMPTY
     allow-list so every tracked egress is flagged (pre-fix had no handler → the
     error propagated with no bind).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.exc import OperationalError

import gateway.middleware.egress_monitor as em
from gateway.context import TenantContext, current_egress_context

_TC = TenantContext(
    tenant_id="t-egress",
    team_id="tm",
    project_id="p",
    agent_id="gateway-core",
    virtual_key_id="k",
)


@pytest.fixture(autouse=True)
def _clear_ctx():
    current_egress_context.set(None)
    yield
    current_egress_context.set(None)


def _op_error() -> OperationalError:
    return OperationalError("SELECT allowed_providers", {}, Exception("connection refused"))


async def test_egress_monitor_resolves_committed_allowlist(routing_policy):
    """Vector 3 (non-stubbed): bind_egress_context resolves the tenant's allow-list
    via the genuine autobegin session. Pre-fix begin() raised (monitor dark), so
    asserting the bound allow-list FAILS pre-fix and PASSES after the fix."""
    tid = str(uuid.uuid4())
    tc = TenantContext(
        tenant_id=tid,
        team_id=str(uuid.uuid4()),
        project_id=str(uuid.uuid4()),
        agent_id="gateway-core",
        virtual_key_id=str(uuid.uuid4()),
    )
    async with routing_policy(tenant_id=tid, allowed_providers="openai"):
        await em.bind_egress_context(tc, "req-real")

    ctx = current_egress_context.get()
    assert ctx is not None
    assert ctx.allowed_providers == ("openai",)


async def test_egress_binds_empty_allowlist_on_db_connectivity_error(monkeypatch):
    """Vector 4b: on a genuine DB-connectivity error the monitor FLAGS rather than
    going dark — it binds an EMPTY allow-list so every tracked egress is flagged.
    Pre-fix bind_egress_context had no handler → the error propagated (no bind) →
    this FAILS; post-fix it binds empty."""

    async def _boom(_tc):
        raise _op_error()

    monkeypatch.setattr(em, "_resolve_allowed_providers", _boom)
    await em.bind_egress_context(_TC, "req-conn")

    ctx = current_egress_context.get()
    assert ctx is not None
    assert ctx.allowed_providers == ()  # flag-all


async def test_egress_logic_error_propagates(monkeypatch):
    """Vector 4 (R1 add-on): a non-connectivity (begin()-class) error must PROPAGATE
    out of bind_egress_context — the narrowed except must not swallow a logic defect
    into a silently dark monitor."""

    async def _boom(_tc):
        raise ValueError("simulated logic defect")

    monkeypatch.setattr(em, "_resolve_allowed_providers", _boom)
    with pytest.raises(ValueError):
        await em.bind_egress_context(_TC, "req-logic")


async def test_egress_binds_empty_allowlist_on_db_pool_timeout(monkeypatch):
    """Vector 4c (reviewer High): a connection-pool checkout timeout
    (sqlalchemy.exc.TimeoutError) is also a connectivity-class failure → flag-empty
    (never dark, never block). Without it in the except set it would propagate to a
    request-blocking 500, violating F-018 detect-only / ADR-0021 never-block."""
    from sqlalchemy.exc import TimeoutError as SATimeoutError

    async def _boom(_tc):
        raise SATimeoutError("QueuePool limit of size 5 overflow 10 reached, connection timed out")

    monkeypatch.setattr(em, "_resolve_allowed_providers", _boom)
    await em.bind_egress_context(_TC, "req-pool")

    ctx = current_egress_context.get()
    assert ctx is not None
    assert ctx.allowed_providers == ()  # flag-all


@pytest.mark.parametrize(
    "exc",
    [ConnectionRefusedError("connection refused"), TimeoutError("command timed out")],
    ids=["connection_refused", "builtin_timeout"],
)
async def test_egress_binds_empty_allowlist_on_raw_oserror(monkeypatch, exc):
    """Vector 4d (audit High): a DOWN Postgres (builtin ConnectionRefusedError, an
    OSError) or a command_timeout (builtin TimeoutError, also OSError) MUST flag-empty,
    never propagate to a request-blocking 500 — F-018 detect-only / ADR-0021
    never-block. (The original narrow set missed these → the monitor 500-blocked every
    request during a DB outage.)"""

    async def _boom(_tc):
        raise exc

    monkeypatch.setattr(em, "_resolve_allowed_providers", _boom)
    await em.bind_egress_context(_TC, "req-os")

    ctx = current_egress_context.get()
    assert ctx is not None
    assert ctx.allowed_providers == ()  # flag-all
