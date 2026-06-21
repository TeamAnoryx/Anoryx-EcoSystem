"""F-015 policy-reuse threat model — vector 13 (ADR-0018 §11).

A policy violation in the batch path is blocked AND audited. The real F-008 model
policy decision is exercised at process_file's call site (the wiring under test);
the decision function is stubbed to ModelDeny so the test does not depend on the
F-008 policy-store fixtures (F-008's own suite proves the decision logic). The
audit append (policy_decision_deny) and the batch_file_blocked outcome are real.
"""

from __future__ import annotations

import os
import re

import pytest
from sqlalchemy import text as sql_text
from sqlalchemy.ext.asyncio import create_async_engine

from bulk.queue import JobMessage
from bulk.repositories.batch_repository import BatchRepository
from bulk.worker import process_job

pytestmark = pytest.mark.integration


def _deps(storage):
    from gateway.config import get_settings
    from orchestration.config import get_orchestration_settings
    from orchestration.registry import build_default_registry

    return {
        "storage": storage,
        "hook_registry": build_default_registry(),
        "gateway_settings": get_settings(),
        "orch_settings": get_orchestration_settings(),
    }


async def _count_events(*, event_type: str, request_id: str) -> int:
    raw = os.environ.get("DATABASE_URL", "")
    url = re.sub(r"^postgresql(\+psycopg)?://", "postgresql+asyncpg://", raw)
    engine = create_async_engine(
        url, connect_args={"server_settings": {"app.session_kind": "privileged"}}
    )
    try:
        async with engine.connect() as conn:
            return int(
                (
                    await conn.execute(
                        sql_text(
                            "SELECT count(*) FROM events_audit_log "
                            "WHERE event_type = :et AND request_id = :rid"
                        ),
                        {"et": event_type, "rid": request_id},
                    )
                ).scalar_one()
            )
    finally:
        await engine.dispose()


async def test_policy_violation_in_batch_blocked_and_audited(
    seed_batch,
    tenant_session_factory,
    stub_storage,
    test_tenant_id,
    monkeypatch,
    cleanup_bulk_after,
):
    import uuid

    from policy.enforcement import ModelDeny

    async def _deny(session, scope, model):
        return ModelDeny(policy_id="p-deny", reason="model_denied")

    monkeypatch.setattr("policy.enforcement.evaluate_model_policies", _deny)

    batch_id, files = await seed_batch(test_tenant_id, object_count=1, model="gpt-denied")
    fid, key = files[0]
    stub_storage.content[key] = b"benign text destined for a denied model."

    job = JobMessage(
        batch_id=batch_id,
        file_id=fid,
        tenant_id=test_tenant_id,
        team_id=str(uuid.uuid4()),
        project_id=str(uuid.uuid4()),
        agent_id="bulk-test",
        object_key=key,
        idempotency_key="seed-K",
        model="gpt-denied",
    )
    result = await process_job(job, **_deps(stub_storage))
    assert result == "blocked"

    make = tenant_session_factory(test_tenant_id)
    async with make() as s:
        bf = await BatchRepository(s).get_file(fid)
        assert bf.status == "blocked" and bf.outcome == "blocked"

    # The F-008 denial is audited (policy_decision_deny) AND the batch lifecycle
    # block is audited (batch_file_blocked). Both keyed to this file's request_id.
    assert await _count_events(event_type="policy_decision_deny", request_id=fid) >= 1
    assert await _count_events(event_type="batch_file_blocked", request_id=fid) >= 1
