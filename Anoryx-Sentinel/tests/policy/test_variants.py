"""Variant views + enforcement matching (ADR-0009 §4, §6, §10).

Pure logic (wildcard match, deny-precedence, specificity, budget evaluation,
period bucketing) plus DB-backed loaders (active-policy fetch, period usage sum).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

from persistence.repositories.audit_log_repository import AuditLogRepository
from persistence.repositories.policy_repository import PolicyRepository
from policy.constants import WILDCARD_AGENT, WILDCARD_UUID
from policy.enforcement import (
    BudgetExceeded,
    BudgetOk,
    ModelAllow,
    ModelDeny,
    RequestScope,
    budget_matches_scope,
    budget_period_used,
    evaluate_budget_against,
    evaluate_model_policies,
    model_matches_scope,
    model_specificity,
    period_start,
    resolve_model_decision,
)
from policy.variants import (
    BudgetLimitPolicy,
    ModelAllowlistPolicy,
    ModelDenylistPolicy,
    parse_variant,
)

# --------------------------------------------------------------------------- #
# View / parse
# --------------------------------------------------------------------------- #


def test_parse_variant_dispatch(make_budget_record, make_allowlist_record, make_denylist_record):
    assert isinstance(parse_variant(make_budget_record()), BudgetLimitPolicy)
    assert isinstance(parse_variant(make_allowlist_record()), ModelAllowlistPolicy)
    assert isinstance(parse_variant(make_denylist_record()), ModelDenylistPolicy)


def test_views_ignore_extra_fields(make_denylist_record):
    # The full signed record (with signature, effective_from, etc.) parses cleanly.
    view = ModelDenylistPolicy(**make_denylist_record(signature="x" * 20))
    assert view.is_denied("gpt-4")
    assert not view.is_denied("gpt-4o")


# --------------------------------------------------------------------------- #
# Model matching / resolution (pure)
# --------------------------------------------------------------------------- #


def _allow(model_ids, *, team=None, project=None, agent=None, version=1, pid=None):
    return ModelAllowlistPolicy(
        policy_id=pid or str(uuid.uuid4()),
        tenant_id="t",
        team_id=team or WILDCARD_UUID,
        project_id=project or WILDCARD_UUID,
        agent_id=agent or WILDCARD_AGENT,
        policy_version=version,
        allowed_model_ids=model_ids,
    )


def _deny(model_ids, *, team=None, project=None, agent=None, pid=None):
    return ModelDenylistPolicy(
        policy_id=pid or str(uuid.uuid4()),
        tenant_id="t",
        team_id=team or WILDCARD_UUID,
        project_id=project or WILDCARD_UUID,
        agent_id=agent or WILDCARD_AGENT,
        policy_version=1,
        denied_model_ids=model_ids,
        reason="test",
    )


_SCOPE = RequestScope(tenant_id="t", team_id="tm", project_id="pr", agent_id="gateway-core")


def test_deny_precedence_over_allow():
    decision = resolve_model_decision([_allow(["gpt-4"])], [_deny(["gpt-4"])], "gpt-4")
    assert isinstance(decision, ModelDeny)
    assert decision.reason == "model_denied"


def test_no_allowlist_is_not_constrained():
    assert isinstance(resolve_model_decision([], [], "anything"), ModelAllow)


def test_model_not_in_allowlist_denied():
    decision = resolve_model_decision([_allow(["gpt-4o"])], [], "gpt-4")
    assert isinstance(decision, ModelDeny)
    assert decision.reason == "model_not_in_allowlist"


def test_most_specific_allowlist_wins():
    broad = _allow(["broad-model"])  # all wildcards -> specificity 0
    specific = _allow(["specific-model"], team="tm", project="pr", agent="gateway-core")  # 3
    # The specific allow-list is chosen; it does NOT contain "broad-model".
    decision = resolve_model_decision([broad, specific], [], "broad-model")
    assert isinstance(decision, ModelDeny)
    assert decision.policy_id == specific.policy_id
    # ...and it DOES permit its own model.
    assert isinstance(resolve_model_decision([broad, specific], [], "specific-model"), ModelAllow)


def test_wildcard_match_and_specificity():
    assert model_matches_scope(_deny(["x"]), _SCOPE)  # all wildcards match
    assert model_matches_scope(_deny(["x"], team="tm"), _SCOPE)  # exact team matches
    assert not model_matches_scope(_deny(["x"], team="other"), _SCOPE)  # wrong team
    assert model_specificity(_allow(["x"])) == 0
    assert model_specificity(_allow(["x"], team="tm", project="pr")) == 2


# --------------------------------------------------------------------------- #
# Budget matching / evaluation (pure)
# --------------------------------------------------------------------------- #


def _budget(scope_level, *, tokens=None, cost=None, team="tm", project="pr", agent="gateway-core"):
    return BudgetLimitPolicy(
        policy_id=str(uuid.uuid4()),
        tenant_id="t",
        team_id=team,
        project_id=project,
        agent_id=agent,
        policy_version=1,
        period="daily",
        scope=scope_level,
        max_tokens_per_period=tokens,
        max_cost_cents_per_period=cost,
    )


def test_budget_matches_by_scope_field():
    # tenant-scope budget matches regardless of the budget row's team/project/agent.
    assert budget_matches_scope(_budget("tenant", team="other"), _SCOPE)
    # team-scope budget requires the team to match.
    assert budget_matches_scope(_budget("team", team="tm"), _SCOPE)
    assert not budget_matches_scope(_budget("team", team="other"), _SCOPE)


def test_evaluate_budget_against_tokens_and_cost():
    tok_budget = _budget("tenant", tokens=1000)
    assert isinstance(evaluate_budget_against([(tok_budget, 900, 0.0)], 50, 0.0), BudgetOk)
    over = evaluate_budget_against([(tok_budget, 990, 0.0)], 50, 0.0)
    assert isinstance(over, BudgetExceeded) and over.reason == "budget_tokens_exceeded"

    cost_budget = _budget("tenant", cost=100.0)
    over_cost = evaluate_budget_against([(cost_budget, 0, 99.0)], 0, 5.0)
    assert isinstance(over_cost, BudgetExceeded) and over_cost.reason == "budget_cost_exceeded"


def test_period_start_truncation():
    now = datetime(2026, 6, 17, 12, 34, 56, tzinfo=UTC)
    assert period_start("hourly", now) == datetime(2026, 6, 17, 12, 0, 0, tzinfo=UTC)
    assert period_start("daily", now) == datetime(2026, 6, 17, 0, 0, 0, tzinfo=UTC)
    assert period_start("monthly", now) == datetime(2026, 6, 1, 0, 0, 0, tzinfo=UTC)


# --------------------------------------------------------------------------- #
# DB-backed
# --------------------------------------------------------------------------- #


async def _persist_policy(session, payload, *, effective_from=None):
    repo = PolicyRepository(session)
    await repo.save_new_version(
        policy_id=payload["policy_id"],
        policy_type=payload["policy_type"],
        policy_version=payload["policy_version"],
        tenant_id=payload["tenant_id"],
        team_id=payload["team_id"],
        project_id=payload["project_id"],
        agent_id=payload["agent_id"],
        effective_from=effective_from or datetime(2026, 1, 1, tzinfo=UTC),
        signature="aaaaaaaa.bbbbbbbb.cccccccc",
        policy_payload=payload,
    )


def _usage_event(tenant, team, project, agent, ts_iso, tokens):
    return {
        "event_type": "usage",
        "tenant_id": tenant,
        "team_id": team,
        "project_id": project,
        "agent_id": agent,
        "event_id": str(uuid.uuid4()),
        "event_timestamp": ts_iso,
        "request_id": "req-" + uuid.uuid4().hex[:8],
        "model": "gpt-4o",
        "tokens_in": tokens,
        "tokens_out": 0,
        "latency_ms": 5,
        "cost_estimate_cents": 1.0,
    }


@pytest.mark.asyncio
async def test_get_active_policies_for_scope_filters(
    priv_session, seeded_tenant, make_denylist_record
):
    active = make_denylist_record(tenant_id=seeded_tenant)
    future = make_denylist_record(tenant_id=seeded_tenant)
    await _persist_policy(priv_session, active, effective_from=datetime(2026, 1, 1, tzinfo=UTC))
    await _persist_policy(priv_session, future, effective_from=datetime(2030, 1, 1, tzinfo=UTC))

    repo = PolicyRepository(priv_session)
    rows = await repo.get_active_policies_for_scope(
        seeded_tenant, "model_denylist", now=datetime(2026, 6, 17, tzinfo=UTC)
    )
    ids = {r.policy_id for r in rows}
    assert active["policy_id"] in ids
    assert future["policy_id"] not in ids  # not yet effective
    # Wrong type returns nothing.
    assert await repo.get_active_policies_for_scope(seeded_tenant, "budget_limit") == []


@pytest.mark.asyncio
async def test_budget_period_used_buckets_by_period(priv_session):
    tenant = str(uuid.uuid4())  # events_audit_log has no FK on tenant_id
    scope = RequestScope(tenant_id=tenant, team_id="tm", project_id="pr", agent_id="gateway-core")
    audit = AuditLogRepository(priv_session)
    await audit.append(
        _usage_event(tenant, "tm", "pr", "gateway-core", "2026-06-17T08:00:00Z", 100)
    )
    await audit.append(
        _usage_event(tenant, "tm", "pr", "gateway-core", "2026-06-15T08:00:00Z", 999)
    )

    budget = _budget("tenant")
    now = datetime(2026, 6, 17, 12, 0, 0, tzinfo=UTC)
    used_tokens, _used_cost = await budget_period_used(priv_session, scope, budget, now=now)
    assert used_tokens == 100  # only the same-day event counts (daily bucket)


@pytest.mark.asyncio
async def test_expired_allowlist_not_enforced(priv_session, seeded_tenant, make_allowlist_record):
    """An allow-list past its effective_until expiry stops constraining (contract)."""
    scope = RequestScope(
        tenant_id=seeded_tenant,
        team_id=str(uuid.uuid4()),
        project_id=str(uuid.uuid4()),
        agent_id="gateway-core",
    )
    common = dict(
        tenant_id=seeded_tenant,
        team_id=scope.team_id,
        project_id=scope.project_id,
        agent_id="gateway-core",
    )
    now = datetime(2026, 6, 17, tzinfo=UTC)
    # Allow-list permitting ONLY gpt-4o, but EXPIRED on 2026-06-01.
    await _persist_policy(
        priv_session,
        make_allowlist_record(
            allowed_model_ids=["gpt-4o"], effective_until="2026-06-01T00:00:00Z", **common
        ),
    )
    # gpt-4 is not permitted by that list, but it is expired -> not enforced -> allowed.
    assert isinstance(
        await evaluate_model_policies(priv_session, scope, "gpt-4", now=now), ModelAllow
    )

    # A NON-expired allow-list excluding gpt-4 denies it.
    await _persist_policy(
        priv_session,
        make_allowlist_record(
            allowed_model_ids=["gpt-4o"], effective_until="2027-01-01T00:00:00Z", **common
        ),
    )
    decision = await evaluate_model_policies(priv_session, scope, "gpt-4", now=now)
    assert isinstance(decision, ModelDeny)
    assert decision.reason == "model_not_in_allowlist"


@pytest.mark.asyncio
async def test_evaluate_model_policies_deny_end_to_end(
    priv_session, seeded_tenant, make_denylist_record
):
    scope = RequestScope(
        tenant_id=seeded_tenant,
        team_id=str(uuid.uuid4()),
        project_id=str(uuid.uuid4()),
        agent_id="gateway-core",
    )
    payload = make_denylist_record(
        tenant_id=seeded_tenant,
        team_id=scope.team_id,
        project_id=scope.project_id,
        agent_id="gateway-core",
        denied_model_ids=["gpt-4"],
    )
    await _persist_policy(priv_session, payload)

    decision = await evaluate_model_policies(priv_session, scope, "gpt-4")
    assert isinstance(decision, ModelDeny)
    assert decision.reason == "model_denied"
    # A non-denied model is not constrained (no allow-list present).
    assert isinstance(await evaluate_model_policies(priv_session, scope, "gpt-4o"), ModelAllow)
