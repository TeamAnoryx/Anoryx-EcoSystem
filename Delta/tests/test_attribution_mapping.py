"""Attribution carrier + the BudgetConcept -> budget_limit payload builder (vector 7)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from delta.attribution import Attribution, budget_concept_to_policy_payload
from delta.budget import BudgetConcept, BudgetPeriod, BudgetScope

_T = "12121212-1212-4212-8212-121212121212"
_TEAM = "13131313-1313-4313-8313-131313131313"
_PROJ = "14141414-1414-4414-8414-141414141414"
_POLICY = "1a1a1a1a-1a1a-4a1a-8a1a-1a1a1a1a1a1a"
_SIG = "aaaaaaaaaaaa.bbbbbbbbbbbb.cccccccccccc"  # syntactically-valid compact-JWS fixture
_EFF = datetime(2026, 6, 26, 0, 0, 0, tzinfo=timezone.utc)


def _concept(**over) -> BudgetConcept:
    base = dict(
        tenant_id=_T,
        team_id=_TEAM,
        project_id=_PROJ,
        agent_id="gateway-core",
        scope=BudgetScope.TEAM,
        period=BudgetPeriod.MONTHLY,
        limit_cost_cents=500000,
    )
    base.update(over)
    return BudgetConcept(**base)


def test_budget_concept_requires_a_limit_at_model_level():
    # The at-least-one-of invariant rejects a budget that limits nothing.
    with pytest.raises(ValidationError, match="at least one"):
        BudgetConcept(
            tenant_id=_T,
            team_id=_TEAM,
            project_id=_PROJ,
            agent_id="gateway-core",
            scope=BudgetScope.TEAM,
            period=BudgetPeriod.MONTHLY,
        )


def test_attribution_valid():
    a = Attribution(tenant_id=_T, team_id=_TEAM, project_id=_PROJ, agent_id="gateway-core")
    assert a.tenant_id == _T


def test_attribution_rejects_extra():
    with pytest.raises(ValidationError):
        Attribution(
            tenant_id=_T, team_id=_TEAM, project_id=_PROJ, agent_id="gateway-core", dept="x"
        )


def test_attribution_rejects_bad_tenant():
    with pytest.raises(ValidationError):
        Attribution(
            tenant_id="not-a-uuid", team_id=_TEAM, project_id=_PROJ, agent_id="gateway-core"
        )


def test_attribution_rejects_bad_agent_slug():
    with pytest.raises(ValidationError):
        Attribution(tenant_id=_T, team_id=_TEAM, project_id=_PROJ, agent_id="Gateway Core")


@pytest.mark.parametrize(
    "bad",
    [
        "12121212121242128212121212121212",  # no dashes (uuid.UUID would accept)
        "{12121212-1212-4212-8212-121212121212}",  # braces
        "urn:uuid:12121212-1212-4212-8212-121212121212",  # urn form
    ],
)
def test_attribution_rejects_noncanonical_uuid(bad):
    # M-1: only the canonical dashed UUID is accepted, matching the wire format:uuid.
    with pytest.raises(ValidationError):
        Attribution(tenant_id=bad, team_id=_TEAM, project_id=_PROJ, agent_id="gateway-core")


def test_builder_carries_concept_ids():
    payload = budget_concept_to_policy_payload(
        _concept(), policy_id=_POLICY, policy_version=3, effective_from=_EFF, signature=_SIG
    )
    assert payload["policy_type"] == "budget_limit"
    assert payload["tenant_id"] == _T
    assert payload["team_id"] == _TEAM
    assert payload["project_id"] == _PROJ
    assert payload["agent_id"] == "gateway-core"
    assert payload["scope"] == "team"
    assert payload["period"] == "monthly"
    assert payload["policy_version"] == 3
    assert payload["effective_from"] == "2026-06-26T00:00:00Z"


def test_builder_includes_only_set_limits():
    cost_only = budget_concept_to_policy_payload(
        _concept(limit_tokens=None, limit_cost_cents=500000),
        policy_id=_POLICY,
        policy_version=1,
        effective_from=_EFF,
        signature=_SIG,
    )
    assert "max_cost_cents_per_period" in cost_only
    assert "max_tokens_per_period" not in cost_only

    tokens_only = budget_concept_to_policy_payload(
        _concept(limit_tokens=1000, limit_cost_cents=None),
        policy_id=_POLICY,
        policy_version=1,
        effective_from=_EFF,
        signature=_SIG,
    )
    assert tokens_only["max_tokens_per_period"] == 1000
    assert "max_cost_cents_per_period" not in tokens_only


def test_builder_cost_is_integer():
    payload = budget_concept_to_policy_payload(
        _concept(limit_cost_cents=500000),
        policy_id=_POLICY,
        policy_version=1,
        effective_from=_EFF,
        signature=_SIG,
    )
    # Vector 1 at the boundary: Delta emits integer cents, never a float.
    assert isinstance(payload["max_cost_cents_per_period"], int)


def test_builder_rejects_zero_policy_version():
    # Locked schema requires policy_version >= 1 (replay/rollback defense).
    with pytest.raises(ValueError, match="policy_version"):
        budget_concept_to_policy_payload(
            _concept(), policy_id=_POLICY, policy_version=0, effective_from=_EFF, signature=_SIG
        )


def test_builder_rejects_overlarge_policy_version():
    # L-4: above the locked schema's 2**53-1 bound.
    with pytest.raises(ValueError, match="policy_version"):
        budget_concept_to_policy_payload(
            _concept(),
            policy_id=_POLICY,
            policy_version=10**18,
            effective_from=_EFF,
            signature=_SIG,
        )


def test_builder_rejects_bad_signature():
    # L-4: not a compact-JWS shape -> rejected before emit (locked schema would reject).
    with pytest.raises(ValueError, match="signature"):
        budget_concept_to_policy_payload(
            _concept(), policy_id=_POLICY, policy_version=1, effective_from=_EFF, signature="short"
        )


def test_builder_rejects_naive_effective_from():
    with pytest.raises(ValueError, match="timezone-aware"):
        budget_concept_to_policy_payload(
            _concept(),
            policy_id=_POLICY,
            policy_version=1,
            effective_from=datetime(2026, 6, 26, 0, 0, 0),
            signature=_SIG,
        )
