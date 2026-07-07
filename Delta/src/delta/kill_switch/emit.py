"""Build the byte-valid ``budget_limit`` kill/clear payloads (ADR-0006 §3.5).

Reuses the D-002 emit path (``attribution.budget_concept_to_policy_payload``) unchanged —
the SAME vehicle D-005 uses — so both payloads validate against the UNMODIFIED locked
``policy.schema.json`` with no schema change and no new ``policy_type``. This mirrors the
schema's own documented pattern for a full block ("set budget_limit to zero"). The
placeholder signature is replaced at drain time by :func:`delta.policy.sign.sign_policy_record`
(see ``budget_engine/emit.py`` — identical mechanism, reused verbatim in spirit here).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..attribution import budget_concept_to_policy_payload
from ..budget import BudgetConcept, BudgetPeriod, BudgetScope
from ..money import MAX_BUDGET_COST_CENTS, MAX_BUDGET_TOKENS

# Shape-valid placeholder (three base64url segments, >= 16 chars) accepted by the D-002
# emit guard. Replaced by the real signature at drain time; never transmitted.
_PLACEHOLDER_SIGNATURE = "AAAAAAAAAAAA.BBBBBBBBBBBB.CCCCCCCCCCCC"

# The wire schema requires a `period`, but a kill/clear record's effect does not depend on
# it (a zero cap blocks in every period bucket; a max cap blocks in none) — a fixed value
# keeps both records for the same policy_id byte-comparable except for the caps/version.
_KILL_SWITCH_PERIOD = BudgetPeriod.DAILY


def _kill_switch_concept(
    *,
    tenant_id: str,
    team_id: str,
    project_id: str,
    agent_id: str,
    limit_tokens: int,
    limit_cost_cents: int,
) -> BudgetConcept:
    return BudgetConcept(
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        agent_id=agent_id,
        scope=BudgetScope.AGENT,
        period=_KILL_SWITCH_PERIOD,
        limit_tokens=limit_tokens,
        limit_cost_cents=limit_cost_cents,
    )


def build_kill_payload(
    *,
    tenant_id: str,
    team_id: str,
    project_id: str,
    agent_id: str,
    policy_id: str,
    policy_version: int,
    effective_from: datetime,
) -> dict[str, Any]:
    """A ``budget_limit`` record with BOTH caps zeroed — an unconditional hard block."""
    concept = _kill_switch_concept(
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        agent_id=agent_id,
        limit_tokens=0,
        limit_cost_cents=0,
    )
    return budget_concept_to_policy_payload(
        concept,
        policy_id=policy_id,
        policy_version=policy_version,
        effective_from=effective_from,
        signature=_PLACEHOLDER_SIGNATURE,
    )


def build_clear_payload(
    *,
    tenant_id: str,
    team_id: str,
    project_id: str,
    agent_id: str,
    policy_id: str,
    policy_version: int,
    effective_from: datetime,
) -> dict[str, Any]:
    """The SAME ``policy_id`` at a bumped version, caps at the locked-schema maxima.

    Lifts ONLY the kill-switch's own restriction (a different, real D-005 budget for the
    same scope, if any, keeps enforcing independently under its own policy_id).
    """
    concept = _kill_switch_concept(
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        agent_id=agent_id,
        limit_tokens=MAX_BUDGET_TOKENS,
        limit_cost_cents=MAX_BUDGET_COST_CENTS,
    )
    return budget_concept_to_policy_payload(
        concept,
        policy_id=policy_id,
        policy_version=policy_version,
        effective_from=effective_from,
        signature=_PLACEHOLDER_SIGNATURE,
    )
