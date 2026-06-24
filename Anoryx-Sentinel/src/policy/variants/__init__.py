"""Typed views over the three validated policy variants (ADR-0009 §6).

These are Pydantic views over data that has ALREADY passed Draft 2020-12
validation (schema_validator) — they are NOT the validation gate (R6) and contain
no `eval`/`exec`; variants are data, not code. They give enforcement typed access
to the variant-specific fields stored in a policy row's policy_payload.

Each view uses ConfigDict(extra="ignore") DELIBERATELY: it is constructed from the
FULL stored record (the policies.policy_payload JSON), which carries common fields
(signature, the four IDs, effective_from, etc.) the variant view does not model.
extra="forbid" would reject those common fields and break enforcement; the closed
schema (additionalProperties:false) was already enforced at intake, so no unknown
field can reach storage in the first place.
"""

from __future__ import annotations

from typing import Any

from policy.variants.allowlist import ModelAllowlistPolicy
from policy.variants.budget import BudgetLimitPolicy
from policy.variants.denylist import ModelDenylistPolicy
from policy.variants.model_approval import ModelApprovalPolicy

__all__ = [
    "BudgetLimitPolicy",
    "ModelAllowlistPolicy",
    "ModelApprovalPolicy",
    "ModelDenylistPolicy",
    "parse_variant",
]

_VIEW_BY_TYPE = {
    "budget_limit": BudgetLimitPolicy,
    "model_allowlist": ModelAllowlistPolicy,
    "model_denylist": ModelDenylistPolicy,
    "model_approval": ModelApprovalPolicy,
}


def parse_variant(
    payload: dict[str, Any],
) -> BudgetLimitPolicy | ModelAllowlistPolicy | ModelDenylistPolicy | ModelApprovalPolicy:
    """Build the typed view for a validated policy payload (dispatched on policy_type)."""
    policy_type = payload.get("policy_type")
    view = _VIEW_BY_TYPE.get(policy_type)
    if view is None:
        raise ValueError(f"unknown policy_type: {policy_type!r}")
    return view(**payload)
