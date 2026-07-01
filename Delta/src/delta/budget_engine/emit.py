"""Build the byte-valid ``budget_limit`` payload from a budget definition (ADR-0005 §4).

Reuses the D-002 emit path (``attribution.budget_concept_to_policy_payload``) unchanged, so
the payload validates against the UNMODIFIED locked ``policy.schema.json`` with no schema
change and no new ``policy_type``. The payload is built with a SHAPE-valid PLACEHOLDER
signature (the emit guard requires a compact-JWS-shaped string); the real ES256 signature
is produced at drain time by :func:`delta.policy.sign.sign_policy_record`, which overwrites
``signature`` and hashes the body MINUS ``signature`` — so the placeholder never affects the
final signed bytes. Warnings are dropped by the emit path (CONFIRM B).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..attribution import budget_concept_to_policy_payload
from .definitions import BudgetDefinition

# Shape-valid placeholder (three base64url segments, >= 16 chars) accepted by the D-002
# emit guard. Replaced by the real signature at drain time; never transmitted.
_PLACEHOLDER_SIGNATURE = "AAAAAAAAAAAA.BBBBBBBBBBBB.CCCCCCCCCCCC"


def build_policy_payload(
    budget: BudgetDefinition, *, policy_version: int, effective_from: datetime
) -> dict[str, Any]:
    """Build the locked ``budget_limit`` record (placeholder signature) for this budget."""
    return budget_concept_to_policy_payload(
        budget.to_concept(),
        policy_id=budget.policy_id,
        policy_version=policy_version,
        effective_from=effective_from,
        signature=_PLACEHOLDER_SIGNATURE,
    )
