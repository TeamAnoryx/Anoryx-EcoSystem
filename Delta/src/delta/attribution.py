"""Attribution to Sentinel identity + the BudgetConcept -> budget_limit builder.

``Attribution`` is the four-ID key Delta shares with every Sentinel event/record
(Fork 1a). ``budget_concept_to_policy_payload`` is the producer side of the
CONFIRM: it serializes a :class:`delta.budget.BudgetConcept` into a dict that
conforms to Sentinel's LOCKED ``BudgetLimitPolicy`` variant with no schema change.
The policy envelope fields (``policy_id`` ... ``signature``) are NOT part of the
domain concept — they are supplied by the caller (D-002 at emit time); D-001's
builder takes them as arguments so the round-trip test can stitch a complete,
schema-valid record.

Cost is emitted as an **integer** (``limit_cost_cents``); an integer is a valid
JSON ``number`` for the wire ``max_cost_cents_per_period`` field, so the locked
schema does not move.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict

from .budget import BudgetConcept
from .identifiers import AgentId, ProjectId, TeamId, TenantId

_POLICY_TYPE_BUDGET_LIMIT = "budget_limit"
# Locked-schema envelope bounds (mirror policy.schema.json so the builder never emits
# a record it already knows the LOCKED schema rejects).
_MAX_POLICY_VERSION = 9007199254740991  # 2**53-1, JS Number.MAX_SAFE_INTEGER
_MIN_SIGNATURE_LENGTH = 16
_COMPACT_JWS = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


class Attribution(BaseModel):
    """The four Sentinel stable IDs every Delta cost is attributed to."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tenant_id: TenantId
    team_id: TeamId
    project_id: ProjectId
    agent_id: AgentId


def _to_rfc3339_utc(value: datetime) -> str:
    """Serialize an aware datetime to an RFC 3339 UTC string (the wire format)."""
    if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
        raise ValueError("effective_from must be timezone-aware (UTC)")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def budget_concept_to_policy_payload(
    concept: BudgetConcept,
    *,
    policy_id: str,
    policy_version: int,
    effective_from: datetime,
    signature: str,
) -> dict[str, Any]:
    """Build a ``budget_limit`` policy record from a ``BudgetConcept`` + envelope.

    The result conforms to ``policy.schema.json`` ``BudgetLimitPolicy``. Only the
    limit fields that are set are included, matching the schema ``anyOf`` (and the
    BudgetConcept's own at-least-one-of invariant guarantees one is present).
    """
    if not 1 <= policy_version <= _MAX_POLICY_VERSION:
        # Locked schema bounds policy_version to [1, 2**53-1] (replay/rollback defense
        # + JSON Number safety). Don't emit a record the contract will reject.
        raise ValueError("policy_version must be in [1, 2**53-1] (locked schema bounds)")
    if len(signature) < _MIN_SIGNATURE_LENGTH or not _COMPACT_JWS.match(signature):
        raise ValueError("signature must be compact JWS (three base64url segments, >=16 chars)")
    payload: dict[str, Any] = {
        "policy_type": _POLICY_TYPE_BUDGET_LIMIT,
        "tenant_id": concept.tenant_id,
        "team_id": concept.team_id,
        "project_id": concept.project_id,
        "agent_id": concept.agent_id,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "effective_from": _to_rfc3339_utc(effective_from),
        "signature": signature,
        "period": concept.period.value,
        "scope": concept.scope.value,
    }
    if concept.limit_tokens is not None:
        payload["max_tokens_per_period"] = concept.limit_tokens
    if concept.limit_cost_cents is not None:
        # Integer cents -> a valid JSON `number`; the locked schema stays frozen.
        payload["max_cost_cents_per_period"] = concept.limit_cost_cents
    return payload
