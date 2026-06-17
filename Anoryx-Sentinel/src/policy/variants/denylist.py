"""ModelDenylistPolicy typed view + deny-precedence helper (ADR-0009 §6).

Per-scope deny-list of model_ids. DENY TAKES PRECEDENCE over ALLOW at enforcement
time (contract §ModelDenylistPolicy): if any matching deny-list forbids the model,
the request is denied regardless of any allow-list.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ModelDenylistPolicy(BaseModel):
    """Typed view of a validated model_denylist policy payload."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    policy_id: str
    tenant_id: str
    team_id: str
    project_id: str
    agent_id: str
    policy_version: int
    denied_model_ids: list[str]
    reason: str

    def is_denied(self, model_id: str) -> bool:
        return model_id in self.denied_model_ids
