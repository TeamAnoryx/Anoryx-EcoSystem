"""ModelAllowlistPolicy typed view (ADR-0009 §6).

Per-scope allow-list of model_ids. At enforcement time the highest-specificity
matching allow-list applies; a request for a model NOT in that allow-list is
denied. Absence of any matching allow-list means the request is not
allow-constrained (model policies are opt-in).
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ModelAllowlistPolicy(BaseModel):
    """Typed view of a validated model_allowlist policy payload."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    policy_id: str
    tenant_id: str
    team_id: str
    project_id: str
    agent_id: str
    policy_version: int
    allowed_model_ids: list[str]
    effective_until: str | None = None

    def is_allowed(self, model_id: str) -> bool:
        return model_id in self.allowed_model_ids
