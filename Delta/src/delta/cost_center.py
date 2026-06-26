"""Cost centers and projects (Fork 1a: cost center IS a Sentinel team_id).

D-001 introduces no Delta-native org hierarchy. A ``CostCenter`` is a thin,
named view over a Sentinel ``team_id``; a ``Project`` is a named view over a
Sentinel ``project_id`` (with its owning ``team_id``). Both are tenant-scoped.
A department/org-tree overlay is deferred to D-013+ and would map *over* these
ids without reshaping any cost record.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

from .identifiers import ProjectId, TeamId, TenantId

_NAME_MAX_LENGTH = 256
EntityName = Annotated[str, StringConstraints(min_length=1, max_length=_NAME_MAX_LENGTH)]


class CostCenter(BaseModel):
    """A named cost center. ``cost_center_id`` is, by decision, a Sentinel team_id."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cost_center_id: TeamId  # == Sentinel team_id (Fork 1a)
    tenant_id: TenantId
    name: EntityName


class Project(BaseModel):
    """A named project. ``project_id`` is a Sentinel project_id, owned by a team."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    project_id: ProjectId
    team_id: TeamId
    tenant_id: TenantId
    name: EntityName
