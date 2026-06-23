"""F-018 shadow-AI attribution — non-forgeable grouping key (ADR-0021 §6, R4).

Attribution is derived ONLY from the server-stamped fields on a raw
`shadow_ai_detected_outbound` audit row: `team_id` and `project_id` were resolved
from the verified virtual-key identity at egress time (never from a client header
or request body) and `selected_provider` was resolved from the outbound host.

Agent-level attribution is intentionally NOT available: the raw event's envelope
`agent_id` is the EMITTING component slug ("defense"), not the offending agent
(ADR-0007 D8 / ADR-0021 §1.1). F-018 attributes to team + project only.
"""

from __future__ import annotations

from typing import Any

# A group key uniquely identifies one candidate within a tenant:
# (team_id, project_id, endpoint, provider).
AttributionKey = tuple[str, str, str, str]


def attribution_key(row: Any) -> AttributionKey:
    """Return the non-forgeable attribution key for a raw egress row.

    Reads ONLY server-stamped row columns — `team_id`, `project_id`,
    `detected_endpoint`, `selected_provider`. A caller-supplied team/agent claim
    cannot reach these columns (they are written by the audit layer from the
    resolved tenant context), so it can never change attribution (R4, vector 2).
    """
    return (
        row.team_id,
        row.project_id,
        row.detected_endpoint or "",
        row.selected_provider or "",
    )
