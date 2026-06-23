"""F-018 shadow-AI detection — domain model (ADR-0021 §5/§6)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class Candidate:
    """A reviewable shadow-AI candidate — NOT a verdict (R3).

    `team_id`, `project_id`, and `provider` are copied verbatim from the
    server-stamped fields on the raw `shadow_ai_detected_outbound` rows, so the
    attribution is non-forgeable (R4): no value here ever originates from caller
    input. `endpoint` is host/path metadata only (R7) — never request/response body.
    """

    tenant_id: str
    team_id: str
    project_id: str
    endpoint: str
    provider: str
    call_count: int
    first_seen: str
    last_seen: str
    confidence_band: Literal["low", "medium", "high"]
    fired_signals: tuple[str, ...]
    candidate_key: str
    label: str = "candidate"


@dataclass(frozen=True)
class CandidateReport:
    """The result of a candidates analysis run for one tenant.

    `disclaimer` is the honesty boundary (R1); it is always present, even when
    `candidates` is empty.
    """

    candidates: tuple[Candidate, ...]
    disclaimer: str
