"""Pydantic v2 models for the Anoryx-Sentinel build-fleet orchestrator.

These models are the shared vocabulary between the conductor (run loop),
the quartermaster (budget/ledger), and the worktree manager.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TaskClass(str, Enum):
    """Work category — drives model/budget allocation in the quartermaster."""

    explore = "explore"
    implement = "implement"
    review = "review"
    security = "security"
    architecture = "architecture"


class TaskStatus(str, Enum):
    """Lifecycle state of a single fleet task."""

    pending = "pending"
    running = "running"
    review = "review"
    rework = "rework"
    pr_ready = "pr_ready"
    human_escalation = "human_escalation"
    done = "done"


class Task(BaseModel):
    """A single unit of work dispatched to one builder agent."""

    id: str
    title: str
    description: str
    klass: TaskClass
    builder_agent: str
    phase: int = 0
    depends_on: list[str] = Field(default_factory=list)
    status: TaskStatus = TaskStatus.pending
    retry_count: int = 0
    worktree_path: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class LedgerRow(BaseModel):
    """One accounting row per agent run, appended to ledger.jsonl.

    est_cost_usd is derived from the Agent SDK ResultMessage.total_cost_usd,
    which is a CLIENT-SIDE estimate computed from a bundled price table. Use
    https://platform.claude.com/docs/en/build-with-claude/usage-cost-api for
    authoritative billing.
    """

    task_id: str
    phase: int
    agent: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_creation_tokens: int = 0
    est_cost_usd: float | None = None
    verdict: str = "pending"
    retries: int = 0
    ts: datetime = Field(default_factory=_utcnow)


class AgentVerdict(BaseModel):
    """Structured verdict parsed from an oversight agent's JSON output."""

    agent_name: str
    verdict: str
    findings: list[str] = Field(default_factory=list)
    raw: dict = Field(default_factory=dict)
