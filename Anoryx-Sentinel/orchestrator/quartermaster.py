"""Budget allocation and token/cost ledger for the build fleet.

Maps each TaskClass to a (model, token_ceiling) pair, records every agent run
to ledger.jsonl, and decides when a run has blown its budget.

Field access on ResultMessage follows the Claude Agent SDK: ResultMessage is a
dataclass with `.usage` (a dict), `.total_cost_usd` (float | None), and
`.model_usage`.
"""

from __future__ import annotations

from pathlib import Path

from claude_agent_sdk import ResultMessage

from .models import LedgerRow, Task, TaskClass

# orchestrator/ -> Anoryx-Sentinel/
_SENTINEL_ROOT = Path(__file__).resolve().parents[1]
_LEDGER_PATH = _SENTINEL_ROOT / "orchestrator" / "ledger.jsonl"

# TaskClass -> (model_string, token_ceiling). Model strings are intentional
# per-tier choices set by the fleet operator; do not auto-upgrade them.
BUDGET_MAP: dict[TaskClass, tuple[str, int]] = {
    TaskClass.explore: ("claude-haiku-4-5-20251001", 40_000),
    TaskClass.implement: ("claude-sonnet-4-6", 120_000),
    TaskClass.review: ("claude-sonnet-4-6", 60_000),
    TaskClass.security: ("claude-opus-4-6", 90_000),
    TaskClass.architecture: ("claude-opus-4-6", 120_000),
}

BUDGET_OVERAGE_FACTOR = 1.5


def allocate(task: Task) -> tuple[str, int]:
    """Return the (model, token_ceiling) allocated for this task's class."""
    return BUDGET_MAP[task.klass]


def _usage_tokens(result: ResultMessage) -> dict[str, int]:
    """Pull the four token counts off a ResultMessage.usage dict, defaulting 0."""
    usage = result.usage or {}
    return {
        "input_tokens": int(usage.get("input_tokens", 0)),
        "output_tokens": int(usage.get("output_tokens", 0)),
        "cache_read_tokens": int(usage.get("cache_read_input_tokens", 0)),
        "cache_creation_tokens": int(usage.get("cache_creation_input_tokens", 0)),
    }


def record(task: Task, result: ResultMessage, attempt: int, verdict: str) -> LedgerRow:
    """Build a LedgerRow from a run and append it as one JSON line to ledger.jsonl."""
    model, _ = allocate(task)
    tokens = _usage_tokens(result)
    row = LedgerRow(
        task_id=task.id,
        phase=task.phase,
        agent=task.builder_agent,
        model=model,
        est_cost_usd=result.total_cost_usd,
        verdict=verdict,
        retries=attempt,
        **tokens,
    )
    _LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _LEDGER_PATH.open("a", encoding="utf-8") as fh:
        fh.write(row.model_dump_json() + "\n")
    return row


def is_over_budget(result: ResultMessage, ceiling: int) -> bool:
    """True when input+output tokens exceed ceiling * BUDGET_OVERAGE_FACTOR.

    Cache tokens are excluded — they are billed at a reduced rate and do not
    reflect the agent doing genuinely more work.
    """
    tokens = _usage_tokens(result)
    spent = tokens["input_tokens"] + tokens["output_tokens"]
    return spent > int(ceiling * BUDGET_OVERAGE_FACTOR)
