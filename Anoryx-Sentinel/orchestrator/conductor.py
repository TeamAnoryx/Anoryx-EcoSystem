"""The conductor: drives one task through the build → oversight → gate loop.

Builders and oversight agents are invoked with the Claude Agent SDK `query()`
function. Each agent is defined as a markdown file under <root>/.claude/agents/;
its frontmatter (description, tools, model) plus body (system prompt) are loaded
into an AgentDefinition and passed via the `agents` parameter. cwd is set to the
task's worktree so file operations land in the isolated checkout.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import yaml
from claude_agent_sdk import (
    AgentDefinition,
    ClaudeAgentOptions,
    ResultMessage,
    query,
)

from . import quartermaster, worktree
from .models import Task, TaskStatus

RETRY_CEILING = 3

# orchestrator/ -> Anoryx-Sentinel/ -> monorepo root
_MONOREPO_ROOT = Path(__file__).resolve().parents[2]
_AGENTS_DIR = _MONOREPO_ROOT / ".claude" / "agents"

# Tools the harness auto-approves at the top query() level. "Agent" must be
# present so subagent invocations do not block on a permission prompt.
_ALLOWED_TOOLS = ["Read", "Write", "Edit", "Bash", "Grep", "Glob", "Agent"]

# Same ledger the quartermaster writes successful runs to; SDK failures land
# here too so a crashed run leaves a durable forensic row before it propagates.
_LEDGER_PATH = Path(__file__).resolve().parent / "ledger.jsonl"


def _log_sdk_failure(agent_name: str, task_id: str | None, exc: Exception) -> None:
    """Append a failed-run row to ledger.jsonl. Never raises (logging must not
    mask the original SDK exception)."""
    row = {
        "event": "sdk_failure",
        "agent": agent_name,
        "task_id": task_id,
        "error": repr(exc),
    }
    try:
        _LEDGER_PATH.parent.mkdir(parents=True, exist_ok=True)
        with _LEDGER_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# Agent loading + invocation
# --------------------------------------------------------------------------- #
def _load_agent_definition(name: str) -> AgentDefinition:
    """Parse .claude/agents/<name>.md frontmatter + body into an AgentDefinition."""
    path = _AGENTS_DIR / f"{name}.md"
    text = path.read_text(encoding="utf-8")

    frontmatter: dict = {}
    body = text
    if text.startswith("---"):
        _, fm_block, body = text.split("---", 2)
        frontmatter = yaml.safe_load(fm_block) or {}

    tools_field = frontmatter.get("tools")
    if isinstance(tools_field, str):
        tools = [t.strip() for t in tools_field.split(",") if t.strip()]
    elif isinstance(tools_field, list):
        tools = tools_field
    else:
        tools = None

    return AgentDefinition(
        description=str(frontmatter.get("description", name)).strip(),
        prompt=body.strip(),
        tools=tools,
        model=frontmatter.get("model"),
    )


async def query_agent(
    name: str,
    prompt: str,
    model: str | None = None,
    cwd: str | None = None,
    task_id: str | None = None,
) -> ResultMessage | None:
    """Run a single agent via the Agent SDK and return its ResultMessage.

    `name` must match a file in .claude/agents/. `model` overrides the agent's
    declared model. `cwd` sets the working directory (the task worktree).
    `task_id` is used only for failure-logging context.

    Any exception from the SDK is logged to ledger.jsonl as a failed-run row,
    then re-raised with the agent + task context attached, so a crash inside
    one agent is never swallowed silently.
    """
    agent_def = _load_agent_definition(name)
    if model:
        agent_def = replace(agent_def, model=model)  # immutable update

    options = ClaudeAgentOptions(
        cwd=cwd,
        model=model,
        allowed_tools=_ALLOWED_TOOLS,
        agents={name: agent_def},
        permission_mode="acceptEdits",
        # Surface the active agent name to the protect-paths hook, which gates
        # contracts/ edits on identity that Claude Code's hook payload omits.
        env={**os.environ, "ANORYX_ACTIVE_AGENT": name},
    )

    result: ResultMessage | None = None
    try:
        async for message in query(
            prompt=f"Use the {name} agent to: {prompt}",
            options=options,
        ):
            if isinstance(message, ResultMessage):
                result = message
    except Exception as exc:
        _log_sdk_failure(name, task_id, exc)
        raise RuntimeError(
            f"SDK call to {name} for {task_id or '<no-task>'} failed: {exc}"
        ) from exc
    return result


# --------------------------------------------------------------------------- #
# Verdict parsing
# --------------------------------------------------------------------------- #
def _result_text(result: ResultMessage | None) -> str:
    return getattr(result, "result", "") or "" if result else ""


def _extract_json(text: str) -> dict:
    """Best-effort: pull the first JSON object out of an agent's result text."""
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return {}
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return {}


def _review_approved(result: ResultMessage | None) -> bool:
    return _extract_json(_result_text(result)).get("verdict") == "APPROVE"


def _has_high_or_critical(result: ResultMessage | None) -> bool:
    findings = _extract_json(_result_text(result)).get("findings", [])
    severities = {str(f.get("severity", "")).lower() for f in findings if isinstance(f, dict)}
    return bool(severities & {"high", "critical"})


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def build_builder_prompt(task: Task, context_result: ResultMessage | None, attempt: int) -> str:
    context = _result_text(context_result)
    return (
        f"Implement: {task.description}\n\n"
        f"Context pack:\n{context}\n\n"
        f"Attempt {attempt} of {RETRY_CEILING}.\n"
        "Work in Anoryx-Sentinel/src/. Conform exactly to "
        "Anoryx-Sentinel/contracts/openapi.yaml. Write tests in "
        "Anoryx-Sentinel/tests/. Do not stop until tests pass."
    )


def run_ci(worktree_path: Path) -> bool:
    """Run pytest inside the worktree's Anoryx-Sentinel package. True if green.

    A non-zero exit is a normal gate signal (tests failed) rather than a harness
    error, so this returns a bool instead of raising — but it surfaces pytest's
    captured stdout+stderr to this process's stderr so the *reason* for red is
    never silently swallowed.
    """
    proc = subprocess.run(
        ["pytest", "-q"],
        cwd=str(worktree_path / "Anoryx-Sentinel"),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        sys.stderr.write(
            f"[run_ci] pytest failed (exit {proc.returncode}) in {worktree_path}:\n"
            f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}\n"
        )
    return proc.returncode == 0


def aggregate_verdicts(
    review: ResultMessage | None,
    security: ResultMessage | None,
    ci_ok: bool,
    perf: ResultMessage | None,
) -> str:
    """Assemble the oversight bundle that pr-gate aggregates into a final verdict."""
    return json.dumps(
        {
            "code_reviewer_verdict": _extract_json(_result_text(review)),
            "security_auditor_verdict": _extract_json(_result_text(security)),
            "test_engineer_verdict": {"ci_passed": ci_ok},
            "perf_load_verdict": _extract_json(_result_text(perf)) if perf else None,
            "ci_status": "passed" if ci_ok else "failed",
        }
    )


def escalate_to_human(task: Task, verdict: ResultMessage | None) -> None:
    print(f"⛔ HUMAN ESCALATION required for task {task.id} ({task.title})")
    findings = _extract_json(_result_text(verdict)).get("findings", [])
    for finding in findings:
        print(f"  - {finding}")


def open_github_pr(worktree_path: Path, task: Task) -> None:
    """Push the task branch and open a DRAFT PR for human review.

    The conductor (harness) opens the PR as a handoff; it never merges. Only a
    human merges to main. Failures here are non-fatal — the branch still exists.

    Gated on ANORYX_PUSH=1. Default (unset) does NOT touch the remote — it just
    reports the READY handoff so a local run never pushes to the shared repo.
    """
    if os.environ.get("ANORYX_PUSH") != "1":
        print(
            f"[push disabled] gate READY for {task.id}. Set ANORYX_PUSH=1 to push "
            f"branch task/{task.id} + open a draft PR. Review worktree: {worktree_path}"
        )
        return

    branch = f"task/{task.id}"
    push = subprocess.run(
        ["git", "-C", str(worktree_path), "push", "-u", "origin", branch],
        capture_output=True,
        text=True,
        check=False,
    )
    if push.returncode != 0:
        # Non-fatal: the branch still exists locally for a human to push.
        print(
            f"[open_github_pr] push of {branch} failed (exit {push.returncode}): "
            f"{push.stderr.strip()}"
        )
        return

    pr = subprocess.run(
        [
            "gh",
            "pr",
            "create",
            "--draft",
            "--base",
            "main",
            "--head",
            branch,
            "--title",
            f"{task.id}: {task.title}",
            "--body",
            "Automated fleet build. ready-for-human-review. Do not auto-merge.",
        ],
        cwd=str(worktree_path),
        capture_output=True,
        text=True,
        check=False,
    )
    if pr.returncode != 0:
        print(
            f"[open_github_pr] gh pr create for {branch} failed "
            f"(exit {pr.returncode}): {pr.stderr.strip()}"
        )


# --------------------------------------------------------------------------- #
# Main loop
# --------------------------------------------------------------------------- #
async def run_task(task: Task) -> TaskStatus:
    """Drive one task: context -> build/review loop -> gate. Returns final status."""
    wt = worktree.make_worktree(task.id)
    task.worktree_path = str(wt)
    cwd = str(wt)

    model, ceiling = quartermaster.allocate(task)

    # 1. Context pack from the cartographer (read-only).
    context_result = await query_agent("cartographer", task.description, cwd=cwd, task_id=task.id)

    review: ResultMessage | None = None
    security: ResultMessage | None = None
    ci_ok = False

    for attempt in range(1, RETRY_CEILING + 1):
        builder_result = await query_agent(
            task.builder_agent,
            build_builder_prompt(task, context_result, attempt),
            model=model,
            cwd=cwd,
            task_id=task.id,
        )
        quartermaster.record(task, builder_result, attempt, "pending")

        if builder_result and quartermaster.is_over_budget(builder_result, ceiling):
            await query_agent(
                "bench-coach",
                f"Task {task.id} exceeded its token budget on attempt {attempt}. "
                "Recommend an action.",
                task_id=task.id,
            )
            return TaskStatus.human_escalation

        diff = worktree.get_diff(wt)
        review = await query_agent(
            "code-reviewer", diff, model="claude-sonnet-4-6", cwd=cwd, task_id=task.id
        )
        security = await query_agent(
            "security-auditor", diff, model="claude-opus-4-6", cwd=cwd, task_id=task.id
        )

        if _has_high_or_critical(security):
            escalate_to_human(task, security)
            return TaskStatus.human_escalation

        ci_ok = run_ci(wt)
        if _review_approved(review) and ci_ok:
            break
        # else: loop again; the next builder prompt re-reads the diff/findings.

    # 4. Optional perf gate, then aggregate and ask pr-gate for the call.
    perf: ResultMessage | None = None
    diff = worktree.get_diff(wt)
    if "src/gateway/" in diff or "src/bulk/" in diff:
        perf = await query_agent("perf-load-engineer", diff, cwd=cwd, task_id=task.id)

    gate_input = aggregate_verdicts(review, security, ci_ok, perf)
    gate = await query_agent("pr-gate", gate_input, cwd=cwd, task_id=task.id)
    gate_verdict = _extract_json(_result_text(gate)).get("gate_verdict")

    if gate_verdict == "READY":
        open_github_pr(wt, task)
        return TaskStatus.pr_ready

    # Loop exhausted or gate withheld -> flag the builder and escalate.
    await query_agent(
        "bench-coach",
        f"Task {task.id} did not reach a READY gate within {RETRY_CEILING} attempts.",
        task_id=task.id,
    )
    escalate_to_human(task, gate)
    return TaskStatus.human_escalation
