"""Entry point for the build fleet.

Reads orchestrator/tasks.yaml, resolves which tasks are ready (all dependencies
satisfied), and dispatches them to the conductor. Independent tasks run
concurrently via asyncio.gather.

Run from the Anoryx-Sentinel/ directory:
    cd Anoryx-Sentinel && python -m orchestrator.run [--task F-001] [--dry-run]
"""

from __future__ import annotations

import argparse
import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path

import yaml

from . import conductor
from .models import Task, TaskStatus

_SENTINEL_ROOT = Path(__file__).resolve().parents[1]
_MONOREPO_ROOT = _SENTINEL_ROOT.parent
_TASKS_PATH = _SENTINEL_ROOT / "orchestrator" / "tasks.yaml"

# Isolate the fleet's harness config from Claude Code's interactive config.
# The SDK spawns the `claude` CLI, which loads hooks + settings from
# CLAUDE_CONFIG_DIR. Pointing it at .claude-fleet gives the fleet its full
# five-hook chain (the root .claude/ keeps only interactive guardrails).
# Set at import time so it is in os.environ before any query() subprocess.
_FLEET_CONFIG_DIR = (_SENTINEL_ROOT / ".claude-fleet").resolve()
os.environ["CLAUDE_CONFIG_DIR"] = str(_FLEET_CONFIG_DIR)
print(
    f"[orchestrator] CLAUDE_CONFIG_DIR = {os.environ.get('CLAUDE_CONFIG_DIR')}",
    flush=True,
)

# Auth: the fleet runs on a long-lived Claude Code OAuth token (Max
# subscription), minted with `claude setup-token` and read by the CLI the SDK
# spawns. The conductor already forwards os.environ to each subprocess, so the
# token only needs to be present in this process's environment.
_AUTH_ENV_VAR = "CLAUDE_CODE_OAUTH_TOKEN"


def _load_root_dotenv() -> None:
    """Load VAR=value lines from <repo-root>/.env into os.environ (no override).

    The root .env is gitignored and hook-protected; secrets never live in a
    subproject folder or in git. A missing .env is fine — the var may already
    be exported in the environment.
    """
    env_path = _MONOREPO_ROOT / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _require_auth() -> None:
    """Fail fast (before any API spend) if the OAuth token is absent."""
    if os.environ.get(_AUTH_ENV_VAR):
        return
    sys.exit(
        f"ERROR: {_AUTH_ENV_VAR} is not set. The fleet authenticates with a "
        "long-lived Claude Code OAuth token (Max subscription).\n"
        "Generate one:   claude setup-token\n"
        f"Then put it in <repo-root>/.env as {_AUTH_ENV_VAR}=... "
        "(gitignored), or export it, before running."
    )


def _clean_all() -> None:
    """Nuclear reset: remove every task worktree + branch, then prune.

    Recovery path when state gets wedged by a crashed run:
        python -m orchestrator.run --task F-001 --clean
    Every step is best-effort and the actions taken are printed.
    """
    root = _MONOREPO_ROOT

    # Collect task/* branches up front (before we start deleting).
    res = subprocess.run(
        ["git", "branch", "--list", "task/*", "--format=%(refname:short)"],
        cwd=str(root),
        capture_output=True,
        text=True,
    )
    branches = [b.strip() for b in res.stdout.splitlines() if b.strip()]

    # Remove every worktrees/* directory (git removal first, then force-rm).
    removed_worktrees: list[str] = []
    worktrees_dir = root / "worktrees"
    if worktrees_dir.exists():
        for child in sorted(worktrees_dir.iterdir()):
            if not child.is_dir():
                continue
            subprocess.run(
                ["git", "worktree", "remove", str(child), "--force"],
                cwd=str(root),
                capture_output=True,
                text=True,
            )
            if child.exists():
                shutil.rmtree(child, ignore_errors=True)
            removed_worktrees.append(child.name)

    subprocess.run(["git", "worktree", "prune"], cwd=str(root), capture_output=True, text=True)

    # Delete the task/* branches.
    removed_branches: list[str] = []
    for branch in branches:
        subprocess.run(
            ["git", "branch", "-D", branch],
            cwd=str(root),
            capture_output=True,
            text=True,
        )
        removed_branches.append(branch)

    print(f"[--clean] worktrees removed: {removed_worktrees or 'none'}")
    print(f"[--clean] branches deleted:  {removed_branches or 'none'}")


def load_tasks(path: Path = _TASKS_PATH) -> list[Task]:
    """Parse tasks.yaml into validated Task models."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [Task(**raw) for raw in data.get("tasks", [])]


def ready_tasks(tasks: list[Task], done_ids: set[str]) -> list[Task]:
    """Tasks whose dependencies are all satisfied and that are still pending."""
    return [t for t in tasks if t.status == TaskStatus.pending and set(t.depends_on) <= done_ids]


async def _run_one(task: Task) -> tuple[str, TaskStatus]:
    status = await conductor.run_task(task)
    return task.id, status


async def run(selected: str | None = None, dry_run: bool = False, clean: bool = False) -> None:
    if clean:
        _clean_all()  # nuclear reset before anything else
    _load_root_dotenv()
    if not dry_run:
        _require_auth()  # fail before any worktree/API work if auth is missing
    tasks = load_tasks()
    if selected:
        tasks = [t for t in tasks if t.id == selected]
        if not tasks:
            print(f"No task with id {selected!r} in tasks.yaml")
            return

    done_ids: set[str] = set()
    batch = ready_tasks(tasks, done_ids)

    if dry_run:
        print("DRY RUN — ready tasks (dependencies satisfied):")
        for t in batch:
            model, ceiling = conductor.quartermaster.allocate(t)
            print(
                f"  {t.id}  [{t.klass.value}] -> {t.builder_agent}  "
                f"model={model} ceiling={ceiling}"
            )
        remaining = [t for t in tasks if t not in batch]
        for t in remaining:
            print(f"  (blocked) {t.id} waits on {t.depends_on}")
        return

    # Dispatch each independent ready task concurrently.
    results = await asyncio.gather(*(_run_one(t) for t in batch))
    for task_id, status in results:
        print(f"{task_id}: {status.value}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Anoryx-Sentinel build fleet runner")
    parser.add_argument("--task", help="Run only this task id (e.g. F-001)")
    parser.add_argument("--dry-run", action="store_true", help="Show the plan, run nothing")
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Nuclear reset: remove all task worktrees + branches before running",
    )
    args = parser.parse_args()
    asyncio.run(run(selected=args.task, dry_run=args.dry_run, clean=args.clean))


if __name__ == "__main__":
    main()
