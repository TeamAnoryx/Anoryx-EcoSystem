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
import sys
from pathlib import Path

import yaml

from . import conductor
from .models import Task, TaskStatus

_SENTINEL_ROOT = Path(__file__).resolve().parents[1]
_MONOREPO_ROOT = _SENTINEL_ROOT.parent
_TASKS_PATH = _SENTINEL_ROOT / "orchestrator" / "tasks.yaml"

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


def load_tasks(path: Path = _TASKS_PATH) -> list[Task]:
    """Parse tasks.yaml into validated Task models."""
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [Task(**raw) for raw in data.get("tasks", [])]


def ready_tasks(tasks: list[Task], done_ids: set[str]) -> list[Task]:
    """Tasks whose dependencies are all satisfied and that are still pending."""
    return [
        t
        for t in tasks
        if t.status == TaskStatus.pending and set(t.depends_on) <= done_ids
    ]


async def _run_one(task: Task) -> tuple[str, TaskStatus]:
    status = await conductor.run_task(task)
    return task.id, status


async def run(selected: str | None = None, dry_run: bool = False) -> None:
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
            print(f"  {t.id}  [{t.klass.value}] -> {t.builder_agent}  "
                  f"model={model} ceiling={ceiling}")
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
    args = parser.parse_args()
    asyncio.run(run(selected=args.task, dry_run=args.dry_run))


if __name__ == "__main__":
    main()
