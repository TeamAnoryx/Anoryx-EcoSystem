"""Git worktree management for isolated, parallel fleet tasks.

Each task runs in its own worktree at <repo-root>/worktrees/<task_id> on a
branch task/<task_id>. Worktrees live at the monorepo root even though the
orchestrator process runs from Anoryx-Sentinel/, so all git invocations are
anchored to the monorepo root explicitly.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

# orchestrator/ -> Anoryx-Sentinel/ -> monorepo root
_MONOREPO_ROOT = Path(__file__).resolve().parents[2]

# At monorepo root (anchored absolute so the path resolves regardless of cwd).
WORKTREES_DIR = _MONOREPO_ROOT / "worktrees"


def _git(*args: str, cwd: Path = _MONOREPO_ROOT) -> subprocess.CompletedProcess[str]:
    """Run a git command, surfacing git's real stderr on failure.

    subprocess's check=True raises a bare CalledProcessError that hides git's
    actual message. Instead we check returncode ourselves and raise a
    RuntimeError carrying both streams, so a worktree failure prints what git
    actually said (e.g. "fatal: a branch named 'task/F-001' already exists").
    """
    result = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed (exit {result.returncode}):\n"
            f"stdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result


def make_worktree(task_id: str) -> Path:
    """Create worktrees/<task_id> on a fresh branch task/<task_id>; return its path."""
    target = WORKTREES_DIR / task_id
    _git("worktree", "add", str(target), "-b", f"task/{task_id}")
    return target


def remove_worktree(task_id: str) -> None:
    """Tear down the worktree and delete its branch. Best-effort on the branch."""
    target = WORKTREES_DIR / task_id
    _git("worktree", "remove", str(target), "--force")
    # Branch deletion is separate; a missing branch must not raise.
    subprocess.run(
        ["git", "branch", "-D", f"task/{task_id}"],
        cwd=str(_MONOREPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )


def get_diff(worktree_path: Path) -> str:
    """Return `git diff main...HEAD` for the given worktree."""
    result = _git("-C", str(worktree_path), "diff", "main...HEAD")
    return result.stdout
