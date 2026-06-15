"""Git worktree management for isolated, parallel fleet tasks.

Each task runs in its own worktree at <repo-root>/worktrees/<task_id> on a
branch task/<task_id>. Worktrees live at the monorepo root even though the
orchestrator process runs from Anoryx-Sentinel/, so all git invocations are
anchored to the monorepo root explicitly.
"""

from __future__ import annotations

import shutil
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


def _branch_exists(task_id: str) -> bool:
    """True if local branch task/<task_id> exists. Never raises."""
    result = subprocess.run(
        ["git", "show-ref", "--verify", "--quiet", f"refs/heads/task/{task_id}"],
        cwd=str(_MONOREPO_ROOT),
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def _cleanup_stale(task_id: str) -> None:
    """Force-remove any leftover worktree, branch, or metadata from a prior run.

    Every step is best-effort: a wedged-but-partial state from a crashed run
    must never block a fresh `git worktree add`. Nothing here raises.
    """
    target = WORKTREES_DIR / task_id

    # 1. Worktree directory: try a clean git removal, else force-delete the dir.
    if target.exists():
        try:
            _git("worktree", "remove", str(target), "--force")
        except Exception:
            shutil.rmtree(target, ignore_errors=True)

    # Drop dangling worktree registrations regardless of the above.
    try:
        _git("worktree", "prune")
    except Exception:
        pass

    # 2. Stale branch.
    if _branch_exists(task_id):
        try:
            _git("branch", "-D", f"task/{task_id}")
        except Exception:
            pass

    # 3. Lingering .git/worktrees/<task_id> metadata dir.
    meta = _MONOREPO_ROOT / ".git" / "worktrees" / task_id
    if meta.exists():
        shutil.rmtree(meta, ignore_errors=True)


def make_worktree(task_id: str) -> Path:
    """Create worktrees/<task_id> on branch task/<task_id>; return its path.

    Idempotent / self-healing: any leftover worktree, branch, or metadata from
    a prior crashed run is force-removed first, so a rerun never collides with
    `fatal: a branch named 'task/<id>' already exists`. The final add uses the
    hardened _git so a genuine failure still surfaces git's real stderr.
    """
    target = WORKTREES_DIR / task_id
    _cleanup_stale(task_id)
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
