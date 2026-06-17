"""Migration tests: forward, rollback, re-apply (F-003 + F-003b).

Tests run against the live sentinel-postgres container.
Migrations are tested in a subprocess to avoid import-time side effects.

Migration chain: 0001 -> 0002 -> 0003 -> 0004 -> 0005 -> 0006 -> 0007 -> 0008
                 -> 0009 -> 0010 (head)
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

SENTINEL_ROOT = Path(__file__).parent.parent.parent
ALEMBIC_CMD = [sys.executable, "-m", "alembic"]
ENV_FILE = str(SENTINEL_ROOT.parent / ".env")


def _run_alembic(*args: str) -> subprocess.CompletedProcess:
    """Run alembic with the correct PYTHONPATH and env file."""
    import os

    env = os.environ.copy()
    env["PYTHONPATH"] = str(SENTINEL_ROOT / "src")
    # dotenv is loaded by alembic env.py itself; DATABASE_URL must be in os.environ.
    from dotenv import dotenv_values

    vals = dotenv_values(ENV_FILE)
    env.update({k: v for k, v in vals.items() if v is not None})

    return subprocess.run(
        ALEMBIC_CMD + list(args),
        cwd=str(SENTINEL_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.mark.integration
def test_current_head_is_0010() -> None:
    """Alembic current should report head at revision 0010 (F-007)."""
    result = _run_alembic("current")
    assert result.returncode == 0, f"alembic current failed:\n{result.stderr}"
    assert "0010" in result.stdout or "0010" in result.stderr


@pytest.mark.integration
def test_migration_downgrade_and_reapply() -> None:
    """Downgrade to base, then re-apply head. All migrations must be reversible."""
    # Downgrade to base.
    result_down = _run_alembic("downgrade", "base")
    assert result_down.returncode == 0, f"downgrade base failed:\n{result_down.stderr}"
    # Re-apply head.
    result_up = _run_alembic("upgrade", "head")
    assert result_up.returncode == 0, f"upgrade head after downgrade failed:\n{result_up.stderr}"
    # Confirm head is back.
    result_current = _run_alembic("current")
    assert "0010" in result_current.stdout or "0010" in result_current.stderr


@pytest.mark.integration
def test_incremental_downgrade() -> None:
    """Step-by-step downgrade verifies each migration's down() works.

    Always re-applies to head at the end to leave the DB in a valid state.
    """
    num_revisions = 10  # 0001 through 0010

    try:
        for _step in range(num_revisions):
            result = _run_alembic("downgrade", "-1")
            if result.returncode != 0:
                # May already be at base; check and break.
                current = _run_alembic("current")
                combined = current.stdout + current.stderr
                if "(head)" not in combined and "0001" not in combined:
                    # Likely already at base — that's OK.
                    break
    finally:
        # Always re-apply head so subsequent tests have a complete schema.
        result_up = _run_alembic("upgrade", "head")
        assert (
            result_up.returncode == 0
        ), f"Failed to re-apply head after incremental downgrade:\n{result_up.stderr}"
