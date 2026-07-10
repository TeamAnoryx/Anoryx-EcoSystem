"""Migration reversibility tests (F-018, ADR-0021 §11).

Vector covered:
  9  test_migration_reversible — alembic upgrade head then downgrade -1
     round-trips cleanly across migration 0024.

DB-GATED: skips when DATABASE_URL not set or Postgres unreachable.
Mirrors the pattern in tests/persistence/test_migrations.py.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from dotenv import dotenv_values, load_dotenv

_ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")
load_dotenv(dotenv_path=_ENV_PATH)

_SENTINEL_ROOT = Path(__file__).parent.parent.parent
_ALEMBIC_CMD = [sys.executable, "-m", "alembic"]


def _db_available() -> bool:
    return bool(os.environ.get("DATABASE_URL"))


def _run_alembic(*args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(_SENTINEL_ROOT / "src")
    vals = dotenv_values(_ENV_PATH)
    env.update({k: v for k, v in vals.items() if v is not None})
    return subprocess.run(
        _ALEMBIC_CMD + list(args),
        cwd=str(_SENTINEL_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.mark.asyncio
async def test_migration_reversible():
    """Vector 9: 0024 upgrade/downgrade/-1 round-trip is clean.

    Approach:
      1. Ensure head is at 0024.
      2. Downgrade -1 (back to 0023).
      3. Upgrade head (back to 0024).
      4. Confirm head = 0024.

    This mirrors persistence/test_migrations.py::test_incremental_downgrade but
    scoped to the single 0024 step.
    """
    if not _db_available():
        pytest.skip("DATABASE_URL not set — skipping migration reversibility test")

    # Step 1: bring the DB to 0024. 0024 is no longer the head (F-019 added
    # 0025-0027), and `alembic upgrade <rev>` only moves FORWARD — so go to head
    # first, then DOWNGRADE to 0024. Keeps this F-018 0024<->0023 reversibility test
    # correct regardless of later migrations.
    result = _run_alembic("upgrade", "head")
    assert result.returncode == 0, f"upgrade head failed:\n{result.stderr}"
    result = _run_alembic("downgrade", "0024")
    assert result.returncode == 0, f"downgrade to 0024 failed:\n{result.stderr}"

    current = _run_alembic("current")
    combined = current.stdout + current.stderr
    assert "0024" in combined, f"Expected revision 0024 before downgrade, got: {combined[:300]}"

    # Step 2: downgrade -1 (0024 -> 0023)
    result_down = _run_alembic("downgrade", "-1")
    assert result_down.returncode == 0, f"downgrade -1 from 0024 failed:\n{result_down.stderr}"

    current_after_down = _run_alembic("current")
    combined_after_down = current_after_down.stdout + current_after_down.stderr
    assert (
        "0023" in combined_after_down
    ), f"Expected head at 0023 after downgrade -1, got: {combined_after_down[:300]}"

    # Step 3: upgrade back to the real head so the DB is left complete for
    # subsequent tests. Later features keep adding migrations after F-018 (F-020
    # 0028-0030, F-021 0031, ADR-0025 0032, F-026 0033, F-028 0034, F-033 0035),
    # so head is now 0035.
    result_up = _run_alembic("upgrade", "head")
    assert result_up.returncode == 0, f"upgrade head after downgrade -1 failed:\n{result_up.stderr}"

    current_after_up = _run_alembic("current")
    combined_after_up = current_after_up.stdout + current_after_up.stderr
    assert (
        "0035" in combined_after_up
    ), f"Expected head at 0035 after re-upgrade, got: {combined_after_up[:300]}"


def test_migration_0024_is_documented_reversible():
    """Sanity check: migration 0024 declares down_revision = '0023'."""
    import importlib.util

    mig_path = (
        _SENTINEL_ROOT
        / "src"
        / "persistence"
        / "migrations"
        / "versions"
        / "0024_shadow_ai_candidate_variant.py"
    )
    spec = importlib.util.spec_from_file_location("mig0024", str(mig_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    assert mod.revision == "0024"
    assert mod.down_revision == "0023"
    # The downgrade function must exist and be callable
    assert callable(getattr(mod, "downgrade", None))
    assert callable(getattr(mod, "upgrade", None))
