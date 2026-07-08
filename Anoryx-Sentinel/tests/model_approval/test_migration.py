"""F-019 migration reversibility — vector 11 (ADR-0022 §9).

  test_migrations_reversible — alembic upgrade head -> downgrade -3 (0027/0026/0025
  back to 0024) -> upgrade head round-trips cleanly across all three F-019 migrations.
  test_*_documented_reversible — each F-019 migration declares its down_revision chain
  (0024 -> 0025 -> 0026 -> 0027) and has callable upgrade()/downgrade().

DB-GATED: skips when DATABASE_URL not set or Postgres unreachable. Mirrors
tests/shadow_ai/test_migration.py.
"""

from __future__ import annotations

import importlib.util
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
_VERSIONS = _SENTINEL_ROOT / "src" / "persistence" / "migrations" / "versions"


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
        timeout=90,
    )


@pytest.mark.asyncio
async def test_migrations_reversible():
    """Vector 11: the three F-019 migrations (0025/0026/0027) round-trip cleanly.

    Later features keep adding migrations on top of F-019 (F-020 0028-0030, F-021
    0031, ADR-0025 0032, F-026 0033). To stay correct regardless of the current head,
    we go to head, then downgrade to the EXPLICIT revision 0024 (pre-F-019) rather
    than a step count, then re-upgrade to head — verifying all F-019 migrations
    reverse.
    """
    if not _db_available():
        pytest.skip("DATABASE_URL not set — skipping migration reversibility test")

    up = _run_alembic("upgrade", "head")
    assert up.returncode == 0, f"upgrade head failed:\n{up.stderr}"
    cur = _run_alembic("current")
    assert "0033" in (cur.stdout + cur.stderr), "expected head at 0033 before downgrade"

    # Downgrade to the explicit pre-F-019 revision (robust to later head bumps).
    down = _run_alembic("downgrade", "0024")
    assert down.returncode == 0, f"downgrade to 0024 failed:\n{down.stderr}"
    cur_down = _run_alembic("current")
    assert "0024" in (cur_down.stdout + cur_down.stderr), "expected 0024 after downgrade"

    # Re-upgrade back to head.
    up2 = _run_alembic("upgrade", "head")
    assert up2.returncode == 0, f"re-upgrade head failed:\n{up2.stderr}"
    cur_up = _run_alembic("current")
    assert "0033" in (cur_up.stdout + cur_up.stderr), "expected head at 0033 after re-upgrade"


@pytest.mark.parametrize(
    "filename,revision,down_revision",
    [
        ("0025_model_approval_policy_type.py", "0025", "0024"),
        ("0026_model_inventory.py", "0026", "0025"),
        ("0027_model_approval_event_variants.py", "0027", "0026"),
    ],
)
def test_migration_documented_reversible(filename, revision, down_revision):
    """Each F-019 migration declares its chain link + callable upgrade/downgrade."""
    spec = importlib.util.spec_from_file_location(f"mig_{revision}", str(_VERSIONS / filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.revision == revision
    assert mod.down_revision == down_revision
    assert callable(getattr(mod, "upgrade", None))
    assert callable(getattr(mod, "downgrade", None))
