"""R-004 migration reversibility — upgrade -> downgrade -> upgrade on the live schema.

Proves the hand-written 0001 migration is cleanly reversible (the CI rendly-migration-roundtrip
job also does a drop-schema rebuild). Runs the alembic CLI in a subprocess so it exercises the
real env.py path. The test leaves the schema at head, so the autouse per-test TRUNCATE that runs
before the NEXT test still finds the tables.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from sqlalchemy import text

from rendly.persistence.database import get_privileged_session

_RENDLY_ROOT = Path(__file__).resolve().parent.parent.parent


def _alembic(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=str(_RENDLY_ROOT),
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=180,
    )


def _tables() -> set[str]:
    with get_privileged_session() as session:
        rows = (
            session.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'rendly'"))
            .scalars()
            .all()
        )
    return set(rows)


def test_migration_down_up_is_clean() -> None:
    expected = {
        "tenants",
        "users",
        "profiles",
        "credentials",
        "refresh_token_families",
        "refresh_tokens",
    }
    # Start at head (session fixture already upgraded).
    assert expected <= _tables()

    down = _alembic("downgrade", "base")
    assert down.returncode == 0, f"{down.stdout}\n{down.stderr}"
    # All identity tables gone; the rendly schema (with alembic_version) is retained.
    assert _tables() & expected == set()

    up = _alembic("upgrade", "head")
    assert up.returncode == 0, f"{up.stdout}\n{up.stderr}"
    assert expected <= _tables()
