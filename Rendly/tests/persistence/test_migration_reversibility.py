"""Migration reversibility — upgrade -> downgrade -> upgrade on the live schema.

Proves the hand-written migration chain is cleanly reversible (the CI rendly-migration-roundtrip
job also does a drop-schema rebuild). Runs the alembic CLI in a subprocess so it exercises the
real env.py path. The test leaves the schema at head, so the autouse per-test TRUNCATE that runs
before the NEXT test still finds the tables.

RULE 9 (R-005 added migration 0002 — Rendly's SECOND migration): the full-chain table set below is
extended with the chat tables, and a dedicated test proves the 0001<->0002 boundary reverses
cleanly (downgrade 0002 drops ONLY the chat tables; the identity tables + the 0001 head survive).

R-008 added migration 0003 (Rendly's THIRD migration) — the ``inspection_audit_log`` table
(``messages.detectors`` is a column addition on an existing table, not a new one, so it does not
extend this table-set check). A further dedicated test proves the 0002<->0003 boundary.
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


# The full table set across BOTH migrations (0001 identity + 0002 chat). RULE 9: extended for the
# chat tables so the round-trip actually proves 0002's tables reverse, not just 0001's.
_IDENTITY_TABLES = {
    "tenants",
    "users",
    "profiles",
    "credentials",
    "refresh_token_families",
    "refresh_tokens",
}
_CHAT_TABLES = {"channels", "memberships", "messages"}
_INSPECTION_TABLES = {"inspection_audit_log"}
_ALL_TABLES = _IDENTITY_TABLES | _CHAT_TABLES | _INSPECTION_TABLES


def test_migration_down_up_is_clean() -> None:
    expected = _ALL_TABLES
    # Start at head (session fixture already upgraded) — both migrations applied.
    assert expected <= _tables()

    down = _alembic("downgrade", "base")
    assert down.returncode == 0, f"{down.stdout}\n{down.stderr}"
    # All identity + chat tables gone; the rendly schema (with alembic_version) is retained.
    assert _tables() & expected == set()

    up = _alembic("upgrade", "head")
    assert up.returncode == 0, f"{up.stdout}\n{up.stderr}"
    assert expected <= _tables()


def test_chat_migration_0002_reverses_to_0001() -> None:
    """The 0001<->0002 boundary: downgrade 0002 drops ONLY the chat tables; 0001 head survives."""
    # Start at head (0002).
    assert _CHAT_TABLES <= _tables()
    assert _IDENTITY_TABLES <= _tables()

    down = _alembic("downgrade", "0001")
    assert down.returncode == 0, f"{down.stdout}\n{down.stderr}"
    tables = _tables()
    assert tables & _CHAT_TABLES == set()  # chat tables gone
    assert _IDENTITY_TABLES <= tables  # identity tables (the 0001 head) intact

    up = _alembic("upgrade", "head")
    assert up.returncode == 0, f"{up.stdout}\n{up.stderr}"
    assert _ALL_TABLES <= _tables()


def test_inspection_migration_0003_reverses_to_0002() -> None:
    """The 0002<->0003 boundary: downgrade 0003 drops ONLY inspection_audit_log; 0002 survives."""
    # Start at head (0003).
    assert _INSPECTION_TABLES <= _tables()
    assert _CHAT_TABLES <= _tables()

    down = _alembic("downgrade", "0002")
    assert down.returncode == 0, f"{down.stdout}\n{down.stderr}"
    tables = _tables()
    assert tables & _INSPECTION_TABLES == set()  # inspection_audit_log gone
    assert _CHAT_TABLES <= tables  # chat tables (the 0002 head) intact

    up = _alembic("upgrade", "head")
    assert up.returncode == 0, f"{up.stdout}\n{up.stderr}"
    assert _ALL_TABLES <= _tables()
