"""Anoryx Sentinel — dev demo seed (F-010 Part 1 compose demo).

Creates a deterministic tenant -> team -> project -> virtual API key for the
compose demo. Idempotent: safe to re-run (check-exists-first at every step).

Environment (assembled by docker-entrypoint.sh before this script runs):
  DATABASE_URL       -- privileged role (migrations/chain ops).
  APP_DATABASE_URL   -- sentinel_app role (tenant-scoped ops, RLS enforced).
  SENTINEL_KEY_SECRET -- HMAC key for virtual API key fingerprints.

Exits 0 on success, non-zero on real error.

Output on first run:
  SEEDED_TENANT_ID=<uuid>
  SEEDED_TEAM_ID=<uuid>
  SEEDED_PROJECT_ID=<uuid>
  SEEDED_AGENT_ID=gateway-core
  SEEDED_VIRTUAL_KEY=<plaintext key>   <- show ONCE, then stored in /seed/.seeded-key

Output on re-run (already seeded):
  ALREADY_SEEDED -- tenant/team/project/key are in place
  SEEDED_TENANT_ID=...  (same stable IDs printed again for convenience)

NOTE: get_privileged_session() autobegins a transaction (SQLAlchemy 2.x implicit
begin). Do NOT call session.begin() inside it -- that raises InvalidRequestError.
Use await session.commit() to commit, or rely on flush() + the context manager
commit on exit.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import sys
from pathlib import Path

SEED_DIR = Path("/seed")
KEY_FILE = SEED_DIR / ".seeded-key"

# Fixed deterministic IDs for the demo tenant (stable across re-runs / restarts).
DEMO_TENANT_ID  = "d0000000-0000-4000-a000-000000000001"
DEMO_TEAM_ID    = "d0000000-0000-4000-a000-000000000002"
DEMO_PROJECT_ID = "d0000000-0000-4000-a000-000000000003"
DEMO_AGENT_ID   = "gateway-core"  # reserved slug per contracts/ids.md


def _check_env() -> None:
    missing = [v for v in ("DATABASE_URL", "APP_DATABASE_URL", "SENTINEL_KEY_SECRET")
               if not os.environ.get(v)]
    if missing:
        print(f"seed.py: ERROR: missing required env vars: {missing}", file=sys.stderr)
        sys.exit(1)


async def _seed() -> None:
    _check_env()

    # Import here so PYTHONPATH=/app/src is already set by the entrypoint.
    from persistence.database import get_privileged_session, get_tenant_session
    from persistence.models.tenant import Tenant
    from persistence.models.team import Team
    from persistence.models.project import Project
    from persistence.models.virtual_api_key import VirtualApiKey
    from persistence.repositories.virtual_api_key_repository import VirtualApiKeyRepository
    from sqlalchemy import select

    # ----------------------------------------------------------------
    # Step 1: Create tenant / team / project via privileged session.
    # NOTE: get_privileged_session() autobegins; do NOT call .begin() inside.
    # ----------------------------------------------------------------
    async with get_privileged_session() as priv:
        # Tenant
        row = (await priv.execute(
            select(Tenant).where(Tenant.tenant_id == DEMO_TENANT_ID)
        )).scalar_one_or_none()
        if row is None:
            tenant = Tenant(
                tenant_id=DEMO_TENANT_ID,
                name="demo",
                display_name="Demo Tenant",
                is_active=True,
            )
            priv.add(tenant)
            await priv.flush()
            print("seed.py: created tenant 'demo'")
        else:
            print("seed.py: tenant 'demo' already exists")

        # Team
        t_row = (await priv.execute(
            select(Team).where(Team.team_id == DEMO_TEAM_ID)
        )).scalar_one_or_none()
        if t_row is None:
            team = Team(
                team_id=DEMO_TEAM_ID,
                tenant_id=DEMO_TENANT_ID,
                name="demo-team",
                display_name="Demo Team",
                is_active=True,
            )
            priv.add(team)
            await priv.flush()
            print("seed.py: created team 'demo-team'")
        else:
            print("seed.py: team 'demo-team' already exists")

        # Project
        p_row = (await priv.execute(
            select(Project).where(Project.project_id == DEMO_PROJECT_ID)
        )).scalar_one_or_none()
        if p_row is None:
            project = Project(
                project_id=DEMO_PROJECT_ID,
                tenant_id=DEMO_TENANT_ID,
                team_id=DEMO_TEAM_ID,
                name="demo-project",
                display_name="Demo Project",
                is_active=True,
            )
            priv.add(project)
            await priv.flush()
            print("seed.py: created project 'demo-project'")
        else:
            print("seed.py: project 'demo-project' already exists")

        await priv.commit()

    # ----------------------------------------------------------------
    # Step 2: Check if a key already exists for the demo tenant.
    # ----------------------------------------------------------------
    async with get_privileged_session() as priv2:
        existing = (await priv2.execute(
            select(VirtualApiKey).where(
                VirtualApiKey.tenant_id == DEMO_TENANT_ID,
                VirtualApiKey.is_active.is_(True),
            )
        )).scalar_one_or_none()

    if existing is not None:
        print("ALREADY_SEEDED -- tenant/team/project/key are in place")
        print(f"SEEDED_TENANT_ID={DEMO_TENANT_ID}")
        print(f"SEEDED_TEAM_ID={DEMO_TEAM_ID}")
        print(f"SEEDED_PROJECT_ID={DEMO_PROJECT_ID}")
        print(f"SEEDED_AGENT_ID={DEMO_AGENT_ID}")
        if KEY_FILE.exists():
            print(f"SEEDED_VIRTUAL_KEY={KEY_FILE.read_text().strip()}")
        else:
            print("SEEDED_VIRTUAL_KEY=<see deploy/seed/.seeded-key>")
        return

    # ----------------------------------------------------------------
    # Step 3: Mint key via tenant session (RLS-scoped write).
    # NOTE: get_tenant_session() autobegins -- do NOT call .begin() inside.
    # ----------------------------------------------------------------
    plaintext = secrets.token_urlsafe(32)
    async with get_tenant_session(DEMO_TENANT_ID) as ts:
        key_repo = VirtualApiKeyRepository(ts)
        await key_repo.create(
            plaintext_key=plaintext,
            tenant_id=DEMO_TENANT_ID,
            team_id=DEMO_TEAM_ID,
            project_id=DEMO_PROJECT_ID,
            agent_id=DEMO_AGENT_ID,
            label="demo-key",
        )
        await ts.commit()  # commit the autobegun transaction

    # Write to bind-mounted /seed/.seeded-key (host: deploy/seed/.seeded-key).
    if SEED_DIR.exists():
        KEY_FILE.write_text(plaintext)
        print("seed.py: virtual key written to /seed/.seeded-key")

    print(f"SEEDED_TENANT_ID={DEMO_TENANT_ID}")
    print(f"SEEDED_TEAM_ID={DEMO_TEAM_ID}")
    print(f"SEEDED_PROJECT_ID={DEMO_PROJECT_ID}")
    print(f"SEEDED_AGENT_ID={DEMO_AGENT_ID}")
    print(f"SEEDED_VIRTUAL_KEY={plaintext}")
    print("seed.py: demo seed complete -- use the key above for /v1 requests")


if __name__ == "__main__":
    asyncio.run(_seed())
