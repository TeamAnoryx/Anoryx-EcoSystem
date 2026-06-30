"""Fixtures for the R-004 identity persistence suite.

Connects to a live Postgres via DATABASE_URL (privileged owner) and APP_DATABASE_URL
(rendly_app, NOBYPASSRLS), read from the environment — no Rendly/.env is committed
(hook-protected). CI sets these in the job env; locally export them (see
Rendly/docker-compose.yml for the matching connection strings) or run the compose stack.

This suite REQUIRES a live Postgres, so when DATABASE_URL is unset (the no-DB contracts CI
lane) the whole directory is collect-ignored rather than failing — the DB lane sets the env
and collects it. Per-test isolation: a session-start + per-test privileged TRUNCATE resets
every table (rendly_app has no TRUNCATE grant; only the harness owner can), and each test
uses fresh random ids, so committed rows never collide and RLS keeps each test's view to its
own tenant.

The rendly_app SCRAM password is provisioned per test (idempotent, ~50ms) — a LOUD
pytest.fail on any provisioning error, never a silent swallow (the F-003b lesson).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import subprocess
import sys
import uuid
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

_RENDLY_ROOT = Path(__file__).resolve().parent.parent.parent  # .../Rendly

# This suite needs a database. With no DATABASE_URL (the no-DB contracts lane), skip the
# entire directory at collection time instead of erroring on every fixture.
collect_ignore_glob: list[str] = []
if not os.environ.get("DATABASE_URL"):
    collect_ignore_glob = ["*"]


def _require(name: str) -> str:
    raw = os.environ.get(name, "")
    if not raw:
        pytest.fail(
            f"{name} is not set. The Rendly persistence suite needs a live Postgres. Export "
            f"DATABASE_URL (owner) and APP_DATABASE_URL (rendly_app), or run "
            f"Rendly/docker-compose.yml. See Rendly/docker-compose.yml for the URLs."
        )
    return raw


def _psycopg_dsn(url: str) -> str:
    """Strip any SQLAlchemy +driver suffix so a raw psycopg connection accepts the URL."""
    return re.sub(r"^postgresql\+\w+://", "postgresql://", url)


def _parse(url: str) -> dict:
    m = re.match(r"postgresql(?:\+\w+)?://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)", url)
    if not m:
        pytest.fail("could not parse a postgres URL (user:pw@host:port/db expected)")
    return {
        "user": m.group(1),
        "password": m.group(2),
        "host": m.group(3),
        "port": int(m.group(4)),
        "database": m.group(5),
    }


@pytest.fixture(scope="session", autouse=True)
def ensure_schema_at_head() -> None:
    """Run `alembic upgrade head` once before any persistence test."""
    _require("DATABASE_URL")
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=str(_RENDLY_ROOT),
        env=os.environ.copy(),
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode != 0:
        pytest.fail(f"alembic upgrade head failed:\n{result.stdout}\n{result.stderr}")


@pytest.fixture(autouse=True)
def _reset_engines_setup() -> Iterator[None]:
    """Drop cached engines at SETUP (banked rule 7) so a stale DSN never leaks across modules."""
    from rendly.persistence.database import reset_engines

    reset_engines()
    yield
    reset_engines()


def _scram_verifier(plaintext: str) -> str:
    """Compute a SCRAM-SHA-256 verifier client-side (the plaintext is never a SQL literal)."""
    salt = os.urandom(16)
    iters = 4096
    salted = hashlib.pbkdf2_hmac("sha256", plaintext.encode(), salt, iters)
    ck = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    sk = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    return (
        f"SCRAM-SHA-256${iters}"
        f":{base64.b64encode(salt).decode()}"
        f"${base64.b64encode(hashlib.sha256(ck).digest()).decode()}"
        f":{base64.b64encode(sk).decode()}"
    )


@pytest.fixture(autouse=True)
def provision_app_role(ensure_schema_at_head: None, _reset_engines_setup: None) -> None:
    """Re-provision rendly_app's SCRAM password before each test (idempotent, cheap).

    Some migration-reversibility tests drop/recreate the role, so this runs per test. LOUD
    pytest.fail on any error — never a silent swallow.
    """
    if os.environ.get("RENDLY_PROVISION_APP_ROLE", "").lower() not in ("1", "true", "yes", "on"):
        return
    import psycopg
    from psycopg import sql

    db = _parse(_require("DATABASE_URL"))
    app_pw = _parse(_require("APP_DATABASE_URL"))["password"]
    verifier = _scram_verifier(app_pw)
    try:
        with psycopg.connect(_psycopg_dsn(_require("DATABASE_URL")), autocommit=True) as conn:
            conn.execute(
                sql.SQL("ALTER ROLE rendly_app WITH LOGIN PASSWORD {}").format(
                    sql.Literal(verifier)
                )
            )
        # Self-check: prove rendly_app authenticates with the plaintext now.
        with psycopg.connect(
            user="rendly_app",
            password=app_pw,
            host=db["host"],
            port=db["port"],
            dbname=db["database"],
        ):
            pass
    except Exception as exc:  # noqa: BLE001 — loud, never silent (F-003b lesson)
        pytest.fail(f"rendly_app provisioning/self-login failed: {exc!r}")


@pytest.fixture(autouse=True)
def _truncate_identity(provision_app_role: None) -> Iterator[None]:
    """Reset every identity table before each test (privileged TRUNCATE CASCADE).

    rendly_app has no TRUNCATE grant, so only the owner harness can do this. Combined with
    fresh per-test ids this gives clean, real-commit tests.
    """
    from rendly.persistence.database import get_privileged_session

    with get_privileged_session() as session:
        session.execute(
            text(
                "TRUNCATE rendly.refresh_tokens, rendly.refresh_token_families, "
                "rendly.credentials, rendly.profiles, rendly.users, rendly.tenants CASCADE"
            )
        )
        session.commit()
    yield


@pytest.fixture
def tenant_id() -> str:
    return str(uuid.uuid4())


@pytest.fixture
def other_tenant_id() -> str:
    return str(uuid.uuid4())


def _app_session_raw() -> Session:
    """A raw rendly_app session with NO tenant GUC set (for the fail-closed RLS tests)."""
    from rendly.persistence.database import _get_app_session_factory

    return _get_app_session_factory()()


@pytest.fixture
def app_session_no_guc() -> Callable[[], Session]:
    """Open a rendly_app session that never sets the GUC — RLS must yield zero rows."""
    return _app_session_raw


@pytest.fixture
def app_session_empty_guc() -> Callable[[], Session]:
    """Open a rendly_app session whose GUC is the empty string — NULLIF -> zero rows."""

    def _open() -> Session:
        session = _app_session_raw()
        session.execute(text("SELECT set_config('app.current_tenant_id', '', true)"))
        return session

    return _open


@pytest.fixture
def seed_identity() -> Callable[..., tuple]:
    """Seed a (tenant, user, profile, credential) set and return the frozen domain objects.

    Tenant goes in via the PRIVILEGED session (global registry); user/profile/credential go
    in under the tenant session (RLS WITH CHECK binds them to the tenant). Returns
    (Tenant, User, Profile) so round-trip tests can compare against the reconstructed values.
    """
    from rendly.auth.passwords import hash_password
    from rendly.enums import OrgRole, PresenceStatus
    from rendly.persistence.database import get_privileged_session, get_tenant_session
    from rendly.persistence.identity_repo import (
        insert_credential,
        insert_profile,
        insert_tenant,
        insert_user,
    )
    from rendly.profile import bind_profile
    from rendly.tenant import Tenant
    from rendly.user import User

    def _seed(
        *,
        tenant_id: str,
        user_id: str,
        username: str,
        password: str,
        org_role: OrgRole = OrgRole.MEMBER,
        team: str | None = None,
        display_name: str = "Test User",
        presence: PresenceStatus = PresenceStatus.ONLINE,
        status_text: str | None = None,
        created_at: datetime | None = None,
    ) -> tuple[Tenant, User, "object"]:
        created = created_at or datetime(2026, 6, 1, 9, 0, 0, tzinfo=timezone.utc)
        tenant = Tenant(tenant_id=tenant_id, created_at=created)
        user = User(
            user_id=user_id,
            tenant_id=tenant_id,
            display_name=display_name,
            status_text=status_text,
            presence=presence,
            created_at=created,
        )
        profile = bind_profile(user, org_role=org_role, team=team)

        with get_privileged_session() as session:
            insert_tenant(session, tenant)
            session.commit()
        with get_tenant_session(tenant_id) as session:
            insert_user(session, user)
            session.flush()  # user must exist before profile/credential (composite FK)
            insert_profile(session, profile)
            insert_credential(
                session,
                username=username,
                user_id=user_id,
                tenant_id=tenant_id,
                password_hash=hash_password(password),
                created_at=created,
            )
            session.commit()
        return tenant, user, profile

    return _seed
