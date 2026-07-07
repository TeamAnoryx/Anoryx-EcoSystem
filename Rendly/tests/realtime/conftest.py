"""Fixtures for the R-005 real-time chat suite (real Postgres + in-process ASGI WebSocket).

Mirrors the R-004 persistence harness (live DB via DATABASE_URL owner + APP_DATABASE_URL
rendly_app; per-test privileged TRUNCATE; loud SCRAM provisioning) and adds what the async chat
layer needs:

  * the Windows SelectorEventLoop policy (asyncpg teardown races under the default Proactor loop —
    the Orchestrator/Delta precedent), set before TestClient builds its portal loop;
  * RENDLY_DB_SSL=disable + RENDLY_DB_NULLPOOL=1 for asyncpg against plaintext local/CI Postgres
    (NullPool avoids a pooled connection being reused across the per-test portal loops);
  * the ASYNC engine reset (alongside the sync one) at setup AND teardown (banked rule 7);
  * an ES256 key + a token-mint helper (tokens are forged directly, not via the password grant,
    so a test can pick the exact scopes), a sync user-seed, and a make_client factory that builds
    the chat app with a chosen MessageInspector (default no-op; seam tests pass a rejecting one).

Tests drive the REAL app over Starlette's in-process TestClient (HTTP + WebSocket are the real
ASGI app, not a stub) and assert DB state with SYNC reads — no pytest-asyncio, so the Windows
per-loop asyncpg flakiness never touches the assertions.
"""

from __future__ import annotations

import asyncio
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

# asyncpg teardown races under Windows' default ProactorEventLoop; the SelectorEventLoop tears
# asyncpg sockets down cleanly. Set BEFORE TestClient creates its anyio portal loop.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# asyncpg against plaintext local/CI Postgres: no SSL probe; NullPool so a connection is never
# reused across the per-test portal loops. setdefault so a CI/local override still wins.
os.environ.setdefault("RENDLY_DB_SSL", "disable")
os.environ.setdefault("RENDLY_DB_NULLPOOL", "1")

_RENDLY_ROOT = Path(__file__).resolve().parent.parent.parent  # .../Rendly

# This suite needs a database. With no DATABASE_URL (the no-DB contracts lane), skip the whole
# directory at collection time rather than erroring on every fixture.
collect_ignore_glob: list[str] = []
if not os.environ.get("DATABASE_URL"):
    collect_ignore_glob = ["*"]

_ALL_TABLES = (
    "messages",
    "memberships",
    "channels",
    "refresh_tokens",
    "refresh_token_families",
    "credentials",
    "profiles",
    "users",
    "tenants",
)


def _require(name: str) -> str:
    raw = os.environ.get(name, "")
    if not raw:
        pytest.fail(
            f"{name} is not set. The Rendly chat suite needs a live Postgres. Export DATABASE_URL "
            f"(owner) and APP_DATABASE_URL (rendly_app), or run Rendly/docker-compose.yml."
        )
    return raw


def _psycopg_dsn(url: str) -> str:
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
    """`alembic upgrade head` once before any chat test (picks up 0002 via the literal head)."""
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
    """Reset BOTH the sync and async engine singletons at setup + teardown (banked rule 7).

    The async reset is run via asyncio.run; with NullPool the engine holds no live connection, so
    disposing it outside its origin loop is a cheap no-op and a fresh engine binds to the next
    TestClient's portal loop.
    """
    from rendly.persistence.async_database import reset_async_engines
    from rendly.persistence.database import reset_engines

    reset_engines()
    asyncio.run(reset_async_engines())
    yield
    reset_engines()
    asyncio.run(reset_async_engines())


def _scram_verifier(plaintext: str) -> str:
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
    """Re-provision rendly_app's SCRAM password before each test. LOUD fail, never silent."""
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
        with psycopg.connect(
            user="rendly_app",
            password=app_pw,
            host=db["host"],
            port=db["port"],
            dbname=db["database"],
        ):
            pass
    except Exception as exc:  # noqa: BLE001 - loud, never silent (F-003b lesson)
        pytest.fail(f"rendly_app provisioning/self-login failed: {exc!r}")


@pytest.fixture(autouse=True)
def _truncate_all(provision_app_role: None) -> Iterator[None]:
    """Reset every identity + chat table before each test (privileged TRUNCATE CASCADE)."""
    from sqlalchemy import text

    from rendly.persistence.database import get_privileged_session

    with get_privileged_session() as session:
        session.execute(
            text("TRUNCATE " + ", ".join(f"rendly.{t}" for t in _ALL_TABLES) + " CASCADE")
        )
        session.commit()
    yield


# --- identity (ES256 key + token mint + sync user seed) --------------------------------


@pytest.fixture(scope="session")
def key() -> "object":
    """A real ES256 (P-256) key pair as KeyMaterial — the app verifies with it; tests mint with it."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from rendly.auth.keys import load_key_material

    private = ec.generate_private_key(ec.SECP256R1())
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    return load_key_material(pem)


@pytest.fixture
def mint_token(key: "object") -> Callable[..., str]:
    """Mint an ES256 access token for (user_id, tenant_id, scope) — scopes chosen per test."""
    from rendly.auth.claims import ISSUER, AccessTokenClaims
    from rendly.auth.tokens import mint

    def _mint(*, user_id: str, tenant_id: str, scope: str, ttl_seconds: int = 3600) -> str:
        now = int(datetime.now(timezone.utc).timestamp())
        claims = AccessTokenClaims(
            iss=ISSUER,
            sub=user_id,
            tenant_id=tenant_id,
            scope=scope,
            token_use="access",
            iat=now,
            exp=now + ttl_seconds,
            jti="jti_" + uuid.uuid4().hex,
        )
        return mint(claims, key)

    return _mint


@pytest.fixture
def seed_user() -> Callable[..., tuple[str, str]]:
    """Seed a (tenant, user) so the chat FKs resolve. Returns (tenant_id, user_id). Sync."""
    from rendly.enums import PresenceStatus
    from rendly.persistence.database import get_privileged_session, get_tenant_session
    from rendly.persistence.identity_repo import insert_tenant, insert_user
    from rendly.tenant import Tenant
    from rendly.user import User

    created = datetime(2026, 6, 1, 9, 0, 0, tzinfo=timezone.utc)
    seeded_tenants: set[str] = set()

    def _seed(*, tenant_id: str, user_id: str, display_name: str = "Chat User") -> tuple[str, str]:
        if tenant_id not in seeded_tenants:
            with get_privileged_session() as session:
                insert_tenant(session, Tenant(tenant_id=tenant_id, created_at=created))
                session.commit()
            seeded_tenants.add(tenant_id)
        user = User(
            user_id=user_id,
            tenant_id=tenant_id,
            display_name=display_name,
            status_text=None,
            presence=PresenceStatus.ONLINE,
            created_at=created,
        )
        with get_tenant_session(tenant_id) as session:
            insert_user(session, user)
            session.commit()
        return tenant_id, user_id

    return _seed


@pytest.fixture
def make_client(key: "object") -> Callable[..., "object"]:
    """Build a TestClient over the real chat app, optionally with a custom inspection seam, a
    custom team-membership resolver (R-006 — seam tests pass an unresolvable/raising resolver),
    and/or a custom ICE credential provider (R-007 — ice-server tests pass a fixed config)."""
    from starlette.testclient import TestClient

    from rendly.realtime.app import create_chat_app
    from rendly.realtime.ice import IceCredentialProvider
    from rendly.realtime.inspector import MessageInspector
    from rendly.realtime.resolver import TeamMembershipResolver

    def _make(
        inspector: MessageInspector | None = None,
        resolver: TeamMembershipResolver | None = None,
        ice_provider: IceCredentialProvider | None = None,
    ) -> "object":
        app = create_chat_app(
            key=key, inspector=inspector, resolver=resolver, ice_provider=ice_provider
        )
        return TestClient(app)

    return _make


@pytest.fixture
def new_uuid() -> Callable[[], str]:
    return lambda: str(uuid.uuid4())
