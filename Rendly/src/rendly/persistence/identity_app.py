"""DB-backed app assembly — the R-003 -> R-004 swap point (no signature change).

``rendly.app.create_app`` already takes the two stores as parameters, so swapping the
fixture stores for the Postgres-backed ones needs NO change to that factory's signature
(Fork E = VERIFIED: the seams are satisfiable byte-for-byte). This module is the documented
production assembly: it builds :class:`DbUserStore` + :class:`DbRefreshTokenStore` and hands
them to the unchanged ``create_app``.

The in-memory fixture path stays the default for the existing non-DB auth tests
(``rendly.auth.build_fixture_store`` + ``InMemoryRefreshTokenStore``); this is the DB-backed
path the new persistence auth-DB e2e uses. The R-003 honesty boundary ("only the user lookup
is fixture-backed") is RETIRED for everything assembled here — the credential lookup, the
identity fetch, and the refresh state are all real Postgres.
"""

from __future__ import annotations

from fastapi import FastAPI

from ..app import create_app
from ..auth.keys import KeyMaterial
from ..auth.service import AuthConfig, Clock
from .refresh_store import DbRefreshTokenStore
from .user_store import DbUserStore


def create_db_app(
    *,
    key: KeyMaterial,
    config: AuthConfig | None = None,
    clock: Clock | None = None,
) -> FastAPI:
    """Build the Rendly auth app over the Postgres-backed stores.

    ``key`` is the ES256 signing material (loaded fail-closed by ``rendly.auth.keys``). The
    DB engines read ``DATABASE_URL`` / ``APP_DATABASE_URL`` lazily from the environment on
    first use — no URL is passed through or logged here.
    """
    return create_app(
        user_store=DbUserStore(),
        refresh_store=DbRefreshTokenStore(clock=clock),
        key=key,
        config=config,
        clock=clock,
    )
