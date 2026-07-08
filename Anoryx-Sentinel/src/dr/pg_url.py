"""Parse a Postgres URL into pg_dump/pg_restore CLI args + PGPASSWORD env
(F-024).

Deliberately does NOT pass the connection string as a single CLI argument to
the pg_dump/pg_restore subprocess: a password embedded in argv is visible to
any other process on the host via `ps`/`/proc`. Splitting into `-h/-p/-U/-d`
args + a PGPASSWORD env var (passed only to the child process's environment,
per CLAUDE.md #4 — never logged, never in argv) is the standard safe pattern.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import unquote, urlsplit


@dataclass(frozen=True, slots=True)
class PgConnParts:
    host: str
    port: int
    user: str
    password: str | None
    dbname: str

    def cli_args(self) -> list[str]:
        return ["-h", self.host, "-p", str(self.port), "-U", self.user, "-d", self.dbname]

    def env(self, base_env: dict[str, str]) -> dict[str, str]:
        env = dict(base_env)
        if self.password:
            env["PGPASSWORD"] = self.password
        return env


def parse_pg_url(url: str) -> PgConnParts:
    """Parse postgresql[+driver]://user:pass@host:port/dbname into parts.

    Strips any SQLAlchemy driver suffix (e.g. postgresql+asyncpg://) since
    pg_dump/pg_restore only understand the plain postgresql:// scheme.
    """
    scheme_stripped = url.split("://", 1)
    normalized = "postgresql://" + scheme_stripped[1] if len(scheme_stripped) == 2 else url
    parts = urlsplit(normalized)
    if not parts.hostname or not parts.username or not parts.path.lstrip("/"):
        raise ValueError("malformed Postgres URL: missing host, user, or dbname")
    return PgConnParts(
        host=parts.hostname,
        port=parts.port or 5432,
        user=unquote(parts.username),
        password=unquote(parts.password) if parts.password else None,
        dbname=parts.path.lstrip("/"),
    )
