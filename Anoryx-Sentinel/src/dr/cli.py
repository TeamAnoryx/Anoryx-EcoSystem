"""sentinel-dr — operator CLI for F-024 disaster recovery (ADR-0030).

    sentinel-dr backup
    sentinel-dr restore --key sentinel-backup-20260707T120000Z.dump \\
        --target-database-url postgresql://sentinel:...@host:5432/restore_target
    sentinel-dr list

`backup` reads DATABASE_URL (the privileged connection — see backup.py) and
the DR_* sink settings from env (src/dr/config.py); it is the command the
Helm CronJob runs on a schedule (deploy/helm/sentinel/templates/
backup-cronjob.yaml, gated off by default).

`restore` NEVER defaults its target to DATABASE_URL — --target-database-url is
required, so a restore can never accidentally overwrite the connection an
operator happens to have configured in the environment. There is no scheduled/
automated restore path; this is an operator-run command only.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

import structlog

from dr.backends.factory import build_sink
from dr.backup import run_backup
from dr.config import get_dr_settings
from dr.exceptions import DrError
from dr.restore import run_restore

log = structlog.get_logger(__name__)


async def _cmd_backup() -> int:
    settings = get_dr_settings()
    source_url = os.environ.get("DATABASE_URL", "")
    if not source_url:
        print("DATABASE_URL is not set.", file=sys.stderr)
        return 2
    sink = build_sink(settings)
    try:
        result = await run_backup(
            sink, source_database_url=source_url, retention_days=settings.dr_retention_days
        )
    except DrError as exc:
        print(f"backup failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"backup OK: key={result.key} size_bytes={result.size_bytes} "
        f"duration_s={result.duration_s:.2f} "
        f"deleted_for_retention={len(result.deleted_for_retention)}"
    )
    return 0


async def _cmd_restore(key: str, target_database_url: str) -> int:
    settings = get_dr_settings()
    sink = build_sink(settings)
    try:
        result = await run_restore(sink, key, target_database_url=target_database_url)
    except DrError as exc:
        print(f"restore failed: {exc}", file=sys.stderr)
        return 1
    print(
        f"restore OK: key={result.key} duration_s={result.duration_s:.2f} "
        f"chain_rows_checked={result.rows_checked}"
    )
    return 0


async def _cmd_list() -> int:
    settings = get_dr_settings()
    sink = build_sink(settings)
    objects = sorted(await sink.list_objects(), key=lambda o: o.created_at)
    if not objects:
        print("no backups found")
        return 0
    for obj in objects:
        print(f"{obj.key}\t{obj.created_at}\t{obj.size_bytes} bytes")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentinel-dr", description=__doc__)
    cmds = parser.add_subparsers(dest="command", required=True)

    cmds.add_parser("backup", help="Run a pg_dump backup and store it via the configured sink.")

    restore_p = cmds.add_parser(
        "restore", help="Restore a backup into an explicit target database."
    )
    restore_p.add_argument("--key", required=True, help="Backup key (see `sentinel-dr list`).")
    restore_p.add_argument(
        "--target-database-url",
        required=True,
        help="Postgres URL to restore INTO. Never defaults — always explicit.",
    )

    cmds.add_parser("list", help="List stored backups, oldest first.")

    args = parser.parse_args(argv)

    if args.command == "backup":
        return asyncio.run(_cmd_backup())
    if args.command == "restore":
        return asyncio.run(_cmd_restore(args.key, args.target_database_url))
    if args.command == "list":
        return asyncio.run(_cmd_list())
    return 2  # pragma: no cover - argparse enforces `required=True` above


if __name__ == "__main__":
    sys.exit(main())
