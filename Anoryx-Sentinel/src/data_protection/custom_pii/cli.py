"""sentinel-pii — operator CLI for F-028 custom PII patterns (ADR-0034).

    sentinel-pii add --tenant <id> --name EMPLOYEE_ID --pattern 'EMP-\\d{6}'
    sentinel-pii list --tenant <id> [--all]
    sentinel-pii revoke --tenant <id> --pattern-id <id>
    sentinel-pii test --tenant <id> --text "..."   (preview which patterns match)

`add` also accepts optional --score (default 0.85) and --action (mask|tokenize|block).

`test` loads the tenant's active patterns and runs the SAME ReDoS-safe engine
the request path uses — an operator can verify masking behavior before relying
on it. The value that matched is NEVER printed (only the entity label + span).
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import structlog

from data_protection.custom_pii.admin import list_patterns, register_pattern, revoke_pattern
from data_protection.custom_pii.config import get_custom_pii_settings
from data_protection.custom_pii.engine import scan
from data_protection.custom_pii.exceptions import CustomPiiError
from data_protection.custom_pii.loader import CustomPiiPatternLoader

log = structlog.get_logger(__name__)


async def _cmd_add(
    tenant_id: str, name: str, pattern: str, score: float, action: str | None
) -> int:
    try:
        row = await register_pattern(tenant_id, name, pattern, score=score, action=action)
    except CustomPiiError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"registered: pattern_id={row.pattern_id} name={row.name} score={row.score}")
    return 0


async def _cmd_list(tenant_id: str, all_: bool) -> int:
    rows = await list_patterns(tenant_id, active_only=not all_)
    if not rows:
        print("no custom PII patterns registered")
        return 0
    for r in rows:
        status = "active" if r.is_active else "inactive"
        # Print the pattern text (operator-owned, not a secret) but keep it on
        # its own tab-delimited field.
        print(
            f"{r.pattern_id}\t{r.name}\t{r.score}\t{r.action or 'default'}\t{status}\t{r.pattern}"
        )
    return 0


async def _cmd_revoke(tenant_id: str, pattern_id: str) -> int:
    try:
        row = await revoke_pattern(tenant_id, pattern_id)
    except CustomPiiError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"revoked: pattern_id={row.pattern_id} name={row.name}")
    return 0


async def _cmd_test(tenant_id: str, text: str) -> int:
    settings = get_custom_pii_settings()
    loader = CustomPiiPatternLoader(ttl_seconds=settings.custom_pii_cache_ttl_seconds)
    patterns = await loader.load(tenant_id)
    if not patterns:
        print("no active custom PII patterns for this tenant")
        return 0
    spans, timed_out = scan(
        text[: settings.custom_pii_max_inspect_chars],
        patterns,
        timeout_seconds=settings.custom_pii_match_timeout_seconds,
    )
    if timed_out:
        print(f"WARNING: patterns timed out (ReDoS guard): {timed_out}", file=sys.stderr)
    if not spans:
        print("no matches")
        return 0
    print(f"{len(spans)} match(es) (matched values NOT printed):")
    for s in sorted(spans, key=lambda x: x.start):
        print(f"  {s.name}\t[{s.start}:{s.end}]\tscore={s.score}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-pii", description="Anoryx Sentinel custom PII pattern CLI (F-028)."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    add = sub.add_parser("add", help="Register a new custom PII regex pattern.")
    add.add_argument("--tenant", required=True, dest="tenant_id")
    add.add_argument("--name", required=True, help="Entity label, e.g. EMPLOYEE_ID.")
    add.add_argument("--pattern", required=True, help="The regex pattern text.")
    add.add_argument("--score", type=float, default=0.85, help="Confidence [0,1] (default 0.85).")
    add.add_argument(
        "--action",
        default=None,
        choices=["mask", "tokenize", "block"],
        help="Per-pattern override.",
    )

    lst = sub.add_parser("list", help="List a tenant's custom PII patterns.")
    lst.add_argument("--tenant", required=True, dest="tenant_id")
    lst.add_argument("--all", action="store_true", help="Include inactive (revoked) patterns.")

    revoke = sub.add_parser("revoke", help="Soft-deactivate a custom PII pattern.")
    revoke.add_argument("--tenant", required=True, dest="tenant_id")
    revoke.add_argument("--pattern-id", required=True)

    test = sub.add_parser(
        "test", help="Preview which patterns match some text (values not printed)."
    )
    test.add_argument("--tenant", required=True, dest="tenant_id")
    test.add_argument("--text", required=True)

    args = parser.parse_args(argv)

    if args.cmd == "add":
        return asyncio.run(
            _cmd_add(args.tenant_id, args.name, args.pattern, args.score, args.action)
        )
    if args.cmd == "list":
        return asyncio.run(_cmd_list(args.tenant_id, args.all))
    if args.cmd == "revoke":
        return asyncio.run(_cmd_revoke(args.tenant_id, args.pattern_id))
    if args.cmd == "test":
        return asyncio.run(_cmd_test(args.tenant_id, args.text))
    parser.error("unknown command")  # pragma: no cover
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
