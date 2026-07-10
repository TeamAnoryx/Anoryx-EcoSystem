"""sentinel-token — operator CLI for the F-033 tokenization vault (ADR-0039).

    sentinel-token tokenize   --tenant <id> --type card   --value 4111111111111111
    sentinel-token detokenize --tenant <id> --token <token>

Requires SENTINEL_TOKEN_VAULT_KEY (base64 32 bytes) and DATABASE_URL/
APP_DATABASE_URL. tokenize prints the format-preserving surrogate token (the
original value is stored only as ciphertext in the tenant's RLS vault);
detokenize reverses it via the tenant session.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from tokenization.exceptions import TokenizationError
from tokenization.formats import TOKEN_TYPES


async def _run_tokenize(tenant: str, token_type: str, value: str) -> int:
    from tokenization.service import tokenize

    try:
        token = await tokenize(tenant, value, token_type=token_type)
    except TokenizationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(token)
    return 0


async def _run_detokenize(tenant: str, token: str) -> int:
    from tokenization.service import detokenize

    try:
        value = await detokenize(tenant, token)
    except TokenizationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(value)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="sentinel-token", description="Anoryx Sentinel tokenization vault CLI (F-033)."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    tk = sub.add_parser("tokenize", help="Tokenize a value (prints the surrogate token).")
    tk.add_argument("--tenant", required=True)
    tk.add_argument("--type", default="generic", choices=TOKEN_TYPES, dest="token_type")
    tk.add_argument("--value", required=True)

    dt = sub.add_parser("detokenize", help="Reverse a token back to its original value.")
    dt.add_argument("--tenant", required=True)
    dt.add_argument("--token", required=True)

    args = p.parse_args(argv)
    if args.cmd == "tokenize":
        return asyncio.run(_run_tokenize(args.tenant, args.token_type, args.value))
    if args.cmd == "detokenize":
        return asyncio.run(_run_detokenize(args.tenant, args.token))
    p.error("unknown command")  # pragma: no cover
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
