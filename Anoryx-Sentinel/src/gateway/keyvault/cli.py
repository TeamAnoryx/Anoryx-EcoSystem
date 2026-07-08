"""sentinel-keyvault — operator CLI for F-027 provider key vaulting (ADR-0033).

    sentinel-keyvault status
    sentinel-keyvault verify --provider anthropic

This CLI runs as a SEPARATE process from the gateway — it cannot push a
rotated credential into a live gateway's in-process cache (that would need a
new admin HTTP endpoint, deferred — see docs/adr/0033). Its role is to let an
operator confirm a backend (Vault/KMS) has a fresh, fetchable credential for
a provider, independent of any running gateway instance. A live gateway picks
up a rotated secret on its own within one `keyvault_cache_ttl_seconds` window
via the periodic background refresh in gateway/main.py.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

import structlog

from gateway.config import get_settings
from gateway.keyvault.exceptions import KeyFetchError, KeyNotConfigured
from gateway.keyvault.factory import build_key_source
from gateway.keyvault.settings import get_keyvault_settings

log = structlog.get_logger(__name__)

_CANDIDATE_PROVIDERS = ("anthropic", "bedrock")


async def _cmd_status() -> int:
    gateway_settings = get_settings()
    keyvault_settings = get_keyvault_settings()
    source = build_key_source(gateway_settings, keyvault_settings)

    print(f"backend: {keyvault_settings.keyvault_backend}")
    print(f"cache_ttl_seconds: {keyvault_settings.keyvault_cache_ttl_seconds}")
    exit_code = 0
    for provider in _CANDIDATE_PROVIDERS:
        try:
            await source.fetch_credentials(provider)
        except KeyNotConfigured:
            print(f"{provider}: not configured")
        except KeyFetchError as exc:
            print(f"{provider}: error ({exc})", file=sys.stderr)
            exit_code = 1
        else:
            print(f"{provider}: ok")
    return exit_code


async def _cmd_verify(provider: str) -> int:
    gateway_settings = get_settings()
    keyvault_settings = get_keyvault_settings()
    source = build_key_source(gateway_settings, keyvault_settings)

    try:
        await source.fetch_credentials(provider)
    except KeyNotConfigured as exc:
        print(f"not configured: {exc}", file=sys.stderr)
        return 1
    except KeyFetchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"ok: {provider} credentials fetched successfully (value not printed)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-keyvault", description="Anoryx Sentinel provider key vaulting CLI (F-027)."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="Show the configured backend and per-provider fetch status.")

    verify = sub.add_parser("verify", help="Fetch one provider's credentials and report success.")
    verify.add_argument("--provider", required=True, choices=_CANDIDATE_PROVIDERS)

    args = parser.parse_args(argv)

    if args.cmd == "status":
        return asyncio.run(_cmd_status())
    if args.cmd == "verify":
        return asyncio.run(_cmd_verify(args.provider))
    parser.error("unknown command")  # pragma: no cover
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
