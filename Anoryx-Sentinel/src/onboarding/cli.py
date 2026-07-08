"""sentinel-onboarding — operator CLI for F-025 guided sandbox provisioning
(ADR-0031).

    sentinel-onboarding sandbox create --name "acme-trial" \\
        --write-templates ./acme-trial-policies

Provisions a tenant + team + project + virtual API key in one step, prints a
getting-started summary (sample curl call, next-step commands to sign+push
the sample F-008 policy templates via the existing `sentinel-cli`), and
optionally writes the sample policy templates to a local directory.

This is a CLI, not an HTTP endpoint — see src/onboarding/__init__.py for why.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

import structlog

from onboarding.sandbox import InvalidSandboxName, SandboxResult, provision_sandbox
from onboarding.templates import sandbox_templates

log = structlog.get_logger(__name__)

_DEFAULT_GATEWAY_URL = "http://localhost:8000"


def _print_summary(result: SandboxResult, *, gateway_url: str) -> None:
    print("sandbox ready:")
    print(f"  tenant_id  = {result.tenant_id}  ({result.tenant_name})")
    print(f"  team_id    = {result.team_id}")
    print(f"  project_id = {result.project_id}")
    print(f"  key_id     = {result.key_id}")
    print()
    print(f"  virtual API key (shown once — store it now): {result.plaintext_key}")
    print()
    print("sample request:")
    print(
        f"""  curl {gateway_url}/v1/chat/completions \\
    -H "Authorization: Bearer {result.plaintext_key}" \\
    -H "X-Anoryx-Tenant-Id: {result.tenant_id}" \\
    -H "X-Anoryx-Team-Id: {result.team_id}" \\
    -H "X-Anoryx-Project-Id: {result.project_id}" \\
    -H "X-Anoryx-Agent-Id: {result.agent_id}" \\
    -H "Content-Type: application/json" \\
    -d '{{"model": "gpt-3.5-turbo", "messages": [{{"role": "user", "content": "Hello!"}}]}}'"""
    )
    print()
    print(
        "This will only succeed once a real upstream provider is configured on "
        "this deployment (UPSTREAM_BASE_URL / ANTHROPIC_API_KEY / AWS_* — see "
        "deploy/ONBOARDING.md) — Sentinel does not fabricate a mock response."
    )


def _write_templates(tenant_id: str, out_dir: str) -> list[str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for slug, record in sandbox_templates(tenant_id).items():
        path = out / f"{slug}.json"
        path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        written.append(str(path))
    return written


def _cmd_sandbox_create(
    name: str,
    display_name: str | None,
    team_name: str,
    project_name: str,
    write_templates: str | None,
    gateway_url: str,
) -> int:
    try:
        result = asyncio.run(
            provision_sandbox(
                name, display_name=display_name, team_name=team_name, project_name=project_name
            )
        )
    except InvalidSandboxName as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"error: sandbox provisioning failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    _print_summary(result, gateway_url=gateway_url)

    if write_templates:
        paths = _write_templates(result.tenant_id, write_templates)
        print()
        print(f"sample policy templates written to {write_templates}/:")
        for p in paths:
            print(f"  {p}")
        print()
        print("push a template (requires an ECDSA P-256 signing keypair — see")
        print("`sentinel-cli policy keygen` if you don't have one yet):")
        for p in paths:
            print(f"  sentinel-cli policy push --file {p} --key <your-private-key.pem>")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-onboarding", description="Anoryx Sentinel guided sandbox onboarding (F-025)."
    )
    groups = parser.add_subparsers(dest="group", required=True)
    sandbox_p = groups.add_parser("sandbox", help="Sandbox tenant provisioning")
    cmds = sandbox_p.add_subparsers(dest="cmd", required=True)

    create = cmds.add_parser(
        "create", help="Provision a new sandbox tenant + team + project + key."
    )
    create.add_argument("--name", required=True, help="Tenant name (^[A-Za-z0-9][A-Za-z0-9._-]*$).")
    create.add_argument("--display-name", default=None, help="Human-friendly tenant display name.")
    create.add_argument(
        "--team-name", default="sandbox-team", help="Team name (default: sandbox-team)."
    )
    create.add_argument(
        "--project-name", default="sandbox-project", help="Project name (default: sandbox-project)."
    )
    create.add_argument(
        "--write-templates",
        default=None,
        help="Directory to write sample F-008 policy JSON templates into (optional).",
    )
    create.add_argument(
        "--gateway-url",
        default=_DEFAULT_GATEWAY_URL,
        help=f"Gateway base URL for the sample curl command (default: {_DEFAULT_GATEWAY_URL}).",
    )

    args = parser.parse_args(argv)
    if args.group == "sandbox" and args.cmd == "create":
        return _cmd_sandbox_create(
            args.name,
            args.display_name,
            args.team_name,
            args.project_name,
            args.write_templates,
            args.gateway_url,
        )
    parser.error("unknown command")  # pragma: no cover
    return 2  # pragma: no cover


if __name__ == "__main__":
    sys.exit(main())
