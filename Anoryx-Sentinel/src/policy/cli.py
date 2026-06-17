"""sentinel-cli — operator CLI for F-008 policy intake (ADR-0009 §11).

Internal-only (no HTTP — R1). `push` loads the SAME intake_policy() the gateway
uses and calls it directly with the signed record. Exposed as the `sentinel-cli`
console entry point in pyproject.toml.

    sentinel-cli policy keygen --out private.pem --pub-out public.pem
    sentinel-cli policy push   --file policy.json --key private.pem

`keygen` produces a dev/test ECDSA P-256 keypair (PEM). Production signing keys
MUST be HSM-managed (key rotation / HSM is deferred — ADR-0009 §12). `push` signs
the record's scope claims with the private key and runs intake; intake verifies
against the public key configured at POLICY_SIGNING_PUBKEY_PATH, so a push is only
Accepted when that public key matches the signing private key.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import sys
from pathlib import Path

import structlog

from policy import crypto
from policy.intake import intake_policy
from policy.results import Accepted

log = structlog.get_logger(__name__)

# F-007 (ADR-0010 §11): classifier-config CLI constants.
_WILDCARD_UUID = "00000000-0000-0000-0000-000000000000"
_WILDCARD_AGENT = "all-agents"
_CLASSIFIER_PRESETS = ("anthropic:claude-haiku-4-5", "openai:gpt-4o-mini")
_AUDIT_MODES = ("full", "redacted")


def _cmd_keygen(out: str, pub_out: str) -> int:
    private_key, public_key = crypto.generate_keypair()
    Path(out).write_bytes(crypto.private_key_to_pem(private_key))
    Path(pub_out).write_bytes(crypto.public_key_to_pem(public_key))
    with contextlib.suppress(OSError):
        os.chmod(out, 0o600)  # best-effort: restrict private-key read perms (POSIX)
    if sys.platform == "win32":
        print(f"WARNING: file permissions are not enforced on Windows — protect {out} manually.")
    print(f"wrote private key -> {out}")
    print(f"wrote public  key -> {pub_out}")
    print("NOTE: dev/test keypair only. Production keys MUST be HSM-managed.")
    return 0


def _cmd_push(file: str, key: str) -> int:
    try:
        record = json.loads(Path(file).read_text(encoding="utf-8"))
        private_key = crypto.load_private_key_pem(Path(key).read_bytes())
        signed = crypto.sign_policy_record(record, private_key)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: could not load/sign the record: {exc}", file=sys.stderr)
        return 1

    result = asyncio.run(intake_policy(signed))
    print(f"intake result: {type(result).__name__}")
    if isinstance(result, Accepted):
        print(
            f"  policy_id={result.policy_id} "
            f"version={result.policy_version} type={result.policy_type}"
        )
        return 0
    print(f"  rejected: {getattr(result, 'detail', '')}")
    return 1


# ---------------------------------------------------------------------------
# F-007 (ADR-0010 §11): classifier config operator commands.
# Writes run on the privileged session (operator action). The config_changed
# audit is recorded as a structured operator log line — it is NOT a request-path
# events_audit_log row (that hash-chained log carries request-scoped events with
# the four stable IDs; an operator config change is not such an event).
# ---------------------------------------------------------------------------


async def _set_classifier(
    tenant: str, team: str, project: str, agent: str, model: str, audit_mode: str
) -> None:
    from sqlalchemy import text

    from persistence.database import get_privileged_session

    async with get_privileged_session() as session:
        async with session.begin():
            await session.execute(
                text(
                    "INSERT INTO tenant_routing_policy (tenant_id, team_id, project_id, "
                    "agent_id, allowed_providers, fallback_order, classifier_model_id, "
                    "audit_mode) VALUES (:t, :team, :proj, :agent, "
                    "'openai,anthropic,bedrock', 'openai,anthropic,bedrock', :model, :mode) "
                    "ON CONFLICT (tenant_id) DO UPDATE SET "
                    "classifier_model_id = :model, audit_mode = :mode, updated_at = now()"
                ),
                {
                    "t": tenant,
                    "team": team,
                    "proj": project,
                    "agent": agent,
                    "model": model,
                    "mode": audit_mode,
                },
            )


async def _unset_classifier(tenant: str) -> None:
    from sqlalchemy import text

    from persistence.database import get_privileged_session

    async with get_privileged_session() as session:
        async with session.begin():
            await session.execute(
                text(
                    "UPDATE tenant_routing_policy SET classifier_model_id = NULL, "
                    "updated_at = now() WHERE tenant_id = :t"
                ),
                {"t": tenant},
            )


async def _get_classifier(tenant: str):
    from persistence.database import get_privileged_session
    from persistence.repositories.tenant_routing_policy_repository import (
        TenantRoutingPolicyRepository,
    )

    async with get_privileged_session() as session:
        async with session.begin():
            return await TenantRoutingPolicyRepository(session).resolve_classifier_config(
                tenant, caller_tenant_id=tenant
            )


def _cmd_classifier_set(
    tenant: str, team: str, project: str, agent: str, model: str, audit_mode: str
) -> int:
    asyncio.run(_set_classifier(tenant, team, project, agent, model, audit_mode))
    # Operator-audit log line (config_changed). Not a request-path hash-chain event.
    log.info(
        "classifier.config_changed",
        action="set",
        tenant_id=tenant,
        classifier_model_id=model,
        audit_mode=audit_mode,
        actor="cli",
    )
    print(f"classifier set for tenant {tenant}: model={model} audit_mode={audit_mode}")
    return 0


def _cmd_classifier_unset(tenant: str) -> int:
    asyncio.run(_unset_classifier(tenant))
    log.info("classifier.config_changed", action="unset", tenant_id=tenant, actor="cli")
    print(f"classifier unset for tenant {tenant} (falls back to parent or unconfigured)")
    return 0


def _cmd_classifier_get(tenant: str) -> int:
    cfg = asyncio.run(_get_classifier(tenant))
    model = cfg.model_id if cfg.model_id is not None else "(unconfigured)"
    print(f"resolved classifier for tenant {tenant}: model={model} audit_mode={cfg.audit_mode}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-cli",
        description="Anoryx Sentinel operator CLI (F-008 policy intake).",
    )
    groups = parser.add_subparsers(dest="group", required=True)
    policy_p = groups.add_parser("policy", help="Policy intake operations")
    cmds = policy_p.add_subparsers(dest="cmd", required=True)

    kg = cmds.add_parser("keygen", help="Generate a dev/test ECDSA P-256 keypair (PEM).")
    kg.add_argument("--out", required=True, help="Path to write the PKCS#8 private key PEM.")
    kg.add_argument("--pub-out", required=True, help="Path to write the SPKI public key PEM.")

    ph = cmds.add_parser("push", help="Sign a policy record and run intake.")
    ph.add_argument("--file", required=True, help="Path to the policy JSON record to sign + push.")
    ph.add_argument("--key", required=True, help="Path to the ECDSA P-256 private key PEM.")

    # F-007 (ADR-0010 §11): classifier (LLM-as-judge) config operations.
    classifier_p = groups.add_parser("classifier", help="Classifier (LLM-as-judge) config")
    ccmds = classifier_p.add_subparsers(dest="cmd", required=True)

    cset = ccmds.add_parser("set", help="Set a tenant's classifier preset + audit mode.")
    cset.add_argument("--tenant", required=True, help="Tenant UUID.")
    cset.add_argument("--team", default=_WILDCARD_UUID, help="Team UUID (new-row only).")
    cset.add_argument("--project", default=_WILDCARD_UUID, help="Project UUID (new-row only).")
    cset.add_argument("--agent", default=_WILDCARD_AGENT, help="Agent slug (new-row only).")
    cset.add_argument(
        "--model", required=True, choices=_CLASSIFIER_PRESETS, help="Classifier preset."
    )
    cset.add_argument(
        "--audit-mode", default="full", choices=_AUDIT_MODES, help="Audit privacy mode."
    )

    cget = ccmds.add_parser("get", help="Show a tenant's resolved classifier config.")
    cget.add_argument("--tenant", required=True, help="Tenant UUID.")

    cunset = ccmds.add_parser("unset", help="Clear a tenant's classifier preset.")
    cunset.add_argument("--tenant", required=True, help="Tenant UUID.")

    args = parser.parse_args(argv)
    if args.group == "policy":
        if args.cmd == "keygen":
            return _cmd_keygen(args.out, args.pub_out)
        if args.cmd == "push":
            return _cmd_push(args.file, args.key)
    elif args.group == "classifier":
        if args.cmd == "set":
            return _cmd_classifier_set(
                args.tenant, args.team, args.project, args.agent, args.model, args.audit_mode
            )
        if args.cmd == "get":
            return _cmd_classifier_get(args.tenant)
        if args.cmd == "unset":
            return _cmd_classifier_unset(args.tenant)
    parser.error("unknown command")  # pragma: no cover
    return 2  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
