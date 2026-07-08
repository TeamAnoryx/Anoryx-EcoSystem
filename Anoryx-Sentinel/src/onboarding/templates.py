"""Sample F-008 policy templates for a freshly-provisioned sandbox tenant
(F-025, ADR-0031).

These are RAW policy records — the exact shape `sentinel-cli policy push`
expects on its `--file` argument (no `signature` field; `sign_policy_record`
computes and adds it). They are deliberately NOT auto-signed or auto-pushed
here: F-008's trust model is that a policy is signed by whoever holds the
signing private key (normally Delta/Orchestrator, or an operator's own
keypair — policy/cli.py `keygen`), never fabricated unsigned inside the
gateway/admin surface. Templates only fill in the sandbox's real IDs; the
operator runs the existing, unmodified sign+push flow (ADR-0009 §11).
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from policy.constants import WILDCARD_AGENT, WILDCARD_UUID


def _now_effective_from() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def budget_daily_cap_template(tenant_id: str) -> dict:
    """A tenant-wide daily token cap — the first policy every sandbox should
    get, so a runaway trial script cannot burn an unbounded amount of usage."""
    return {
        "policy_type": "budget_limit",
        "tenant_id": tenant_id,
        "team_id": WILDCARD_UUID,
        "project_id": WILDCARD_UUID,
        "agent_id": WILDCARD_AGENT,
        "policy_id": str(uuid.uuid4()),
        "policy_version": 1,
        "effective_from": _now_effective_from(),
        "period": "daily",
        "scope": "tenant",
        "max_tokens_per_period": 50_000,
    }


def model_allowlist_starter_template(tenant_id: str, allowed_model_ids: list[str]) -> dict:
    """A starter allow-list restricting the sandbox to a small, cheap set of
    models — a trial tenant should not be able to route to every model a
    deployment happens to have provider credentials for."""
    return {
        "policy_type": "model_allowlist",
        "tenant_id": tenant_id,
        "team_id": WILDCARD_UUID,
        "project_id": WILDCARD_UUID,
        "agent_id": WILDCARD_AGENT,
        "policy_id": str(uuid.uuid4()),
        "policy_version": 1,
        "effective_from": _now_effective_from(),
        "allowed_model_ids": list(allowed_model_ids),
    }


DEFAULT_ALLOWED_MODELS = ["gpt-3.5-turbo", "claude-haiku-4-5"]


def sandbox_templates(tenant_id: str) -> dict[str, dict]:
    """The default template bundle for a new sandbox tenant, keyed by a
    filename-safe slug (see cli.py's `sandbox create --write-templates`)."""
    return {
        "budget-daily-cap": budget_daily_cap_template(tenant_id),
        "model-allowlist-starter": model_allowlist_starter_template(
            tenant_id, DEFAULT_ALLOWED_MODELS
        ),
    }
