"""Per-file processing pipeline (F-015, ADR-0018 §5 D4, R2).

Each file runs the SAME inspection as a synchronous request — NO bypass, NO
reimplementation:

  1. F-005 detectors (PII / injection / secret) via the reused
     `build_default_registry()` + `HookRegistry.run_pre_request`. A detector block
     → outcome 'blocked'; PII masking → outcome 'redacted'; a HookFailSafeError
     PROPAGATES (the worker treats it as a processing FAILURE → retry/DLQ, never a
     silent pass — ADR-0007 D3 fail-safe).
  2. F-008 model policy (only when the batch declares a target model): the reused
     `evaluate_model_policies` on the per-job TENANT session (RLS-scoped read). A
     ModelDeny → outcome 'blocked' + a reused `policy_decision_deny` audit event.
     Budget is intentionally NOT enforced for a scan: a batch scan invokes no
     model and incurs no token spend, so there is nothing to bill against a budget
     (honest scope, ADR-0018 §5). When no model is declared the file is
     detectors-only.

Detector + policy audit events are emitted by the REUSED paths (HookContext.emit /
emit_policy_decision) with the tenant's own attribution. The batch_* lifecycle
events are emitted by the worker on top.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog

from gateway.context import TenantContext

log = structlog.get_logger(__name__)

# Placeholder virtual_key_id for the worker-reconstructed context. NEVER used as a
# tenant identifier (only the sync rate-limit key uses it, which the worker skips).
_WORKER_VKEY = "bulk-worker"


@dataclass(frozen=True, slots=True)
class FileOutcome:
    """Result of processing one file."""

    status: str  # terminal batch_file status: "done" | "blocked"
    outcome: str  # security outcome: "allowed" | "blocked" | "redacted"
    reason: str | None  # short reason class (never raw content)


class _UserMessage:
    """Minimal message shape for build_hook_context (role + content)."""

    __slots__ = ("role", "content")

    def __init__(self, content: str) -> None:
        self.role = "user"
        self.content = content


def context_from_job(
    *, tenant_id: str, team_id: str, project_id: str, agent_id: str
) -> TenantContext:
    """Reconstruct a TenantContext from a job's four stable IDs (Fork 1 (a))."""
    return TenantContext(
        tenant_id=tenant_id,
        team_id=team_id,
        project_id=project_id,
        agent_id=agent_id,
        virtual_key_id=_WORKER_VKEY,
    )


async def process_file(
    *,
    content: str,
    tenant_context: TenantContext,
    request_id: str,
    model: str,
    session: Any,
    hook_registry: Any,
    gateway_settings: Any,
    orch_settings: Any,
) -> FileOutcome:
    """Run one file through F-005 detectors + (optional) F-008 model policy.

    `session` is the per-job TENANT session (RLS) used for the policy read.
    `hook_registry` is the reused detector chain (build_default_registry()).
    Raises HookFailSafeError (and any storage/processing error) to the caller so
    the worker can apply bounded retry → DLQ — a fail-safe error is NEVER swallowed
    into an 'allowed' outcome.

    Honest scope: the injection detector's optional LLM-as-judge needs a provider
    registry to route; the worker passes None, so the judge falls back to its regex
    path (fail-safe, R9). Wiring a worker provider registry is a future upgrade.
    """
    from orchestration.context import build_hook_context
    from orchestration.exceptions import HookBlockedError

    ctx = build_hook_context(
        tenant_context=tenant_context,
        request_id=request_id,
        validated_messages=[_UserMessage(content)],
        phase="pre_request",
        events_per_detector_cap=orch_settings.events_per_detector_cap,
        provider_registry=None,  # judge → regex fallback in the worker (honest scope)
        gateway_settings=gateway_settings,
    )

    # --- F-005 detectors (reused chain) ---
    try:
        masked = await hook_registry.run_pre_request(content, ctx)
    except HookBlockedError:
        # A detector blocked (secret / injection / PII-block). The detector already
        # emitted its own event in run_pre_request. The file outcome is 'blocked'.
        return FileOutcome("blocked", "blocked", "detector_block")
    # HookFailSafeError intentionally NOT caught — propagates to the worker
    # (fail-safe: a broken detector blocks/retries, never passes uninspected).

    redacted = masked != content

    # --- F-008 model policy (only when a target model is declared) ---
    if model:
        from policy.enforcement import (
            ModelDeny,
            evaluate_model_policies,
            scope_from_context,
        )

        decision = await evaluate_model_policies(session, scope_from_context(tenant_context), model)
        if isinstance(decision, ModelDeny):
            try:
                from policy.audit_events import emit_policy_decision

                await emit_policy_decision(
                    tenant_context,
                    request_id=request_id,
                    allow=False,
                    policy_id=decision.policy_id,
                    requested_model=model,
                    reason=decision.reason,
                )
            except Exception:
                log.error("bulk_policy_decision_emit_failed", request_id=request_id)
            return FileOutcome("blocked", "blocked", decision.reason)

    return FileOutcome("done", "redacted" if redacted else "allowed", None)
