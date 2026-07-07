"""Policy intake pipeline (ADR-0009 §3) — the F-008 trust boundary.

intake_policy(record_json) runs a fixed, fail-closed pipeline and returns exactly
one typed result, emitting a hash-chained audit event on EVERY path (no rejection
path skips audit — closes the F-004 audit-bypass anti-pattern):

  schema (Draft 2020-12) -> RejectedSchema (policy_intake_rejected_schema)
  signature (ES256) -> RejectedSignature (policy_intake_rejected_signature)
  scope-resolve-and-reject -> RejectedScopeMismatch (policy_intake_rejected_scope_mismatch)
  replay/rollback -> RejectedReplay (policy_intake_rejected_replay)
  persist + audit (ATOMIC) -> Accepted (policy_intake_accepted)

The verified signature claims are the AUTHORITATIVE scope (R4). Body IDs are a
cross-check only and can never widen scope. tenant_id may never be the wildcard
(threat #16). Intake runs on the privileged session (BYPASSRLS) until the
signature resolves the authoritative tenant; that tenant is then written into the
policy row's tenant_id for RLS to enforce on later reads (R10).

NEVER logged: signature bytes, raw payload, key material. Raw disputed body IDs on
a scope mismatch go ONLY to structured logs keyed by request_id (Decision B).
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from persistence.database import get_privileged_session
from persistence.repositories.policy_repository import PolicyRepository
from policy import eval_cache
from policy.audit_events import (
    append_policy_event,
    build_policy_event,
    new_intake_request_id,
    system_scope,
)
from policy.constants import (
    CONTENT_HASH_CLAIM,
    EVT_INTAKE_ACCEPTED,
    EVT_INTAKE_REJECTED_REPLAY,
    EVT_INTAKE_REJECTED_SCHEMA,
    EVT_INTAKE_REJECTED_SCOPE_MISMATCH,
    EVT_INTAKE_REJECTED_SIGNATURE,
    MAX_RECORD_BYTES,
    SIGNED_CLAIM_FIELDS,
    WILDCARD_UUID,
)
from policy.crypto import (
    CompactJWSError,
    InvalidSignature,
    load_verifying_key,
    policy_content_hash,
    verify_compact_jws,
)
from policy.results import (
    Accepted,
    IntakeResult,
    RejectedReplay,
    RejectedSchema,
    RejectedScopeMismatch,
    RejectedSignature,
)
from policy.schema_validator import validate_policy_record

log = structlog.get_logger(__name__)

_ACTION_LOGGED = "logged"
_ACTION_BLOCKED = "blocked"
_SCOPE_ID_FIELDS = ("tenant_id", "team_id", "project_id", "agent_id")
# F-023 (ADR-0029): policy types evaluate_model_policies() reads — the only
# ones a cached ModelDecision can go stale against.
_MODEL_DECISION_POLICY_TYPES = frozenset({"model_allowlist", "model_denylist", "model_approval"})


async def intake_policy(
    record_json: str | bytes | dict[str, Any],
    *,
    session: AsyncSession | None = None,
) -> IntakeResult:
    """Verify, scope-resolve, replay-check, and (on success) persist+audit a policy.

    If *session* is provided (privileged), the caller owns the transaction (used by
    tests with savepoint isolation, and by the CLI). If omitted, a privileged
    session + transaction is opened here so persist and audit commit atomically.
    """
    if session is not None:
        return await _run_intake(record_json, session)
    async with get_privileged_session() as own_session:
        async with own_session.begin():
            return await _run_intake(record_json, own_session)


async def _run_intake(
    record_json: str | bytes | dict[str, Any], session: AsyncSession
) -> IntakeResult:
    request_id = new_intake_request_id()

    # 1. Parse + coarse size guard (DoS-via-inspection, threat #9 backstop).
    record = _parse_record(record_json)
    if record is None:
        await _audit_reject(
            session, EVT_INTAKE_REJECTED_SCHEMA, system_scope(), request_id, "schema.unparseable"
        )
        return RejectedSchema("record is not valid JSON or exceeds the size bound")

    # 2. JSON Schema Draft 2020-12 (structural bounds, additionalProperties, oneOf).
    errors = validate_policy_record(record)
    if errors:
        await _audit_reject(
            session, EVT_INTAKE_REJECTED_SCHEMA, system_scope(), request_id, "schema.invalid"
        )
        log.warning(
            "policy_intake_rejected_schema",
            request_id=request_id,
            error_count=len(errors),
            first_error=errors[0],
        )
        return RejectedSchema("; ".join(errors[:3]))

    # 3. Signature verification (ES256). No key configured => fail closed.
    key = load_verifying_key()
    if key is None:
        await _audit_reject(
            session, EVT_INTAKE_REJECTED_SIGNATURE, system_scope(), request_id, "signature.no_key"
        )
        log.error("policy_intake_no_verifying_key", request_id=request_id)
        return RejectedSignature("no policy verifying key is configured (fail-closed)")
    try:
        claims = verify_compact_jws(record["signature"], key)
    except (CompactJWSError, InvalidSignature):
        await _audit_reject(
            session, EVT_INTAKE_REJECTED_SIGNATURE, system_scope(), request_id, "signature.invalid"
        )
        log.warning("policy_intake_rejected_signature", request_id=request_id)
        return RejectedSignature()

    # 3b. The signed payload must carry all eight scope claims + the content hash.
    if (
        any(field not in claims for field in SIGNED_CLAIM_FIELDS)
        or CONTENT_HASH_CLAIM not in claims
    ):
        await _audit_reject(
            session,
            EVT_INTAKE_REJECTED_SCOPE_MISMATCH,
            system_scope(),
            request_id,
            "scope_mismatch.claims_incomplete",
        )
        log.warning(
            "policy_intake_scope_mismatch", request_id=request_id, dimension="claims_incomplete"
        )
        return RejectedScopeMismatch(dimension="claims_incomplete")

    # 4. Wildcard-tenant prohibition (threat #16) — checked on the VERIFIED claims.
    if claims["tenant_id"] == WILDCARD_UUID:
        await _audit_reject(
            session,
            EVT_INTAKE_REJECTED_SCOPE_MISMATCH,
            system_scope(),
            request_id,
            "scope_mismatch.wildcard_tenant",
        )
        log.warning(
            "policy_intake_scope_mismatch", request_id=request_id, dimension="wildcard_tenant"
        )
        return RejectedScopeMismatch(dimension="wildcard_tenant")

    # 5. Scope-resolve-and-reject: verified claims are authoritative (R4).
    resolved = {field: claims[field] for field in _SCOPE_ID_FIELDS}
    mismatch = _first_scope_mismatch(claims, record)
    if mismatch is not None:
        await _audit_reject(
            session,
            EVT_INTAKE_REJECTED_SCOPE_MISMATCH,
            resolved,
            request_id,
            f"scope_mismatch.{mismatch}",
        )
        # Raw disputed IDs -> structured logs ONLY, keyed by request_id (Decision B).
        log.warning(
            "policy_intake_scope_mismatch",
            request_id=request_id,
            dimension=mismatch,
            signature_scope={f: claims.get(f) for f in _SCOPE_ID_FIELDS},
            body_scope={f: record.get(f) for f in _SCOPE_ID_FIELDS},
        )
        return RejectedScopeMismatch(dimension=mismatch)

    # 5b. Full-record integrity: the verified claims carry a hash of the ENTIRE
    # record. The eight scope claims do NOT cover the enforcement fields
    # (denied/allowed_model_ids, max_*_per_period, period, scope, reason,
    # effective_until); reject if the body's content hash disagrees — i.e. any
    # enforcement field was tampered after signing (security-auditor CRITICAL).
    if policy_content_hash(record) != claims[CONTENT_HASH_CLAIM]:
        await _audit_reject(
            session,
            EVT_INTAKE_REJECTED_SCOPE_MISMATCH,
            resolved,
            request_id,
            "scope_mismatch.content_hash",
        )
        log.warning("policy_intake_content_mismatch", request_id=request_id)
        return RejectedScopeMismatch(dimension="content_hash")

    # Past here body == claims for all eight fields; persist the claim values.
    policy_id = str(claims["policy_id"])
    version = int(claims["policy_version"])
    policy_type = str(claims["policy_type"])
    repo = PolicyRepository(session)

    # 6. Replay/rollback defense at intake (R5) — first line; DB trigger is last.
    current_max = await repo.get_max_version(policy_id)
    if current_max is not None and version <= current_max:
        await _audit_reject(
            session, EVT_INTAKE_REJECTED_REPLAY, resolved, request_id, "replay", policy_id=policy_id
        )
        log.warning(
            "policy_intake_rejected_replay",
            request_id=request_id,
            policy_id=policy_id,
            attempted_version=version,
            current_max_version=current_max,
        )
        return RejectedReplay(
            policy_id=policy_id, attempted_version=version, current_max_version=current_max
        )

    # 7. Persist + audit ATOMICALLY (one transaction owned by the caller).
    await repo.save_new_version(
        policy_id=policy_id,
        policy_type=policy_type,
        policy_version=version,
        tenant_id=resolved["tenant_id"],
        team_id=resolved["team_id"],
        project_id=resolved["project_id"],
        agent_id=resolved["agent_id"],
        effective_from=_parse_dt(str(claims["effective_from"])),
        signature=record["signature"],
        policy_payload=record,
    )
    accepted = build_policy_event(
        EVT_INTAKE_ACCEPTED,
        scope=resolved,
        request_id=request_id,
        action_taken=_ACTION_LOGGED,
        policy_id=policy_id,
    )
    await append_policy_event(session, accepted)
    log.info(
        "policy_intake_accepted",
        request_id=request_id,
        policy_id=policy_id,
        policy_version=version,
        policy_type=policy_type,
    )
    if policy_type in _MODEL_DECISION_POLICY_TYPES:
        # F-023 (ADR-0029): only these policy types feed evaluate_model_policies()
        # / the eval_cache decision cache — a budget_limit/code_scan/data_lock
        # write can never change a cached model decision, so skip the Redis
        # round trip for it. Best-effort (never raises into this pipeline).
        await eval_cache.invalidate_tenant(resolved["tenant_id"])
    return Accepted(policy_id=policy_id, policy_version=version, policy_type=policy_type)


async def _audit_reject(
    session: AsyncSession,
    event_type: str,
    scope: dict[str, str],
    request_id: str,
    violation_type: str,
    *,
    policy_id: str | None = None,
) -> None:
    """Append a rejection audit event, best-effort in a SAVEPOINT (ADR-0009 §7).

    A rejected policy is never persisted, so this audit append is the only write.
    It runs in a nested SAVEPOINT so that, if the append fails (transient DB error),
    the savepoint rolls back WITHOUT poisoning the caller's transaction, the failure
    is logged ERROR, and the typed rejection is still returned (the security outcome
    — rejection — is preserved). Every rejection path calls this, so no rejection
    path skips the audit ATTEMPT (the F-004 audit-bypass anti-pattern is closed).
    """
    event = build_policy_event(
        event_type,
        scope=scope,
        request_id=request_id,
        action_taken=_ACTION_BLOCKED,
        policy_id=policy_id,
        violation_type=violation_type,
    )
    try:
        async with session.begin_nested():
            await append_policy_event(session, event)
    except Exception:
        log.error(
            "policy_intake_reject_audit_failed",
            event_type=event_type,
            request_id=request_id,
        )


def _first_scope_mismatch(claims: dict[str, Any], record: dict[str, Any]) -> str | None:
    """Return the first signed-claim field that disagrees with the body, or None.

    ALL eight signed claims are cross-checked, not only the four scope IDs: a
    disagreement on policy_id / policy_version / effective_from / policy_type is
    also body tampering against a valid signature and is rejected (defense in depth
    beyond the four-ID scope poisoning case). The returned dimension names the
    first disagreeing field; the verified claims remain authoritative for persistence.
    """
    for field in SIGNED_CLAIM_FIELDS:
        if claims.get(field) != record.get(field):
            return field
    return None


def _parse_dt(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _parse_record(record_json: str | bytes | dict[str, Any]) -> Any | None:
    """Parse to a Python object, enforcing the coarse byte guard; None on failure.

    A pre-parsed dict comes only from trusted internal / CLI callers, so the coarse
    byte guard is skipped for it; the schema's maxLength/maxItems bounds are the
    effective size gate for dict inputs (the validator runs next regardless).
    """
    if isinstance(record_json, dict):
        return record_json
    if isinstance(record_json, (bytes, bytearray)):
        if len(record_json) > MAX_RECORD_BYTES:
            return None
        raw: bytes | str = bytes(record_json)
    elif isinstance(record_json, str):
        if len(record_json.encode("utf-8")) > MAX_RECORD_BYTES:
            return None
        raw = record_json
    else:
        return None
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
