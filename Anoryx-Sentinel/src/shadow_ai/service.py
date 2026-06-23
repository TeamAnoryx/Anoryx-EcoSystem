"""F-018 shadow-AI service — read-triggered analysis + dedup emission (ADR-0021 §6).

`get_candidates(tenant_id)` is the single entry point the admin endpoint calls:

  1. read the tenant's recent `shadow_ai_detected_outbound` rows on a TARGET tenant
     session (RLS-scoped — vector 10), plus recent `shadow_ai_candidate_detected`
     rows for dedup;
  2. classify them into candidates (pure, `classifier.classify`);
  3. emit a `shadow_ai_candidate_detected` audit event for each NEW candidate
     (dedup by `candidate_key` within the day bucket) on the PRIVILEGED session
     (the hash chain is global — append() asserts privilege);
  4. return the candidates plus the honesty disclaimer (always present).

Fail-closed (ADR-0021 §5, mirrors `data_lock/config.py`): any DB/parse error
raises `ShadowAiServiceError`; the endpoint surfaces it as a 500 rather than
returning a partial or empty list that could read as "no shadow-AI found".
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import structlog

from persistence.database import get_privileged_session, get_tenant_session
from persistence.repositories.audit_log_repository import AuditLogRepository
from shadow_ai import constants as C
from shadow_ai.classifier import classify
from shadow_ai.models import Candidate, CandidateReport

log = structlog.get_logger(__name__)


class ShadowAiServiceError(Exception):
    """Raised when the candidates analysis cannot complete (fail-closed)."""


def _now_rfc3339_z() -> str:
    """RFC3339 UTC 'Z' form — matches every production audit writer."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _candidate_event(candidate: Candidate, *, request_id: str) -> dict[str, object]:
    """Build the audit event dict for a candidate.

    The attributed `team_id` / `project_id` are copied from the candidate (which
    took them verbatim from the raw event's server-stamped fields) — never from
    caller input (R4). `agent_id` is the emitter slug (ADR-0007 D8). `fired_signals`
    is comma-joined for the String(128) column; the endpoint splits it back to an
    array at the API boundary.
    """
    return {
        "event_type": C.CANDIDATE_EVENT_TYPE,
        "action_taken": "logged",
        "event_id": str(uuid.uuid4()),
        "event_timestamp": _now_rfc3339_z(),
        "request_id": request_id,
        "tenant_id": candidate.tenant_id,
        "team_id": candidate.team_id,
        "project_id": candidate.project_id,
        "agent_id": C.DETECTOR_SLUG,
        "detected_endpoint": candidate.endpoint,
        "traffic_volume": candidate.call_count,
        "first_seen_at": candidate.first_seen,
        "selected_provider": candidate.provider,
        "confidence_band": candidate.confidence_band,
        "fired_signals": ",".join(candidate.fired_signals),
        "candidate_key": candidate.candidate_key,
    }


async def get_candidates(tenant_id: str, *, request_id: str) -> CandidateReport:
    """Analyze a tenant's egress events and return review candidates.

    Read-triggered: each call re-derives candidates from the current event stream
    and records any not-yet-recorded ones. Idempotent within a day bucket via the
    candidate_key dedup. A rare concurrent-poll race may double-record a candidate;
    this does not break chain integrity but may surface as a duplicate candidate row
    in audit reports — a known per-poll limitation (ADR-0021 §6 D6).
    """
    try:
        window_bucket = datetime.now(UTC).date().isoformat()

        # get_tenant_session autobegins (it issues set_config before yielding), so
        # these pure SELECTs run directly on the session — no `session.begin()`
        # wrapper (that would raise "a transaction is already begun"; see
        # admin/keys.py and admin/audit_log.py for the same read pattern). No
        # commit needed: the read writes nothing.
        async with get_tenant_session(tenant_id) as session:
            repo = AuditLogRepository(session)
            raw_rows = await repo.list_for_tenant_by_event_type(
                tenant_id, C.RAW_EGRESS_EVENT_TYPE, limit=C.MAX_RAW_EVENTS
            )
            existing_rows = await repo.list_for_tenant_by_event_type(
                tenant_id, C.CANDIDATE_EVENT_TYPE, limit=C.MAX_CANDIDATE_LOOKBACK
            )

        existing_keys = {r.candidate_key for r in existing_rows if r.candidate_key}
        candidates = classify(raw_rows, tenant_id, window_bucket=window_bucket)

        # Emit NEW candidates, bounded by MAX_CANDIDATES_PER_EMIT so a single poll
        # cannot fire an unbounded burst of privileged appends (each takes the global
        # chain advisory lock). The RETURNED list is never truncated; only emission
        # is capped, and a cap hit is logged (no silent truncation).
        emitted = 0
        for candidate in candidates:
            if candidate.candidate_key in existing_keys:
                continue
            if emitted >= C.MAX_CANDIDATES_PER_EMIT:
                log.warning(
                    "shadow_ai.service.emit_capped",
                    tenant_id=tenant_id,
                    cap=C.MAX_CANDIDATES_PER_EMIT,
                    total_candidates=len(candidates),
                )
                break
            async with get_privileged_session() as ps:
                async with ps.begin():
                    await AuditLogRepository(ps).append(
                        _candidate_event(candidate, request_id=request_id)
                    )
            emitted += 1

        return CandidateReport(candidates=tuple(candidates), disclaimer=C.HONESTY_DISCLAIMER)
    except Exception as exc:  # fail-closed — never return a misleading clean result
        # exc_info intentionally omitted: a raw DB error may carry row data; correlate
        # via request_id instead. Re-raised as ShadowAiServiceError → clean 500.
        log.error("shadow_ai.service.analysis_failed", tenant_id=tenant_id)
        raise ShadowAiServiceError("shadow-AI candidate analysis failed") from exc
