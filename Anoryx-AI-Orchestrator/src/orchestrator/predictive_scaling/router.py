"""GET /v1/admin/traffic-forecast (O-015, ADR-0015).

Operator-gated (`ORCH_ADMIN_TOKEN`, `CoordinationSettings.admin_token` — the SAME
credential fronting every other O-005/O-007/O-013/O-014 admin seam). A pure, read-only
current-rate projection over the O-003 ingest_events stream — see ADR-0015 for why this
is the honest slice of the roadmap's "predictive scaling / traffic-spike prediction",
NOT actual autoscaling and NOT a trained model.
"""

from __future__ import annotations

import hmac
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from orchestrator.config import CoordinationSettings, PredictiveScalingSettings
from orchestrator.persistence.database import get_privileged_session
from orchestrator.persistence.repositories import count_ingest_events_in_window

router = APIRouter()

_BEARER_PREFIX = "Bearer "
_METHOD = "current_rate_projection_v1"


def _request_id() -> str:
    return "req-orch-" + uuid.uuid4().hex[:24]


def _error(status: int, code: str, message: str, request_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={"error": {"code": code, "message": message, "request_id": request_id}},
        headers={"X-Request-Id": request_id},
    )


def _isoformat(value: datetime) -> str:
    return value.isoformat()


def _require_admin(
    request: Request, settings: CoordinationSettings, request_id: str
) -> JSONResponse | None:
    """Fail-closed operator-token gate. Byte-identical policy to every other admin
    router's `_require_admin` copy in this codebase (admin/router.py,
    external_gateway/router.py, command_center/router.py)."""
    header = request.headers.get("Authorization", "")
    if not header.startswith(_BEARER_PREFIX):
        return _error(401, "unauthorized", "operator authentication required", request_id)
    presented = header[len(_BEARER_PREFIX) :]
    if not presented:
        return _error(401, "unauthorized", "operator authentication required", request_id)
    if settings.admin_token is None:
        return _error(401, "unauthorized", "operator authentication required", request_id)
    if not hmac.compare_digest(presented, settings.admin_token):
        return _error(403, "forbidden", "operator is not authorized", request_id)
    return None


@router.get("/v1/admin/traffic-forecast")
async def traffic_forecast(request: Request) -> JSONResponse:
    """A current-rate ingest-traffic projection + spike heuristic (operator-gated).

    Buckets ingest_events into two adjacent windows of ORCH_PREDICTIVE_SCALING_WINDOW_HOURS
    each (current: [now - window, now); previous: [now - 2*window, now - window)),
    computes each window's rate (events/hour), and projects the CURRENT window's rate
    forward over ORCH_PREDICTIVE_SCALING_HORIZON_HOURS, held constant
    (`current_rate_projection_v1` — mirrors Delta's D-011 forecast method exactly, never
    a regression or trained model). `spike_detected` is a deterministic threshold
    comparison (current_rate / previous_rate >= ORCH_PREDICTIVE_SCALING_SPIKE_RATIO_THRESHOLD);
    a previous window with zero events cannot compute a ratio at all
    (`insufficient_data: true`, never a divide-by-zero or a fabricated verdict). This
    endpoint takes NO autoscaling action — it only reports the projection (ADR-0015).
    """
    request_id = _request_id()
    coordination_settings: CoordinationSettings = request.app.state.coordination_settings
    auth_error = _require_admin(request, coordination_settings, request_id)
    if auth_error is not None:
        return auth_error

    settings: PredictiveScalingSettings = request.app.state.predictive_scaling_settings
    window = timedelta(hours=settings.window_hours)
    now = datetime.now(timezone.utc)
    current_since, current_until = now - window, now
    previous_since, previous_until = now - 2 * window, now - window

    async with get_privileged_session() as session:
        current_count = await count_ingest_events_in_window(
            session, since=current_since, until=current_until
        )
        previous_count = await count_ingest_events_in_window(
            session, since=previous_since, until=previous_until
        )

    current_rate = current_count / settings.window_hours
    previous_rate = previous_count / settings.window_hours
    projected_event_count_over_horizon = current_rate * settings.horizon_hours

    insufficient_data = previous_count == 0
    spike_ratio = None if insufficient_data else current_rate / previous_rate
    spike_detected = (
        not insufficient_data
        and spike_ratio is not None
        and spike_ratio >= settings.spike_ratio_threshold
    )

    body = {
        "method": _METHOD,
        "generated_at": _isoformat(now),
        "window_hours": settings.window_hours,
        "horizon_hours": settings.horizon_hours,
        "current_window": {
            "since": _isoformat(current_since),
            "until": _isoformat(current_until),
            "event_count": current_count,
            "rate_per_hour": current_rate,
        },
        "previous_window": {
            "since": _isoformat(previous_since),
            "until": _isoformat(previous_until),
            "event_count": previous_count,
            "rate_per_hour": previous_rate,
        },
        "projected_event_count_over_horizon": projected_event_count_over_horizon,
        "spike_ratio": spike_ratio,
        "spike_ratio_threshold": settings.spike_ratio_threshold,
        "spike_detected": spike_detected,
        "insufficient_data": insufficient_data,
    }
    return JSONResponse(status_code=200, content=body, headers={"X-Request-Id": request_id})
