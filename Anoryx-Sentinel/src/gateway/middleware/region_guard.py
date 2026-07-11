"""Passive-region write-exclusion guard (F-022 audit H1 remediation, ADR-0028 D2).

A multi-region Sentinel deployment (F-022, ADR-0028) is active/passive: a
`passive` region is a replication standby, promoted on failover. The problem H1
found: nothing ENFORCED the read-only posture. Every governed request runs the
non-bypassable terminal-audit middleware, which appends a row to the region's
LOCAL `events_audit_log`. That table's `sequence_number` is a per-database
`bigserial` and its rows are hash-chained (`prev_hash`/`row_hash`); Postgres
logical replication does NOT carry sequence values. So a passive region that
serves even one governed request:

  1. FORKS the tamper-evident hash chain (its local row chains off the last
     *replicated* row_hash → a second branch that, on failover, is
     indistinguishable from tampering — defeating the core promise), and
  2. HALTS replication (the locally consumed sequence PK collides with one the
     active region later replicates → duplicate-key error stops the subscriber).

This middleware enforces the posture in the app tier, fail-closed: when
`SENTINEL_REGION_ROLE=passive`, it REFUSES every governed (audit-generating)
request with `503` BEFORE the request reaches the terminal-audit middleware — so
no local audit row is ever written and the chain cannot fork. It is the
OUTERMOST middleware (added last in create_app), wrapping even the terminal
audit, precisely so its rejection does not itself produce an audit write.

Exactly the paths that DON'T write the audit chain stay served on a passive
region: the k8s liveness/readiness probes (`_AUDIT_EXEMPT_PATHS`, reused as the
single source of truth), so the pod stays alive and is promotable on failover.
Everything else — `/v1/*`, `/admin/*`, `/metrics` — is refused until the region
is promoted to `active` (a config change + restart flips `region_role`).

Honest scope: this makes "passive serves NO governed traffic" true and enforced.
It deliberately does NOT let a passive region serve residency-local reads — that
would still write the audit chain on every read and reintroduce H1. Serving
passive reads safely needs a cross-region global audit sequencer (out of scope
for the MVP; see docs/followups/f-022-passive-readonly-enforcement.md). ADR-0028
D2 is amended to match this enforced reality.
"""

from __future__ import annotations

import uuid
from typing import Any, Awaitable, Callable, MutableMapping

import structlog
from fastapi.responses import JSONResponse

from gateway.config import get_settings
from gateway.middleware.terminal_audit_wrapper import _AUDIT_EXEMPT_PATHS

log = structlog.get_logger(__name__)

_PASSIVE_ERROR_CODE = "region_passive_standby"
_PASSIVE_MESSAGE = (
    "This region is a passive standby and does not serve governed traffic; "
    "route requests to the active region (or promote this region on failover)."
)


class PassiveRegionGuardMiddleware:
    """Outermost pure-ASGI guard: on a passive region, refuse governed traffic.

    Pure-ASGI (not BaseHTTPMiddleware) and added LAST so it is OUTSIDE the
    terminal-audit middleware — a refusal here never triggers an audit write.
    """

    def __init__(self, app: Callable) -> None:
        self._app = app

    async def __call__(
        self,
        scope: MutableMapping[str, Any],
        receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
        send: Callable[[MutableMapping[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return

        path: str = scope.get("path", "")
        # Probe paths never write the audit chain — always safe on passive, and
        # required so k8s can keep the pod alive and promote it on failover.
        if path in _AUDIT_EXEMPT_PATHS:
            await self._app(scope, receive, send)
            return

        if get_settings().region_role == "passive":
            request_id = "req-" + uuid.uuid4().hex[:32]
            log.warning(
                "passive_region_refused_governed_request",
                request_id=request_id,
                path=path,
                # Never log tenant data, headers, or bodies.
            )
            response = JSONResponse(
                content={
                    "error_code": _PASSIVE_ERROR_CODE,
                    "message": _PASSIVE_MESSAGE,
                    "request_id": request_id,
                },
                status_code=503,
                headers={"X-Request-Id": request_id, "Retry-After": "0"},
            )
            await response(scope, receive, send)
            return

        await self._app(scope, receive, send)
