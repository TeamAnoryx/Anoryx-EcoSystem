"""Body-size / edge guard middleware (ADR-0006 pipeline step 2).

Enforces MAX_BODY_BYTES (default 1 MiB) BEFORE body parsing — an attacker
cannot exhaust inspection resources with an oversize body (threat #8).

Also rejects requests where both Transfer-Encoding and Content-Length are
present (request-smuggling signal, threat #3 partial in-process defense).

The body is read once here and stored on request.state.raw_body so that
downstream handlers can access it without a second read from the stream
(which would be empty after the first read).

Rejects:
  - Content-Length > MAX_BODY_BYTES → 413 request_too_large
  - body read exceeds MAX_BODY_BYTES → 413 request_too_large
  - Transfer-Encoding + Content-Length both present → 400 invalid_request
    (smuggling rejection; the request cannot be safely interpreted)
"""

from __future__ import annotations

import uuid

import structlog
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from gateway.config import get_settings
from gateway.exceptions import ERROR_TABLE

log = structlog.get_logger(__name__)

# Paths exempt from body-size check (no body expected).
_BODY_EXEMPT_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def _error_json(error_code: str, request_id: str) -> JSONResponse:
    message, status = ERROR_TABLE[error_code]
    return JSONResponse(
        content={"error_code": error_code, "message": message, "request_id": request_id},
        status_code=status,
        headers={"X-Request-Id": request_id},
    )


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """Edge guard: enforce body-size cap and reject smuggling signals.

    Runs BEFORE auth (ADR-0006 pipeline step 2) so large bodies are rejected
    before any key lookup or expensive processing is attempted.

    NOTE: Starlette BaseHTTPMiddleware exception propagation to FastAPI
    exception handlers is unreliable across versions. This middleware catches
    all error conditions and returns JSONResponse directly.
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        settings = get_settings()
        max_bytes = settings.max_body_bytes
        request_id = "req-" + uuid.uuid4().hex[:32]

        # --- Request-smuggling rejection (threat #3 partial in-process defense) ---
        has_te = "transfer-encoding" in request.headers
        has_cl = "content-length" in request.headers
        if has_te and has_cl:
            log.warning(
                "request_smuggling_signal",
                path=request.url.path,
                has_transfer_encoding=True,
                has_content_length=True,
            )
            return _error_json("invalid_request", request_id)

        # --- Content-Length pre-check (fast path before reading body) ---
        if request.method not in _BODY_EXEMPT_METHODS:
            cl_header = request.headers.get("content-length")
            if cl_header is not None:
                try:
                    cl_value = int(cl_header)
                except ValueError:
                    return _error_json("invalid_request", request_id)
                if cl_value > max_bytes:
                    log.info(
                        "request_too_large_content_length",
                        content_length=cl_value,
                        max_bytes=max_bytes,
                    )
                    return _error_json("request_too_large", request_id)

            # --- Capped body read ---
            chunks: list[bytes] = []
            total = 0
            async for chunk in request.stream():
                total += len(chunk)
                if total > max_bytes:
                    log.info("request_too_large_body_read", bytes_read=total, max_bytes=max_bytes)
                    return _error_json("request_too_large", request_id)
                chunks.append(chunk)

            raw_body = b"".join(chunks)
            request.state.raw_body = raw_body
        else:
            request.state.raw_body = b""

        return await call_next(request)
