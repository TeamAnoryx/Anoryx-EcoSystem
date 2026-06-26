"""Error envelope — codes, fixed 1:1 messages, status mapping, request ids (R-001 conformance).

R-001 locks a deliberately minimal ``Error`` envelope ``{error_code, message, request_id}`` used
for EVERY non-2xx response, including the token endpoint (ADR-0001 D2: the token endpoint uses the
Rendly envelope, not the RFC 6749 error object). ``message`` is a FIXED template chosen SOLELY by
``error_code`` — no request-derived interpolation — so each code maps 1:1 to one stable string and
the envelope is structurally incapable of echoing request content or PII.

R-001 audit LOW-6 explicitly tasks R-003 with a REAL 1:1 code→message pairing test (the contract
left the pairing un-schema-enforced and the R-001 test only checked cardinality). :data:`MESSAGES`
below IS that authoritative pairing, reproduced verbatim from the contract, and
``tests/auth/test_error_envelope.py`` asserts it against the committed ``openapi.yaml`` examples.
"""

from __future__ import annotations

import secrets
from enum import StrEnum


class ErrorCode(StrEnum):
    """The LOCKED ``Error.error_code`` enum (contracts/openapi.yaml)."""

    INVALID_REQUEST = "invalid_request"
    REQUEST_TOO_LARGE = "request_too_large"
    INVALID_TOKEN = "invalid_token"
    TENANT_CONTEXT_MISMATCH = "tenant_context_mismatch"
    FORBIDDEN = "forbidden"
    MESSAGE_BLOCKED = "message_blocked"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    INTERNAL_ERROR = "internal_error"


# The authoritative 1:1 code→message pairing (verbatim from the LOCKED Error schema). LOW-6.
MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.INVALID_REQUEST: "The request body is invalid or violates a field constraint.",
    ErrorCode.REQUEST_TOO_LARGE: "The request body exceeds the maximum allowed size.",
    ErrorCode.INVALID_TOKEN: "The access token is missing, expired, or invalid.",
    ErrorCode.TENANT_CONTEXT_MISMATCH: (
        "The addressed tenant does not match the access token's authorized tenant."
    ),
    ErrorCode.FORBIDDEN: "The caller is not permitted to perform this action.",
    ErrorCode.MESSAGE_BLOCKED: "Content was blocked by the safety inspection seam.",
    ErrorCode.RATE_LIMIT_EXCEEDED: "Rate limit exceeded. Retry after the window resets.",
    ErrorCode.NOT_FOUND: "The requested resource was not found.",
    ErrorCode.CONFLICT: "The request conflicts with the current state of the resource.",
    ErrorCode.INTERNAL_ERROR: "An internal error occurred. The request was not processed.",
}

# HTTP status for each code (the status under which the contract documents that code).
STATUS: dict[ErrorCode, int] = {
    ErrorCode.INVALID_REQUEST: 400,
    ErrorCode.REQUEST_TOO_LARGE: 413,
    ErrorCode.INVALID_TOKEN: 401,
    ErrorCode.TENANT_CONTEXT_MISMATCH: 403,
    ErrorCode.FORBIDDEN: 403,
    ErrorCode.MESSAGE_BLOCKED: 403,
    ErrorCode.RATE_LIMIT_EXCEEDED: 429,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.CONFLICT: 409,
    ErrorCode.INTERNAL_ERROR: 500,
}


class AuthError(Exception):
    """A request failed with a fixed-envelope error. The app handler renders the Error body."""

    def __init__(self, code: ErrorCode) -> None:
        super().__init__(code.value)
        self.code = code

    @property
    def status_code(self) -> int:
        return STATUS[self.code]

    @property
    def message(self) -> str:
        return MESSAGES[self.code]


def new_request_id() -> str:
    """Mint a correlation id matching the contract pattern ``^[A-Za-z0-9._-]{1,64}$``."""
    return "req_" + secrets.token_urlsafe(16)


def error_body(code: ErrorCode, request_id: str) -> dict[str, str]:
    """Build the fixed Error envelope ``{error_code, message, request_id}``."""
    return {"error_code": code.value, "message": MESSAGES[code], "request_id": request_id}
