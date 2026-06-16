"""Gateway exception types and the constant error-code → (message, status) table.

The code→message pairing is NOT schema-enforced in contracts/openapi.yaml.
It is guaranteed HERE and pinned by unit tests (ADR-0006 Decision 6).
message strings are taken VERBATIM from the contract Error.message enum.
NO interpolation — the message is a constant selected solely by error_code.
"""

from __future__ import annotations

from typing import Final

# ---------------------------------------------------------------------------
# Constant lookup table: error_code → (fixed_message, http_status)
# Verbatim message strings from contracts/openapi.yaml Error.message enum.
# This table is the SINGLE SOURCE OF TRUTH for all error responses in F-004.
# It is covered by test_exceptions.py to pin the mapping.
# ---------------------------------------------------------------------------

ERROR_TABLE: Final[dict[str, tuple[str, int]]] = {
    "missing_required_header": (
        "A required header is missing or malformed.",
        400,
    ),
    "invalid_request": (
        "The request body is invalid or violates a field constraint.",
        400,
    ),
    "request_too_large": (
        "The request body exceeds the maximum allowed size.",
        413,
    ),
    "invalid_api_key": (
        "Virtual API key is missing, revoked, or invalid.",
        401,
    ),
    "id_context_mismatch": (
        "Supplied routing context does not match the API key's authorized scope.",
        403,
    ),
    "policy_blocked": (
        # Reserved for F-008. Wired here so the mapping is ready on F-008 landing.
        # F-004 does NOT emit this code itself.
        "Request blocked by policy for this tenant/team/project/agent context.",
        403,
    ),
    "rate_limit_exceeded": (
        "Rate limit exceeded. Retry after the window resets.",
        429,
    ),
    "internal_error": (
        "An internal error occurred. The request was not processed.",
        500,
    ),
}


class GatewayError(Exception):
    """Sentinel gateway domain exception.

    Carries a contract error_code. The message and HTTP status are looked up
    from ERROR_TABLE — they are never derived from request content (ADR-0006
    Decision 6, threat #9 information-disclosure).
    """

    def __init__(self, error_code: str, *, retry_after: int | None = None) -> None:
        if error_code not in ERROR_TABLE:
            # Unknown code → fall back to internal_error rather than leaking
            # an invalid code onto the wire.
            error_code = "internal_error"
        self.error_code = error_code
        message, status = ERROR_TABLE[error_code]
        self.message = message
        self.status_code = status
        self.retry_after = retry_after
        super().__init__(message)
