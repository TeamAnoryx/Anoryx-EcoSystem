"""Orchestration hook exceptions (F-005, ADR-0007 D3).

These are raised inside the hook-chain executor and caught by the gateway
route handler to produce the appropriate error response.

HookBlockedError  — a clean detection-block (PII action=block, injection score>=threshold,
                    inbound secret).  The handler responds 403 policy_blocked.
HookFailSafeError — an unexpected exception inside a hook wrapper.  The handler
                    responds 500 internal_error and NEVER passes the request upstream
                    (ADR-0007 D3: "inspection failure → BLOCK, never pass-through").
"""

from __future__ import annotations


class HookBlockedError(Exception):
    """Raised when a clean detection result mandates blocking the request.

    Carries the error_code ('policy_blocked') and the event dict that was (or
    should be) appended to the audit log.  The handler does NOT re-emit the
    event — it was already emitted by HookContext.emit() inside the hook.
    """

    def __init__(self, error_code: str = "policy_blocked", event: dict | None = None) -> None:
        self.error_code = error_code
        self.event = event
        super().__init__(f"Request blocked by inspection hook: {error_code}")


class HookFailSafeError(Exception):
    """Raised when an unexpected exception occurs inside a hook.

    Per ADR-0007 D3: any unexpected hook exception → FAIL-SAFE BLOCK.
    The request is NEVER passed upstream on inspection failure.
    The handler responds 500 internal_error.
    """

    def __init__(self, original: Exception) -> None:
        self.original = original
        super().__init__(f"Hook fail-safe block due to unexpected exception: {original!r}")
