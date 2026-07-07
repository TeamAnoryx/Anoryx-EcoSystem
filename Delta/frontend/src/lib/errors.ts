/**
 * Centralized error mapping (mirrors Anoryx-Sentinel/frontend/src/lib/errors.ts).
 *
 * Upstream/admin errors are mapped to operator-friendly messages. A raw upstream
 * stack or trace is NEVER surfaced to the UI — only a status + the upstream
 * `detail` string (Delta's admin API always returns `{"detail": "..."}` on
 * error) + a safe fallback message. The `detail` is captured (not discarded)
 * because the UI needs to distinguish specific, expected outcomes — e.g.
 * `allocation_already_decided` (409) — from a generic error.
 */

export class AdminApiError extends Error {
  readonly status: number;
  /** Raw `detail` field from the upstream JSON error body, when present. */
  readonly detail: string | undefined;

  constructor(status: number, message: string, detail?: string) {
    super(message);
    this.name = "AdminApiError";
    this.status = status;
    this.detail = detail;
  }
}

export interface FriendlyError {
  status: number;
  message: string;
  /** True when the client should redirect to /login. */
  reauth: boolean;
}

/**
 * Map an AdminApiError to an operator-friendly message. Callers that need to
 * branch on a specific `detail` (e.g. "allocation_already_decided",
 * reconciliation errors on 422) should check `err.detail` themselves BEFORE
 * falling back to this generic mapper — see allocations/actions.ts.
 */
export function toFriendlyError(err: unknown): FriendlyError {
  const status = err instanceof AdminApiError ? err.status : 500;
  switch (true) {
    case status === 401:
      return { status, message: "Your session has expired. Please sign in again.", reauth: true };
    case status === 403:
      return { status, message: "You are not authorized to perform this action.", reauth: false };
    case status === 404:
      return { status, message: "The requested resource was not found.", reauth: false };
    case status === 409:
      return {
        status,
        message:
          "This allocation was already decided by someone else. Refresh to see the outcome.",
        reauth: false,
      };
    case status === 422 || status === 400: {
      const detail = err instanceof AdminApiError ? err.detail : undefined;
      return {
        status,
        message: detail ?? "The request was rejected as invalid.",
        reauth: false,
      };
    }
    case status === 429:
      return { status, message: "Too many requests. Please slow down and retry.", reauth: false };
    default:
      // 5xx and anything unexpected — never echo the upstream body/stack.
      return {
        status: 500,
        message: "The Delta admin API returned an error. Please try again.",
        reauth: false,
      };
  }
}
