/**
 * Centralized error mapping (ADR-0015 D2, vector 9).
 *
 * Upstream/admin errors are mapped to operator-friendly messages. A raw upstream
 * body, stack, or trace is NEVER surfaced to the UI — only a status + a safe
 * message. 401 signals re-login; 403 forbidden; everything else a generic message.
 */

export class AdminApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "AdminApiError";
    this.status = status;
  }
}

export interface FriendlyError {
  status: number;
  message: string;
  /** True when the client should redirect to /login. */
  reauth: boolean;
}

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
      return { status, message: "The request conflicts with the current state.", reauth: false };
    case status === 422 || status === 400:
      return { status, message: "The request was rejected as invalid.", reauth: false };
    case status === 429:
      return { status, message: "Too many requests. Please slow down and retry.", reauth: false };
    default:
      // 5xx and anything unexpected — never echo the upstream body/stack.
      return { status: 500, message: "The gateway returned an error. Please try again.", reauth: false };
  }
}
