/**
 * In-memory fixed-window rate limiter (ADR-0015 D1 — login throttle).
 *
 * Honest limitation: per-process and reset on restart. For the single-operator
 * v1 console this raises the bar on online token guessing; a distributed limit
 * (or an edge/Caddy limit) is the production hardening path. Pure + now-injectable
 * so it is unit-testable.
 */

interface Bucket {
  count: number;
  resetAt: number;
}

const buckets = new Map<string, Bucket>();

export interface RateLimitResult {
  allowed: boolean;
  retryAfterMs: number;
}

export function rateLimit(
  key: string,
  limit: number,
  windowMs: number,
  now: number = Date.now(),
): RateLimitResult {
  const b = buckets.get(key);
  if (!b || now >= b.resetAt) {
    buckets.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true, retryAfterMs: 0 };
  }
  if (b.count >= limit) {
    return { allowed: false, retryAfterMs: b.resetAt - now };
  }
  b.count += 1;
  return { allowed: true, retryAfterMs: 0 };
}

/** Test helper — clears all buckets. */
export function _resetRateLimits(): void {
  buckets.clear();
}
