import { afterEach, describe, expect, it } from "vitest";

import { _resetRateLimits, rateLimit } from "@/lib/rate-limit";

describe("rate limit (login throttle, M2)", () => {
  afterEach(() => _resetRateLimits());

  it("allows up to the limit then blocks within the window", () => {
    const now = 1_000;
    for (let i = 0; i < 3; i += 1) {
      expect(rateLimit("ip", 3, 1000, now).allowed).toBe(true);
    }
    const blocked = rateLimit("ip", 3, 1000, now);
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfterMs).toBeGreaterThan(0);
  });

  it("resets after the window elapses", () => {
    rateLimit("ip", 1, 1000, 0);
    expect(rateLimit("ip", 1, 1000, 500).allowed).toBe(false);
    expect(rateLimit("ip", 1, 1000, 1001).allowed).toBe(true);
  });

  it("tracks keys independently", () => {
    expect(rateLimit("a", 1, 1000, 0).allowed).toBe(true);
    expect(rateLimit("a", 1, 1000, 0).allowed).toBe(false);
    expect(rateLimit("b", 1, 1000, 0).allowed).toBe(true);
  });
});
