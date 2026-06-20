import { describe, expect, it } from "vitest";

import { AdminApiError, toFriendlyError } from "@/lib/errors";

describe("error mapping (vector 9)", () => {
  it("maps 401 to a re-auth signal", () => {
    const f = toFriendlyError(new AdminApiError(401, "x"));
    expect(f.reauth).toBe(true);
    expect(f.status).toBe(401);
  });

  it("maps 403 to forbidden, no re-auth", () => {
    const f = toFriendlyError(new AdminApiError(403, "x"));
    expect(f.reauth).toBe(false);
    expect(f.message.toLowerCase()).toContain("authorized");
  });

  it("collapses 5xx to a generic message (no upstream detail)", () => {
    const f = toFriendlyError(new AdminApiError(503, "kaboom: secret stack trace at line 42"));
    expect(f.status).toBe(500);
    expect(f.message).not.toContain("kaboom");
    expect(f.message).not.toContain("stack");
  });

  it("treats unknown (non-API) errors as 500 without leaking the message", () => {
    const f = toFriendlyError(new Error("internal detail with /home/path and stack"));
    expect(f.status).toBe(500);
    expect(f.message).not.toContain("/home/path");
  });
});
