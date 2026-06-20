import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  ADMIN_PRINCIPAL,
  issueSessionToken,
  verifySessionToken,
} from "@/lib/session-token";

const SECRET = "unit-test-session-secret";
const NOW = 1_000_000;

describe("session token", () => {
  it("round-trips a valid token", () => {
    const token = issueSessionToken(SECRET, NOW);
    const payload = verifySessionToken(token, SECRET, NOW + 60);
    expect(payload?.principal).toBe(ADMIN_PRINCIPAL);
    expect(payload?.exp).toBeGreaterThan(NOW);
  });

  it("rejects an expired token (vector 4)", () => {
    const token = issueSessionToken(SECRET, NOW);
    // 30m TTL — verify well past expiry.
    expect(verifySessionToken(token, SECRET, NOW + 31 * 60)).toBeNull();
  });

  it("rejects a tampered signature (vector 4)", () => {
    const token = issueSessionToken(SECRET, NOW);
    const tampered = `${token.slice(0, -1)}${token.endsWith("A") ? "B" : "A"}`;
    expect(verifySessionToken(tampered, SECRET, NOW + 60)).toBeNull();
  });

  it("rejects a token signed with a different secret", () => {
    const token = issueSessionToken(SECRET, NOW);
    expect(verifySessionToken(token, "other-secret", NOW + 60)).toBeNull();
  });

  it("rejects a forged payload even with a valid signature for the wrong principal", () => {
    const payload = Buffer.from(
      JSON.stringify({ iat: NOW, exp: NOW + 600, principal: "attacker" }),
    ).toString("base64url");
    const sig = createHmac("sha256", SECRET).update(payload).digest("base64url");
    expect(verifySessionToken(`${payload}.${sig}`, SECRET, NOW + 60)).toBeNull();
  });

  it("rejects malformed tokens", () => {
    expect(verifySessionToken("", SECRET, NOW)).toBeNull();
    expect(verifySessionToken(undefined, SECRET, NOW)).toBeNull();
    expect(verifySessionToken("no-dot", SECRET, NOW)).toBeNull();
    expect(verifySessionToken(".onlysig", SECRET, NOW)).toBeNull();
    expect(verifySessionToken("payload.", SECRET, NOW)).toBeNull();
  });
});
