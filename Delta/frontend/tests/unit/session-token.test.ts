import { createHmac } from "node:crypto";

import { describe, expect, it } from "vitest";

import {
  ADMIN_PRINCIPAL,
  SESSION_TTL_SECONDS,
  issueSessionToken,
  verifySessionToken,
} from "@/lib/session-token";

const SECRET = "unit-test-session-secret";
const NOW = 1_000_000;

describe("session token — issue/verify round-trip", () => {
  it("round-trips a token and reports the correct principal + expiry", () => {
    const token = issueSessionToken(SECRET, NOW);
    const payload = verifySessionToken(token, SECRET, NOW + 60);
    expect(payload).not.toBeNull();
    expect(payload?.principal).toBe(ADMIN_PRINCIPAL);
    expect(payload?.exp).toBe(NOW + SESSION_TTL_SECONDS);
    expect(payload?.iat).toBe(NOW);
  });

  it("rejects an expired token", () => {
    const token = issueSessionToken(SECRET, NOW);
    expect(verifySessionToken(token, SECRET, NOW + 31 * 60)).toBeNull();
  });

  it("accepts a token right up to (but not past) expiry", () => {
    const token = issueSessionToken(SECRET, NOW);
    expect(verifySessionToken(token, SECRET, NOW + SESSION_TTL_SECONDS - 1)).not.toBeNull();
    expect(verifySessionToken(token, SECRET, NOW + SESSION_TTL_SECONDS)).toBeNull();
  });

  it("rejects a tampered signature", () => {
    const token = issueSessionToken(SECRET, NOW);
    const tampered = `${token.slice(0, -1)}${token.endsWith("A") ? "B" : "A"}`;
    expect(verifySessionToken(tampered, SECRET, NOW + 60)).toBeNull();
  });

  it("rejects a tampered payload (re-signed with the attacker's own secret)", () => {
    const forged = { iat: NOW, exp: NOW + SESSION_TTL_SECONDS, principal: ADMIN_PRINCIPAL };
    const payloadB64 = Buffer.from(JSON.stringify(forged)).toString("base64url");
    const badSig = createHmac("sha256", "wrong-secret").update(payloadB64).digest("base64url");
    expect(verifySessionToken(`${payloadB64}.${badSig}`, SECRET, NOW + 60)).toBeNull();
  });

  it("rejects a token signed with a different secret", () => {
    const token = issueSessionToken(SECRET, NOW);
    expect(verifySessionToken(token, "other-secret", NOW + 60)).toBeNull();
  });

  it("rejects a token with the wrong principal even if correctly signed", () => {
    const bad = { iat: NOW, exp: NOW + SESSION_TTL_SECONDS, principal: "attacker" };
    const payloadB64 = Buffer.from(JSON.stringify(bad)).toString("base64url");
    const sig = createHmac("sha256", SECRET).update(payloadB64).digest("base64url");
    expect(verifySessionToken(`${payloadB64}.${sig}`, SECRET, NOW + 60)).toBeNull();
  });
});

describe("session token — malformed inputs", () => {
  it("rejects null, undefined, empty, no-dot, only-dot tokens", () => {
    expect(verifySessionToken(null, SECRET, NOW)).toBeNull();
    expect(verifySessionToken(undefined, SECRET, NOW)).toBeNull();
    expect(verifySessionToken("", SECRET, NOW)).toBeNull();
    expect(verifySessionToken("no-dot", SECRET, NOW)).toBeNull();
    expect(verifySessionToken(".onlysig", SECRET, NOW)).toBeNull();
    expect(verifySessionToken("payload.", SECRET, NOW)).toBeNull();
  });

  it("rejects a token whose payload is not valid JSON", () => {
    const payloadB64 = Buffer.from("not-json").toString("base64url");
    const sig = createHmac("sha256", SECRET).update(payloadB64).digest("base64url");
    expect(verifySessionToken(`${payloadB64}.${sig}`, SECRET, NOW)).toBeNull();
  });

  it("rejects a payload missing iat/exp", () => {
    const bad = { principal: ADMIN_PRINCIPAL };
    const payloadB64 = Buffer.from(JSON.stringify(bad)).toString("base64url");
    const sig = createHmac("sha256", SECRET).update(payloadB64).digest("base64url");
    expect(verifySessionToken(`${payloadB64}.${sig}`, SECRET, NOW)).toBeNull();
  });
});
