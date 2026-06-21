import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  ADMIN_PRINCIPAL,
  BREAKGLASS_KIND,
  SSO_KIND,
  SESSION_TTL_SECONDS,
  issueBreakglassToken,
  issueSsoToken,
  issueSessionToken,
  verifySessionToken,
  type BreakglassPayload,
  type SsoPayload,
} from "@/lib/session-token";

const SECRET = "unit-test-session-secret";
const NOW = 1_000_000;

const SSO_OPTS = {
  operatorToken: "python-operator-token-abc",
  role: "tenant_admin",
  tenantId: "11111111-1111-1111-1111-111111111111",
} as const;

// ─── Break-glass ─────────────────────────────────────────────────────────────

describe("session token — break-glass", () => {
  it("round-trips a break-glass token with kind=breakglass", () => {
    const token = issueBreakglassToken(SECRET, NOW);
    const payload = verifySessionToken(token, SECRET, NOW + 60);
    expect(payload?.kind).toBe(BREAKGLASS_KIND);
    const bg = payload as BreakglassPayload;
    expect(bg.principal).toBe(ADMIN_PRINCIPAL);
    expect(bg.exp).toBe(NOW + SESSION_TTL_SECONDS);
  });

  it("rejects an expired break-glass token", () => {
    const token = issueBreakglassToken(SECRET, NOW);
    expect(verifySessionToken(token, SECRET, NOW + 31 * 60)).toBeNull();
  });

  it("rejects a tampered signature", () => {
    const token = issueBreakglassToken(SECRET, NOW);
    const tampered = `${token.slice(0, -1)}${token.endsWith("A") ? "B" : "A"}`;
    expect(verifySessionToken(tampered, SECRET, NOW + 60)).toBeNull();
  });

  it("rejects a break-glass token signed with a different secret", () => {
    const token = issueBreakglassToken(SECRET, NOW);
    expect(verifySessionToken(token, "other-secret", NOW + 60)).toBeNull();
  });

  it("issueSessionToken (deprecated shim) issues a break-glass kind", () => {
    const token = issueSessionToken(SECRET, NOW);
    const payload = verifySessionToken(token, SECRET, NOW + 60);
    expect(payload?.kind).toBe(BREAKGLASS_KIND);
  });
});

// ─── Legacy F-012 cookie migration ───────────────────────────────────────────

describe("session token — legacy F-012 cookie migration", () => {
  it("verifies a legacy {iat,exp,principal} token as break-glass", () => {
    // Simulate an F-012 token that has no `kind` field.
    const legacy = { iat: NOW, exp: NOW + SESSION_TTL_SECONDS, principal: ADMIN_PRINCIPAL };
    const payloadB64 = Buffer.from(JSON.stringify(legacy)).toString("base64url");
    const sig = createHmac("sha256", SECRET).update(payloadB64).digest("base64url");
    const token = `${payloadB64}.${sig}`;

    const payload = verifySessionToken(token, SECRET, NOW + 60);
    expect(payload?.kind).toBe(BREAKGLASS_KIND);
  });

  it("rejects a legacy token with a wrong principal", () => {
    const legacy = { iat: NOW, exp: NOW + SESSION_TTL_SECONDS, principal: "attacker" };
    const payloadB64 = Buffer.from(JSON.stringify(legacy)).toString("base64url");
    const sig = createHmac("sha256", SECRET).update(payloadB64).digest("base64url");
    expect(verifySessionToken(`${payloadB64}.${sig}`, SECRET, NOW + 60)).toBeNull();
  });

  it("rejects an expired legacy token", () => {
    const legacy = { iat: NOW, exp: NOW + 60, principal: ADMIN_PRINCIPAL };
    const payloadB64 = Buffer.from(JSON.stringify(legacy)).toString("base64url");
    const sig = createHmac("sha256", SECRET).update(payloadB64).digest("base64url");
    expect(verifySessionToken(`${payloadB64}.${sig}`, SECRET, NOW + 120)).toBeNull();
  });
});

// ─── SSO ─────────────────────────────────────────────────────────────────────

describe("session token — sso", () => {
  it("round-trips an SSO token with kind=sso and all fields", () => {
    const token = issueSsoToken(SECRET, SSO_OPTS, NOW);
    const payload = verifySessionToken(token, SECRET, NOW + 60);
    expect(payload?.kind).toBe(SSO_KIND);
    const sso = payload as SsoPayload;
    expect(sso.operatorToken).toBe(SSO_OPTS.operatorToken);
    expect(sso.role).toBe(SSO_OPTS.role);
    expect(sso.tenantId).toBe(SSO_OPTS.tenantId);
    expect(sso.exp).toBe(NOW + SESSION_TTL_SECONDS);
  });

  it("rejects an expired SSO token", () => {
    const token = issueSsoToken(SECRET, SSO_OPTS, NOW);
    expect(verifySessionToken(token, SECRET, NOW + 31 * 60)).toBeNull();
  });

  it("rejects an SSO token with a tampered signature", () => {
    const token = issueSsoToken(SECRET, SSO_OPTS, NOW);
    const tampered = `${token.slice(0, -1)}${token.endsWith("A") ? "B" : "A"}`;
    expect(verifySessionToken(tampered, SECRET, NOW + 60)).toBeNull();
  });

  it("rejects an SSO token signed with a different secret", () => {
    const token = issueSsoToken(SECRET, SSO_OPTS, NOW);
    expect(verifySessionToken(token, "other-secret", NOW + 60)).toBeNull();
  });

  it("rejects a forged SSO payload (attacker supplies kind=sso but wrong secret)", () => {
    const forged = {
      iat: NOW,
      exp: NOW + SESSION_TTL_SECONDS,
      kind: "sso",
      operatorToken: "attacker-token",
      role: "tenant_admin",
      tenantId: "evil-tenant",
    };
    const payloadB64 = Buffer.from(JSON.stringify(forged)).toString("base64url");
    const badSig = createHmac("sha256", "wrong-secret").update(payloadB64).digest("base64url");
    expect(verifySessionToken(`${payloadB64}.${badSig}`, SECRET, NOW + 60)).toBeNull();
  });

  it("rejects an SSO token missing operatorToken", () => {
    const bad = { iat: NOW, exp: NOW + SESSION_TTL_SECONDS, kind: "sso", role: "tenant_admin", tenantId: "t1" };
    const payloadB64 = Buffer.from(JSON.stringify(bad)).toString("base64url");
    const sig = createHmac("sha256", SECRET).update(payloadB64).digest("base64url");
    expect(verifySessionToken(`${payloadB64}.${sig}`, SECRET, NOW + 60)).toBeNull();
  });
});

// ─── Common malformed inputs ──────────────────────────────────────────────────

describe("session token — malformed inputs", () => {
  it("rejects null, undefined, empty, no-dot, only-dot tokens", () => {
    expect(verifySessionToken(null, SECRET, NOW)).toBeNull();
    expect(verifySessionToken(undefined, SECRET, NOW)).toBeNull();
    expect(verifySessionToken("", SECRET, NOW)).toBeNull();
    expect(verifySessionToken("no-dot", SECRET, NOW)).toBeNull();
    expect(verifySessionToken(".onlysig", SECRET, NOW)).toBeNull();
    expect(verifySessionToken("payload.", SECRET, NOW)).toBeNull();
  });
});
