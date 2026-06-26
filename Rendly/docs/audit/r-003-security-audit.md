# R-003 Rendly Authentication (OAuth2 + JWT) — Independent Security Audit

- Task: R-003 (Rendly's first implementation task — self-contained OAuth2 + JWT issuance, verify,
  rotating refresh, revoke; in-memory `UserStore` seam).
- Scope: `Rendly/src/rendly/auth/*.py`, `Rendly/src/rendly/app.py`, `Rendly/tests/auth/*.py`,
  audited against the LOCKED `contracts/openapi.yaml` + `contracts/ids.md` + `docs/adr/0003`.
  Out of scope (later tasks): real persistence / DB / migration (R-004), per-channel RBAC
  enforcement (R-005/R-006), gateway rate-limiting.
- Branch: `feat/R-003-rendly-auth` (off `origin/main` @ 3fe98a3), pre-squash.
- Auditor stance: independent red-team, run by the `security-auditor` agent (Opus). No benefit of
  the doubt; code not written by the auditor. The auditor treated the implementer's summary as
  unverified and confirmed every item by reading the code and running the suite + Semgrep itself.
- Date: 2026-06-26

## Verdict

**PASS** — no High/Critical findings.
**0 Critical · 0 High · 0 Medium · 3 Low** (after fixes). Nothing requires human escalation.

The first pass found 0 Critical / 0 High / 2 Medium / 3 Low. Both Mediums were fixed and the
auditor independently re-verified them as CLOSED with no regression. The 3 Lows are documented
in-memory-seam limitations or ADR-disclosed follow-ups (R-004 / gateway); none escalate.

Tooling: Semgrep `p/python` + `p/security-audit` + `p/secrets` (ERROR severity) over the auth
files → 0 findings, 0 scan errors. Full suite `pytest -q` → 150 passed, 0 skipped, 0 errors,
coverage 98% (gate 90). No hardcoded secret; the fixture passwords are non-secrets and
`build_fixture_store` is wired only in tests (no production entrypoint imports it); no in-repo
signing key (the ES256 key is env-injected, fail-closed).

---

## What the implementation gets RIGHT (attacked and held)

- **Alg-confusion / `alg:none` fail closed.** `verify` pins `algorithms=["ES256"]` with an EC
  public-key object; an `alg:none` token and an HS256 token forged with the public key as the HMAC
  secret are both rejected before any key use (`tokens.py`; proven by
  `test_alg_none_token_is_rejected`, `test_alg_confusion_hs256_with_public_key_is_rejected`).
- **Full verification chain.** Signature, `exp`, `iss`, and `token_use` are verified, then the
  payload is re-parsed into the CLOSED `AccessTokenClaims` model — a smuggled extra claim or a
  non-`access` `token_use` is rejected at parse (refresh-as-access confusion blocked).
- **Identity is structurally token-derived.** No auth request DTO carries a `tenant_id`/`user_id`
  field (closed schemas); a planted body key → 400. `tenant_id`/`sub`/`roles` come only from the
  stored `User`/`Profile`, never from request input.
- **Cross-tenant isolation.** `get_user` is tenant-scoped — a token bound to tenant A resolves no
  user under tenant B → 401.
- **Refresh hardening.** Rotation on every use; reuse-detection revokes the whole family; revoke is
  idempotent; tokens are SHA-256-hashed at rest.
- **Fail-closed posture.** Missing/malformed/wrong-curve signing key → service refuses to start;
  any unexpected internal error → 500 `internal_error` (never passes traffic through).
- **Error envelope.** A real 1:1 `error_code`→`message` pairing bound to the contract examples
  (closes R-001 audit LOW-6, which only checked cardinality).

---

## Findings

### MED-1 (FIXED, re-verified CLOSED) — username-enumeration timing oracle
- File: `src/rendly/auth/service.py` (`issue_password_grant`).
- Issue: the original `if cred is None or not verify_password(...)` short-circuited, so an unknown
  username skipped the Argon2 verify and returned far faster than a known user with a wrong
  password — a *timing* enumeration oracle, contradicting the stated "no enumeration oracle"
  property (the error *shape* was already uniform).
- Fix: added `passwords.dummy_verify(plaintext)` — one Argon2 verify against a fixed module-level
  decoy hash (`_DECOY_HASH`, same `_HASHER` cost parameters), always `False`. The unknown-user
  branch now calls `dummy_verify(password)` before raising, so both failure paths perform exactly
  one Argon2 verification. Equalized by construction; covered by `test_dummy_verify_is_always_false`
  and the existing generic-401 tests.
- Re-verification: the auditor confirmed `_DECOY_HASH` carries identical Argon2 params and that both
  paths do exactly one verify → indistinguishable by time and by error. **CLOSED.**

### MED-2 (FIXED, re-verified CLOSED) — body-size cap failed open on chunked/missing Content-Length
- File: `src/rendly/app.py` (request-context middleware).
- Issue: the cap keyed only off `Content-Length`; a missing header (chunked `Transfer-Encoding`)
  skipped the check and a malformed value fell through to `too_large = False` — both fail-open,
  allowing an oversized body to be buffered on the unauthenticated token endpoint (memory DoS).
- Fix: the cap now gates on body-bearing methods (`POST/PUT/PATCH`) and defaults `too_large = True`,
  flipping to `False` only on a present, parseable, ≤cap `Content-Length`. Missing CL → 413;
  unparseable CL → 413; CL > cap → 413. GET/DELETE (no body read by any R-003 route) skip the cap.
  Covered by `test_oversized_body_is_413` and `test_body_without_content_length_fails_closed_413`
  (streamed iterator → chunked, no CL → 413).
- Re-verification: the auditor traced every branch and confirmed the reported fail-open is gone.
  Residual (rated Low/informational, NOT a reopen): the cap still trusts the *declared* CL to equal
  the actual body size; a smuggled/understated CL is a server/proxy-framing concern (compliant ASGI
  servers enforce RFC-7230) — the only fully self-contained fix is to also cap bytes read from the
  request stream, deferred to R-004. **CLOSED** for the reported bypass.

### LOW-1 — authorization staleness on refresh
- File: `src/rendly/auth/service.py` (`issue_refresh_grant`).
- Issue: refresh re-mints from `scopes`/`roles` cached at original issue time; it confirms the user
  still exists but does not re-resolve current role/scopes, so a privilege change is not reflected
  for up to the 14-day refresh window unless the family is revoked.
- Disposition: deferred to R-004 (the DB-backed `UserStore` is the live authority — re-resolve
  scopes/roles on refresh and revoke families on role change). Blast radius is bounded: per-channel
  RBAC is re-resolved server-side per channel (R-005) and does not trust the token `roles`.

### LOW-2 — unbounded in-memory refresh-store growth
- File: `src/rendly/auth/refresh.py` (`InMemoryRefreshTokenStore`).
- Issue: `_by_hash` / `_revoked_families` are never pruned.
- Disposition: documented per-process R-004 seam — `InMemoryRefreshTokenStore` must not ship;
  R-004's DB-backed store applies TTL expiry/cleanup.

### LOW-3 — no rate-limiting / lockout on `/auth/token`
- File: `src/rendly/app.py` (`/v1/auth/token`).
- Issue: the unauthenticated token endpoint is unthrottled (Argon2id slows but does not stop
  credential-stuffing / brute force).
- Disposition: disclosed in ADR-0003 §5 as a deferred follow-up; the contract already reserves
  `rate_limit_exceeded`/429. Enforce at the gateway or in R-004 (per-IP / per-username backoff).

(Informational, from the MED-2 re-verification: consider a stream-read byte cap in R-004 to remove
the residual Content-Length trust.)

---

## Escalation

No Critical or High findings. No human escalation required. Both first-pass Mediums are fixed and
independently re-verified CLOSED; the 3 Lows are documented seams / ADR-disclosed follow-ups owned
by R-004 / the gateway.
