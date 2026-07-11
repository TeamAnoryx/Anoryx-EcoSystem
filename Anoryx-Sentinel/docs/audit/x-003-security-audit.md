# Security Audit — X-003 policy-intake HTTP ingress (`POST /admin/policies/intake`)

- **Feature:** X-003 (budget-enforcement loop closure) — a NEW authenticated HTTP
  ingress into Sentinel's policy store; reverses ADR-0009 §11 R1 for `intake_policy()`
  only (ADR-0042).
- **Date:** 2026-07-11
- **Reviewer:** independent security-auditor (arms-length, red-team), post-implementation.
- **Verdict:** **CLEAN / mergeable.** No High or Critical findings. Two Low findings
  (both pre-existing in out-of-scope modules, both fail-safe, neither a bypass).
- **Human sign-off:** product owner authorized the ADR-0009 §11 R1 reversal (2026-07-11);
  ADR-0042 Accepted.

## Scope reviewed

`src/admin/policies.py` (new route), `src/admin/router.py` (mount),
`contracts/openapi.yaml` (`adminIntakePolicy` path + schemas/responses/Error enum),
`docs/adr/0042-policy-intake-http-endpoint.md`, `tests/admin/test_policy_intake_route.py`,
and the Orchestrator e2e harness (`_sentinel_shim.py`, `conftest.py`,
`test_distribution_e2e.py`). Cross-checked against `src/policy/intake.py`,
`src/policy/crypto.py`, `src/policy/results.py`, `src/admin/auth.py`, `src/admin/scope.py`,
`src/gateway/middleware/request_validation.py`, and `src/gateway/main.py`.

## Attack classes exercised (all defended)

1. **Auth bypass** — `require_admin` (parent router dep) runs before `reject_sso_global`
   (policies-router dep); both fail closed. Break-glass `SENTINEL_ADMIN_TOKEN` only;
   `hmac.compare_digest`; unset token never matches. Data-plane virtual key can't reach
   `/admin/*` (AuthMiddleware skips the prefix). Confirmed by route tests.
2. **Scope/tenant confusion** — route adds zero trust; authoritative scope resolved from
   the verified signature inside `intake_policy()`; body IDs are cross-check-only; wildcard
   tenant rejected; a stolen admin bearer still cannot forge enforcement without the
   separate ES256 signing key (two independent secrets).
3. **Signature/integrity** — raw received bytes forwarded unchanged; full-record content
   hash binds every non-signature field; forged/wrong-alg/absent-key all → RejectedSignature
   (403), nothing persisted, audited.
4. **Replay/rollback** — monotonic `policy_version` defense unchanged through the HTTP path.
5. **Info leak** — bounded `Error` envelope, fixed constant messages, `request_id` never
   record-derived; disputed IDs only in server-side logs keyed by request_id.
6. **DoS/resource** — body size capped by RequestValidationMiddleware before intake, and
   re-guarded by `intake_policy()`. (Rate limiting — Low finding #2.)
7. **Fail-closed** — any exception escaping `intake_policy()` → 500 via the generic handler
   with the transaction rolled back (nothing persists). (One edge case — Low finding #1.)
8. **Audit trail** — hash-chained audit on every accept + every rejection branch.
9. **e2e integrity** — the Orchestrator e2e drives the real mounted route + real
   `require_admin`/`reject_sso_global`; new assertions provably fail against the old shim.

## Findings

### Low #1 — non-UTF-8 JWS segment → uncaught 500 instead of audited 403 — **FIXED in this PR**

`crypto.verify_compact_jws` decodes the JWS header segment before verifying and caught only
`json.JSONDecodeError`; a base64url segment decoding to invalid UTF-8 raised
`UnicodeDecodeError`, which `intake_policy()` did not classify — so the new ingress returned
500 with **no rejection audit event** (attacker-reachable pre-signature by the break-glass
principal). Not a bypass: fail-closed, nothing persisted.

**Fix applied (in-scope, per the auditor's own suggested location):** `src/policy/intake.py`
now includes `UnicodeDecodeError` in the signature-verification `except`, mapping it to
`RejectedSignature` → the contract's audited **403 `policy_intake_signature_rejected`**.
`crypto.py` (locked / out of scope) untouched. Regression test added
(`test_non_utf8_signature_segment_rejected_as_signature`), verified to fail (500) without the
fix and pass (403) with it.

### Low #2 — no rate limiting on the `/admin/*` surface — **deferred (tracked)**

A pre-existing property of the entire admin surface (`RateLimitMiddleware` is not mounted
app-wide); `POST /admin/policies/intake` inherits it. Impact is bounded: gated to the single
deploy-injected break-glass secret, body size capped before intake, and `intake_policy()`
re-guards the record size. This is resource pressure by a **trusted principal**, not an
unauthenticated DoS. The auditor's recommendation: acceptable to defer given break-glass
gating; add an admin-surface rate limit if the break-glass principal is ever exposed beyond
the O-004 loopback path. **Not changed in X-003** (it would alter the whole admin middleware
stack, out of scope). Tracked here for a future admin-hardening task.

## Conclusion

The new ingress **adds ingress, not trust** — every record still runs the full fail-closed
`intake_policy()` pipeline (schema → ES256 signature → scope-from-signature → content-hash →
replay) and is hash-chain audited on every path. Merge recommendation: **CLEAN**, with Low #1
fixed here and Low #2 tracked for future admin-surface hardening.
