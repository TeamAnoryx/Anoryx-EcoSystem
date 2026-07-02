# R-006 Security Audit — Rendly Role-Based Secure Channels + Manual Team Mapping

Verdict: **CLEAN** (no High/Critical). Independent red-team security-auditor (Opus), static +
Semgrep, on branch `feat/R-006-rendly-channels` (PR #46). R-006 is an authorization task, so
authorization bypass was the headline attack surface.

Scope reviewed: `src/rendly/realtime/{authz.py, resolver.py, pipeline.py, rest.py, app.py, ws.py,
registry.py}`, `src/rendly/persistence/{chat_repo.py, async_database.py, migrations/versions/
0002_chat_schema.py}`, `src/rendly/{channel.py, membership.py, enums.py}`, `src/rendly/auth/
{claims.py, dependencies.py}`, `contracts/openapi.yaml` (the `/team` addition), ADR-0006, and the
tests. Semgrep (`p/python, p/security-audit, p/secrets`, ERROR severity): **0 findings, 0 scan
errors** across the six changed source files.

## Invariants actively attacked and NOT broken
- **Fail-open:** `authorize()` is strictly fail-closed — scope pre-gate → tenant guard → `try/except
  Exception` around `resolver.resolve_role` returns `deny("resolver_error")` (never allow) →
  `status != "resolved"` → `deny("unresolvable")` → matrix miss → `deny("role")`; `evaluate` default
  returns False. The `channel is not None and (...).allowed` short-circuits never call `authorize`
  with a None channel. The `Unresolvable`/`Raising` resolver stubs deny even the real owner. No
  `async with session.begin()` wrap anywhere (Rule-6 double-begin class not reintroduced).
- **Cross-tenant:** identity is token-derived only; every read/write goes through
  `get_tenant_session` (GUC `SET LOCAL`, `NULLIF` fail-closed) on `rendly_app` NOBYPASSRLS with
  FORCE RLS + `WITH CHECK`. `map_channel_to_team`'s UPDATE is RLS-scoped; `external_ref` is never
  dereferenced (opaque, charset-bounded), so a shared label is not a cross-tenant vector.
- **Self-escalation:** a member (or non-member, or guest) holding the `channels:admin` *scope* is
  denied manage/map at the fine matrix — scope alone no longer authorizes.
- **Identity integrity:** `AuthzPrincipal` is built only from verified claims; request bodies are
  `extra="forbid"` with no identity fields; the `chat.send` frame is a closed key set — no
  claim-injection surface.
- **TOCTOU:** the WS send step-4 re-authorize runs in the same autobegun transaction as
  `insert_message`; a membership revoked during the (potentially multi-second) inspection is caught
  (proven by `test_membership_revoked_during_inspection_blocks_send` — message never persisted).
- **Honesty:** boundaries present verbatim (manual-mapping-only; resolver-seam-not-auto;
  fixed-roles-not-custom). `ManualResolver` imports only `chat_repo`/`channel`/`enums` — no
  httpx/requests/socket; there is genuinely no hidden Delta call.

## Low findings — accepted, non-gating
1. **Residual micro-TOCTOU (pipeline.py step 4).** The re-auth `member_role` SELECT and
   `insert_message` share one READ COMMITTED transaction, but the SELECT takes no row lock and
   `insert_message` locks the *channel* row, not the *membership* row. A revoke that commits in the
   sub-millisecond gap between the re-auth SELECT and the INSERT is not serialized against — one
   message could persist from an already-revoked member. **Accepted:** the meaningful window (the
   multi-second R-008 inspection between step 2 and step 4) *is* closed and tested; this is the
   irreducible check-then-act residue on localhost, requires an external admin action to land in a
   sub-ms window, and channel ids are random. Future hardening if desired: `SELECT … FOR UPDATE` on
   the membership row at step 4, or run the step-4 txn at REPEATABLE READ/SERIALIZABLE.
2. **owner == admin in the matrix (authz.py).** `_MANAGER_ROLES = {OWNER, ADMIN}`; a channel admin
   can demote/remove the owner and self-promote. **Accepted:** no capability is gained (owner and
   admin have identical action sets in R-006), so this is a governance surprise, not privilege
   escalation, and it is exactly what the documented matrix ("manage-members: owner/admin") says. If
   owner should be protected, gate owner demote/remove/promote behind an owner-only sub-rule (a
   later governance task; outside R-006's fixed-roles boundary).
3. **Same-tenant 404 timing side-channel (rest.py).** "absent/other-tenant" returns 404 after one
   `load_channel`; "present-but-no-role" returns 404 only after an extra `member_role` query — a
   timing delta (bodies/status identical). **Accepted:** cross-tenant is unaffected (RLS `None` on
   the fast path, before the resolver), and UUIDv4 channel ids make own-tenant enumeration
   infeasible — effectively unexploitable. R-005's no-oracle stance is preserved.

## Gate
CLEAN — no High/Critical. Cleared for merge. The three Low findings are documented and accepted
within R-006's stated scope (fixed roles, READ COMMITTED, no-oracle 404); none require a code change.
