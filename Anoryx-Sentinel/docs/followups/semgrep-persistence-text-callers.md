# Per-site nosemgrep justifications for sqlalchemy-text callers in src/persistence/

**Status:** Follow-up (out of F-008 scope) · **Priority:** LOW · **Effort:** ~3–4h fleet work (32 sites × ~5–10 min review each)

## Context

`semgrep --config=p/python --config=p/secrets --severity=ERROR src/` flags **32 `sqlalchemy-text`
findings** across four persistence files:

- `src/persistence/repositories/audit_log_repository.py` (hash-chain advisory lock + reads)
- `src/persistence/migrations/versions/0002_rbac.py`
- `src/persistence/migrations/versions/0006_tenant_isolation.py`
- `src/persistence/migrations/versions/0007_tenant_routing_policy.py`

Every current call site interpolates **module constants or DDL literals** (e.g.
`text(f"SELECT pg_advisory_xact_lock({_CHAIN_ADVISORY_LOCK_ID})")` where `_CHAIN_ADVISORY_LOCK_ID`
is a module-constant int; migrations interpolate fixed schema/table/role names). **No user input
reaches any of these `text()` calls — they are safe today.** The risk is future drift: a later
modification could route user input into one of these sites, and a blanket suppression would
silently propagate a false sense of safety.

F-008's own surface (`src/policy/`, `src/gateway/router/selection.py`,
`src/gateway/routes/chat_completions.py`) is **semgrep-clean (0 findings)** — these 32 are
pre-existing F-002/F-003 code.

## Scope

For **each** of the 32 sites, do one of:

- **(a) Refactor to parameterized form** where the value can be a bind parameter
  (preferred when the dialect allows it).
- **(b) Add an inline `# nosemgrep: sqlalchemy-text` annotation** with a comment stating WHY that
  specific site is safe — e.g. `# nosemgrep: sqlalchemy-text — advisory lock ID is a module
  constant; no user input reaches this text()`.

Do **not** apply a blanket file-level or rule-level suppression; per-site review is the correct
tool here precisely because future edits must re-justify each site.

## Why deferred from F-008

Out of scope — these sites live in the persistence subsystem (F-002/F-003), not the policy engine.
A blanket suppression is the wrong fix, and per-site review is a distinct, reviewable unit of work.
The F-008 semgrep gate was scoped (with reviewer approval) to F-008-changed files, where it passes
clean.

## Acceptance

- All 32 `sqlalchemy-text` findings in the four files are either refactored to parameterized form
  or carry a per-site `# nosemgrep: sqlalchemy-text` annotation with a safety rationale.
- `semgrep --config=p/python --config=p/secrets --severity=ERROR src/persistence/` returns 0
  blocking findings.
- No blanket/file-level suppressions introduced.
