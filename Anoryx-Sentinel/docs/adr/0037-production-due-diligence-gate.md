# ADR-0037 — Production Due-Diligence Gate (F-031)

- Status: Accepted (implemented)
- Date: 2026-07-09
- Builds on: ADR-0033 (F-027 key vaulting — the `KeyVaultSettings.keyvault_backend`
  the secrets check reads), ADR-0003/0014 (F-003 hash-chain — reuses
  `admin.audit_read.verify_chain()`), ADR-0030 (F-024 DR — same chain-validation
  primitive), ADR-0029 (F-023 perf budget — the SLO context the config check
  sanity-bounds).
- Scope: `src/preflight/` (new), one `[project.scripts]` entry
  (`sentinel-preflight`). **No `contracts/` change, no new HTTP surface, no DB
  migration.**

## Context

Roadmap F-031: "Pre-launch checklist tool (secrets vaulted, chain valid,
migrations applied, CRITICAL/HIGH closed, SLOs validated). Depends on F-011,
F-027." This is an operator/deploy-pipeline gate, not a runtime feature — it
answers "is this deployment safe to launch?" by verifying the invariants earlier
features established, and it must be a REAL gate (non-zero exit blocks the
pipeline), not a rubber stamp.

## Decision

A `src/preflight/` package with independent checks, each **reusing an existing
subsystem** rather than reimplementing it, and each returning a `CheckResult`
(`pass` / `warn` / `fail` / `skip` + remediation). A `sentinel-preflight run`
CLI runs them all and exits non-zero iff any check hard-fails.

### The checks

1. **secrets-vaulted** — FAIL if `KeyVaultSettings.keyvault_backend == "env"`
   (upstream provider secrets are still raw env vars). Reuses F-027 directly.
2. **config-sane** — FAIL if `GatewaySettings` won't load (a required env var
   missing/invalid); WARN on SLO-adjacent concerns (out-of-range timeout, a
   localhost Redis URL that betrays a dev default). The ADR-0029 latency budget
   itself is enforced by perf tests, not at runtime, so this bounds the config
   knobs rather than measuring live latency (stated honestly).
3. **no-open-critical-high** — FAIL if any finding doc is OPEN with High/Critical
   severity, using the repo's EXISTING markdown convention (`**Status:** OPEN`
   + `**Severity:** High/Critical`, as used by `docs/followups`/`docs/audit`).
   **Honest limitation**: this sees only DOCUMENTED findings — it is not a live
   scanner and does not replace security-auditor/SAST; a clean result means "no
   documented open High/Critical", not "no vulnerabilities". (On the current
   tree this correctly FAILs on the real F-022 passive-read-only High finding —
   proving the gate bites.)
4. **migrations-at-head** — FAIL if the DB's `alembic_version` != the Alembic
   script head (in-process via `ScriptDirectory`), i.e. migrations not fully
   applied. SKIP if no `DATABASE_URL`.
5. **audit-chain-integrity** — FAIL if `admin.audit_read.verify_chain()` reports
   the F-003 hash-chain invalid (tampering/corruption). SKIP if no `DATABASE_URL`.

### Gate semantics

- **fail** blocks the gate (CLI exits 1). **warn** and **skip** are surfaced but
  do NOT block — a warn is an operator judgement call; a skip means a check
  couldn't run (e.g. offline) and coverage was incomplete, which the operator
  must weigh. This distinction is deliberate: a gate that treats "couldn't
  check" as "pass" is dishonest, and one that treats every soft concern as a
  hard block is unusable.
- `--offline` skips the two DB checks for a config-only preflight; `--skip`
  drops named checks; `--json` emits a machine-readable summary for pipelines.

### Why CLI-only

Like `sentinel-dr`/`sentinel-keyvault`/`sentinel-hipaa`, this is an operator
tool with no HTTP surface — it runs in a deploy pipeline or on an operator's
shell, not in the request path. It complements (does not replace) the runtime
`/readyz` health endpoint: `/readyz` answers "can this instance serve now?",
the gate answers "should this build be launched at all?".

## Honest limitations

- **The findings check is documentation-based**, not a live scanner (see
  check 3). It is only as complete as the findings ledger; wiring a
  machine-readable SARIF source is a natural future enhancement noted in
  `docs/followups/f-031-machine-readable-findings.md`.
- **config-sane bounds config, it does not measure live SLOs.** True latency/
  throughput validation is F-023's perf-test job, not something a static
  preflight can assert.
- **The gate verifies invariants it can observe from one host** (settings, the
  DB it's pointed at, the findings docs in the artifact). It does not verify
  cluster-wide concerns (every replica's config, network policy, TLS
  termination) — those remain infra/platform responsibilities.
