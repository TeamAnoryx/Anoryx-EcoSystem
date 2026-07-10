# Follow-up: machine-readable security-findings source for the due-diligence gate

**Context:** F-031 (ADR-0037) `no-open-critical-high` check scans the repo's
markdown findings docs (`docs/followups`, `docs/audit`) for the existing
`**Status:** OPEN` + `**Severity:** High/Critical` convention. This works and
correctly catches the real open F-022 High finding, but it is documentation-
based: it only sees findings someone wrote down in that format, and it is not a
live scanner.

**What a stronger version would do:**

1. Consume a machine-readable findings source as the authoritative input —
   e.g. a SARIF file produced by the CI SAST/security-auditor step, or a small
   committed `docs/security-findings.yaml` ledger with `{id, severity, status,
   owner}` entries. The gate would FAIL on any `status: open` with `severity in
   {high, critical}` from that source.
2. Optionally run (or require the pipeline to have run) the security-auditor /
   Semgrep/Bandit (F-016) scan and fold its High/Critical results in, so the
   gate reflects a FRESH scan rather than only historically-documented findings.
3. Keep the markdown scan as a fallback/cross-check so a human-tracked finding
   (like F-022, which is an architectural gap a scanner won't flag) is never
   silently dropped.

**Why deferred:** there is no machine-readable findings artifact in the repo
today (confirmed: no SARIF, no findings JSON/YAML). Introducing the ledger
format and wiring the CI step to emit it is a separate, cross-cutting change
(touches CI config + the security-audit process), larger than F-031's scope.
The markdown convention is the honest interim — and its limitation is stated
plainly in the check's own PASS message and in ADR-0037.
