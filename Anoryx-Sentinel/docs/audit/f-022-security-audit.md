# F-022 Independent Security Audit — Multi-Region Deployment (ADR-0028)

**Scope: deployment / infrastructure (Helm overlay).** Governing doc:
`docs/adr/0028-multi-region-deployment.md` · Contracts: unchanged (no API/event/policy
schema; `policy.schema.json` untouched) · `src/`: unchanged.

> **Why this audit exists.** F-022 shipped to `main` in PR #49 whose description
> claimed "security-audit (CLEAN), no High/Critical." No independent audit artifact
> was ever committed (every other shipped Sentinel feature has a
> `docs/audit/f-0XX-security-audit.md`) and the roadmap line was never ticked. The
> helm render tests DO run in CI (GitHub `ubuntu-latest` ships `helm`), but the one
> guard that could have caught the byte-identical regression
> (`test_default_render_has_no_region_resources`) asserted only substring *absence*,
> so it passed despite a whitespace-only leak — the central claims were asserted, not
> independently verified. This pass closes that gap for real: the auditor was given
> no benefit of the doubt and the PR's CLEAN claim was treated as non-existent. This
> document is the audit-of-record; remediation was applied in the F-022
> reconciliation PR and dispositions are recorded per finding.

## Executive verdict: BLOCK (as-shipped) → remediated, with one High escalated

> **UPDATE — H1 RESOLVED (app-tier enforcement).** The escalated High (H1) has
> since been remediated in the app tier: `GatewaySettings` reads
> `SENTINEL_REGION_ROLE` and `PassiveRegionGuardMiddleware` (outermost middleware,
> `src/gateway/middleware/region_guard.py`) refuses all governed traffic on a
> passive region with `503` before the terminal audit writes — so a passive region
> cannot append to its local `events_audit_log` or fork the hash chain. Proven by
> `tests/region/test_passive_no_audit_realdb.py` (real-DB row count unchanged) and
> `tests/gateway/test_region_guard.py`. ADR-0028 D2 was amended: a passive region
> serves NO governed traffic (incl. reads) until a global audit sequencer lands.
> The H1 row below is retained as the record of the finding at audit time; only
> the lower-priority **L2** identifier-hardening item remains open.

The independent pass returned **BLOCK** on the code as merged in PR #49. One **High**
(H1) is load-bearing and was **not fully closable at the deployment layer** — it
required app-tier enforcement and was escalated for human ownership
(`docs/followups/f-022-passive-readonly-enforcement.md`; now resolved, see the
update above). All other findings are remediated in the reconciliation PR. The PR
#49 body's "CLEAN, no High/Critical" claim is **not substantiated** by this pass.

### Tooling limitation (recorded honestly)
In the **audit sandbox**, `semgrep.dev` and `get.helm.sh` are blocked by egress
policy (403 CONNECT), so the Semgrep registry rulesets and a live `helm` render could
not be run *there*. This is a limitation of the audit environment, **not** of CI:
GitHub `ubuntu-latest` ships `helm`, so the `@helm_only` render tests execute in the
Sentinel CI lane (confirmed — the reconciliation PR's stronger render assertions run
and gate there), and the CI lane runs Semgrep with registry access. The changed
runtime surface is Helm YAML + one pytest file (no application Python), so the
substantive audit control was a manual injection/secret/gating review of the
templates, grounded against the `events_audit_log` schema
(`src/persistence/migrations/versions/0005_events_audit_log.py`), `hash_chain.py`,
and the audit model, cross-checked by the CI render.

## Findings table

| # | Severity | Location | Issue | Disposition |
|---|----------|----------|-------|-------------|
| H1 | **High** | `region-replication-configmap.yaml`; ADR-0028 D2/D3; `MULTI-REGION.md`; `values.yaml` | "Passive copy is read-only so the chain cannot fork" is asserted but **not enforced** at any layer F-022 ships. `SENTINEL_REGION_ROLE` is decorative env (`GatewaySettings extra="ignore"`, nothing reads it); no DB-role `REVOKE`, no app-tier serve gate. A passive region that serves a governed request appends to its **local** `events_audit_log`; `sequence_number` is a per-DB `bigserial` that logical replication does not carry, so the local write forks the hash chain off the last-replicated `row_hash` **and** collides on a sequence PK the active will later replicate → replication halts, and on failover the fork is indistinguishable from tampering. | **Escalated to human — not closed.** Deployment layer cannot correctly enforce this without an app-tier decision (the audit-write path runs on every request incl. reads). Remediation applied: the false guarantee is **removed** from the ConfigMap, ADR D2/D3 + Consequences, `values.yaml`, and the runbook, replaced with an explicit "operator MUST NOT route governed traffic to a passive region" boundary; tracked in `docs/followups/f-022-passive-readonly-enforcement.md`. |
| M1 | Medium | `region-replication-configmap.yaml:35`; `values.region-passive.example.yaml` | Cross-region replication TLS not enforced: the operator-conninfo branch appends only `password=…` (libpq defaults to `sslmode=prefer` — silent plaintext fallback); the example used `sslmode=require` (encrypt but **no** cert verification → MITM). The link carries signed policies + the audit log. | **Fixed.** Example conninfo → `sslmode=verify-full` + `sslrootcert=`; runbook §4/§5 require verify-full with a pinned CA and warn against `require`. |
| L1 | Low | `region-replication-configmap.yaml:18` | `region.replication.tables` had no allowlist guard — a values override could add a tenant-scoped / residency-bound table to the publication, replicating residency-bound rows cross-region ("data never leaves the jurisdiction" violated). Residency safety rested on convention. | **Fixed.** The ConfigMap now `fail`s the render if any listed table is outside `{policies, policy_versions, events_audit_log}`. Enforced, not conventional. (The code-review pass rated this **High**; both agreed a guard must exist.) |
| L2 | Low | `region-replication-job.yaml:34,64-72` | values.yaml strings interpolated into SQL with no quoting: `publicationName`/`subscriptionName`/table entries become bare identifiers, `activePrimaryConninfo` sits inside a single-quoted CONNECTION literal; the bootstrap Job runs the result as the Postgres superuser. A single-quote / crafted identifier breaks out → arbitrary SQL. Operator-controlled today (already privileged), real if ever fed from a self-service source. | **Partially mitigated + documented.** The table list is now allowlisted (rejects arbitrary identifiers). `publicationName`/`subscriptionName`/`activePrimaryConninfo` remain operator-owned trusted inputs; the residual (identifier regex validation + `squote`) is noted in the H1 follow-up as hardening for any future self-service region onboarding. |
| L3 | Low | `region-replication-job.yaml:42,52` | `set -eu` without `set -o pipefail`: the `sed \| psql` pipe surfaced only psql's status, so a sed error left psql to read empty stdin and exit 0 — a **silent success creating no subscription**. | **Fixed.** The pipe is replaced by a temp-file substitution under `set -e` (`sed … > "$subst_sql"; psql -f "$subst_sql"`), so a substitution failure aborts the Job. |
| L4 | Low | `region-replication-job.yaml:73-78` | The Job `envFrom`-mounted the **entire** app Secret (SENTINEL_KEY_SECRET, admin tokens, provider keys) though its only secret need is `REPLICATION_PASSWORD`. Least-privilege violation / oversized blast radius. | **Fixed.** Replaced with a single `secretKeyRef` for `REPLICATION_PASSWORD` (passive only). |
| L5 | Low | `MULTI-REGION.md` §5 | `CREATE SUBSCRIPTION` persists the conninfo (incl. password) in `pg_subscription` in plaintext and can surface in server logs — a durable credential copy outside any Secret/Vault, un-warned. | **Fixed (documented).** Runbook §5 now requires a quiet log posture for the bootstrap window (`log_statement=none`), a post-bootstrap password rotation, and prefers a `.pgpass`/passfile conninfo where supported. |
| I1 | Info | `tests/deploy/test_multiregion.py` | "Byte-identical when off" was unproven: `test_default_render_has_no_region_resources` only asserted substring absence, and the region includes were pulled via `include … | nindent N` — `nindent` on an empty string emits a trailing-whitespace line, so the default render was **not** literally byte-identical. The existing guard ran in CI (helm is present) but was too weak to catch it. | **Fixed.** The `regionLabels`/`regionEnv` includes are now gated on `region.enabled` **at the call site** (matching `service.yaml`), so nothing renders when off. New parse-only `test_region_includes_are_call_site_gated` asserts the gating; helm-gated `test_region_off_gate_dominates_subfields` asserts the render is byte-identical whether or not the region sub-fields are toggled while `region.enabled=false`. |
| I2 | Info | `tests/deploy/test_multiregion.py` | `test_region_does_not_loosen_networkpolicy` compared only the egress **port set**, not the `to:` peers (would miss a broadened peer on an allowed port). (Separately: Semgrep/helm could not run in the audit sandbox — but both run in CI.) | **Fixed.** NP test now compares full egress rules (peers + ports). Manual verification: no region template references `networkpolicy.yaml`, so the default-deny NP is provably untouched and cross-region egress stays behind the pre-existing `networkPolicy.extraEgress` opt-in. |

## What was verified clean (manual review)
- **Gating / fail-safe defaults.** Every region template gates on `region.enabled`
  (setting only `replication.enabled` / `topologySpread.enabled` /
  `geoRouting.annotations` without `region.enabled=true` renders nothing); invalid
  `region.role` and empty `region.name` hard-fail the render; region labels go to
  pod-template metadata only, never the immutable Deployment `selector.matchLabels`.
- **No committed secret.** ConfigMap / NOTES.txt / examples carry no literal
  password — only the `${REPLICATION_PASSWORD}` placeholder; the Job fails hard on an
  unset/empty password (`: "${REPLICATION_PASSWORD:?…}"`).
- **Replication direction.** Strictly one-way active→passive; the generated SQL is
  `CREATE PUBLICATION`/`CREATE SUBSCRIPTION` only (no DROP/DELETE/TRUNCATE/ALTER).
- **NetworkPolicy.** Enabling region does not add or broaden any egress rule.

## Auditor's escalation note (verbatim intent)
H1 is a real, load-bearing High: the product's tamper-evident-audit promise is
undercut by an unenforced read-only claim on the exact path this feature enables
(passive serving + failover). Per the security-auditor mandate, a High escalates to a
human regardless of retry ceiling. The reconciliation PR does not merge on the
strength of an automated pass; a human owns the H1 design decision.
