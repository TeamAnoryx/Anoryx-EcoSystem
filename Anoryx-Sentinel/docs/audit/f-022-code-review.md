# F-022 Independent Code Review — Multi-Region Deployment (ADR-0028)

**Reviewer:** independent code-reviewer (did not write the code). **Scope:** the
additive Helm overlay merged in PR #49. **Verdict as-shipped: BLOCK** (1 High, 5
Medium, 2 Low). Remediation applied in the F-022 reconciliation PR; dispositions below.

> Context: PR #49's body claimed "Independent code-review (APPROVE)" but no review
> artifact was committed and the roadmap was never ticked. This is the real review.

| # | Severity | Location | Finding | Disposition |
|---|----------|----------|---------|-------------|
| 1 | **High** | `region-replication-configmap.yaml:25` | `CREATE PUBLICATION … FOR TABLE {{ $tables }}` is built from the unvalidated operator list `region.replication.tables`; nothing enforces the "global stores only" scope. ADR-0028's "residency-safe by construction" holds only for the default value. | **Fixed.** Render-time allowlist guard: the ConfigMap `fail`s if any table is outside `{policies, policy_versions, events_audit_log}`. ADR wording changed from "by construction" to "by an enforced allowlist". |
| 2 | Medium | `deployment.yaml:20,84` | `include "sentinel.regionLabels/Env" … | nindent N` called unconditionally; `nindent` on the empty (region-off) helper output still emits a whitespace-only line → default render **not** byte-identical, falsifying the values.yaml/ADR/runbook claim. | **Fixed.** Both includes wrapped in `{{- if .Values.region.enabled }} … {{- end }}` at the call site (mirrors `service.yaml`). |
| 3 | Medium | `worker-deployment.yaml:26,73` | Same unguarded-call-site whitespace leak on the worker pod template. | **Fixed.** Same call-site gating applied. |
| 4 | Medium | `tests/deploy/test_multiregion.py:148` | `test_default_render_has_no_region_resources` asserts only substring absence, never byte-equality — cannot catch the leak; the headline claim is "byte-identical when off". (The guard runs in CI — helm is present on the runner — but was too weak.) | **Fixed.** Added parse-only `test_region_includes_are_call_site_gated` and helm-gated `test_region_off_gate_dominates_subfields` (byte-identical render whether or not region sub-fields are toggled while `region.enabled=false`). |
| 5 | Medium | `region-replication-job.yaml:42,52` | `set -eu` without `set -o pipefail`; the `sed \| psql` pipe reports only psql's status, so a sed failure → psql on empty stdin → exit 0 (silent success, no subscription). | **Fixed.** Replaced the pipe with a temp-file substitution under `set -e` (fails hard on a substitution error). |
| 6 | Medium | `region-replication-job.yaml:10` | Fixed Job name across releases, unlike migrate/seed/minio-init Jobs (which suffix `-{{ .Release.Revision }}` because `spec.template` is immutable — the "PR #14" bug class). A second `helm upgrade` with any pod-template change fails "field is immutable". | **Fixed.** Job name is now `…-region-replication-{{ .Release.Revision }}`; the mounted ConfigMap keeps its stable name. Test matcher updated. |
| 7 | Low | `docs/adr/0028-multi-region-deployment.md:3` | `Status: Proposed` on already-merged code. | **Fixed.** → `Status: Accepted (implemented — F-022, PR #49; hardened + independently audited in the reconciliation PR)`. |
| 8 | Low | `values.yaml:101` | Comment "the two global stores" lists three tables. | **Fixed.** → "three global stores". |

## Reviewer's overall note
The overlay's gating design, fail-fast on invalid role/name, pod-label placement
(never on the immutable selector), and one-way replication scope were otherwise sound.
The High (unvalidated table scope) and the byte-identical claim were the load-bearing
gaps; both are now enforced/tested rather than asserted. The passive-region
read-only enforcement gap is the subject of the parallel security audit (H1) and is
escalated, not silently closed.
