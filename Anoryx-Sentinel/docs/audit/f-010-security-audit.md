# F-010 Extended Adversarial Security Audit — Anoryx Sentinel

**Scope: Deployment & Release Tooling** | Branch `task/F-010-deployment-release-native` | Governing doc: `docs/adr/0012-deployment-and-release.md` | Contracts: unchanged (F-010 adds no API/event/policy schema)

> Audit performed by the independent security-auditor (Opus), extended adversarial — the auditor did not write this code and grants it no benefit of the doubt. This pass verifies the three code-reviewer MED fixes (open NetworkPolicy egress, vacuous NP test, bundled-PG password in plain env) and probes the six explicit attack vectors. The two Affu-authorized R1 deviations (ADR-0012 §11: `tracing.py` OTLP export; middleware operational-exempt allowlists) and the Postgres-only `/readyz` decision (§12) were treated as in-scope architecture, not waived.

## Executive Verdict: PASS

No Critical and no High findings. Semgrep (`p/python`, `p/security-audit`, `p/secrets`) returned 0 findings, 0 scan errors across all six changed Python files (full-severity sweep also 0). No container-escape path, no privilege escalation, no secret exposure (image layers, k8s pod spec, `docker inspect` env, health bodies, or entrypoint logs), no Helm value-to-manifest injection, no release-pipeline injection, and no health-endpoint information disclosure was exploited.

The three code-reviewer MED fixes were independently re-verified and hold:

- NetworkPolicy renders default-deny (`policyTypes: [Ingress, Egress]`) with every egress rule port-scoped — no open all-port `to:` rule.
- The NetworkPolicy test (`tests/deploy/test_helm.py:61`) is now substantive: it asserts every egress rule carries `ports`, constrains the egress port set to {53,5432,6379,4317,4318,443}, and requires in-cluster `podSelector` egress destinations to be label-scoped (not empty {}).
- The bundled-Postgres password is referenced via `secretKeyRef` in every pod spec (app Deployment, postgres Deployment, migration Job) and appears as a literal only inside the dedicated k8s Secret `stringData` — confirmed by rendering the chart and grepping the output.

Six residual findings (1 Medium documented-and-accepted, 5 Low) are recorded below. None blocks the PR.

## Findings Table

| # | Severity | Location | Issue | Exploit / Failure Scenario | Recommended Fix |
|---|----------|----------|-------|----------------------------|-----------------|
| M1 | Medium (documented residual) | `deploy/helm/sentinel/templates/networkpolicy.yaml:88-90` (default branch) | Egress `:443` and DNS rules have NO `to:` peer, so egress is permitted to ANY IP on those ports. Plain k8s NetworkPolicy cannot match egress by FQDN. | A compromised gateway pod (e.g. via an RCE in a dependency) can exfiltrate data to an arbitrary internet host over TLS:443 or tunnel over DNS:53. The NP scopes in-cluster deps tightly but does not constrain external egress. | Documented in ADR-0012 §8/§10 as a CNI limitation. Mitigation hook ships: set `networkPolicy.providerEgressCIDRs` to restrict by IP block, or deploy a FQDN-aware CNI (Cilium/Calico) for true `*.openai.com`/`*.anthropic.com` rules. Recommend SELF_HOST elevate CIDR-pinning from optional to a production-checklist item. |
| L1 | Low | `deploy/helm/sentinel/templates/networkpolicy.yaml:24-25` | First ingress rule `from: [{podSelector: {}}]` has no `ports:`, so any pod in the namespace may reach ALL ports the gateway listens on, not just `:8000`. | A co-tenant/compromised pod in the same namespace gets unrestricted L4 reach to the gateway pod. Practical surface is limited (the container exposes only `:8000`), but the rule is broader than necessary. | Add `ports: [{port: http, protocol: TCP}]` to the same-namespace ingress rule, or scope `from` to the ingress-controller namespace/labels rather than the whole namespace. |
| L2 | Low | `deploy/otel/collector-config.yaml:54-57,60` | The standalone/Compose collector config enables the `pprof` (`:1777`) and `zpages` (`:55679`) debug extensions; the Helm ConfigMap (`configmap.yaml`) correctly omits them. | In Compose these ports are not published to the host (only 4317/4318 are), but they are reachable to any service on `sentinel-net`. pprof/zpages expose runtime internals / recent-span data — a low-value internal-recon surface and config drift vs the Helm chart. | Drop `pprof`/`zpages` from `deploy/otel/collector-config.yaml` to match the hardened Helm ConfigMap, or bind them to localhost only. |
| L3 | Low | `deploy/SELF_HOST.md:154` | Doc references `networkPolicy.allowBedrock=true`, but no `allowBedrock` key exists in `values.yaml` or `networkpolicy.yaml`. | An operator following the doc to enable AWS Bedrock egress sets a no-op value; Bedrock egress is silently NOT opened (the operator must use `extraEgress`). Operational confusion, and the failure is silent. | Fix the doc to use `networkPolicy.extraEgress` (as the `values.yaml` comments already correctly instruct), or implement the `allowBedrock` toggle in the template. |
| L4 | Low | `.github/workflows/sentinel-release.yml:142-143` (release-notes verify command) | The published `cosign verify --certificate-identity-regexp` is `https://github.com/TeamAnoryx/anoryx-sentinel/.*` — matches ANY workflow file in the repo, not just `sentinel-release.yml`. | A consumer running the documented verify command would accept a signature produced by any GHA workflow in the repo (e.g. a future, less-trusted workflow with `id-token: write`). Weakens the identity binding that keyless signing is meant to provide. | Pin the identity to the release workflow path (e.g. `--certificate-identity` ending in `/.github/workflows/sentinel-release.yml@refs/tags/<tag>`), or use a tightly-anchored regexp. |
| L5 | Low | `deploy/otel/collector-config.yaml:35-36` | `debug` exporter `verbosity: normal` on traces+metrics pipelines writes received spans/metrics to the collector stdout by default. Span hygiene (no PII/secrets/keys) is enforced upstream in `tracing.py` (R9), so this is not a disclosure today. | If a future span-attribute regression let sensitive data onto a span, `verbosity: normal` would print it to collector stdout / log aggregation. Latent, gated by the upstream R9 span-attribute discipline. | Lower to `verbosity: basic` (already TODO-flagged in the file) or wire a real backend; keep the F-009 span-attribute allowlist as the primary control. |

## Per-Attack-Vector Results

1. Container escape / privilege — NOT EXPLOITED. Dockerfile creates uid/gid 1000 (nologin shell) and sets USER 1000; the runtime stage carries no build toolchain. Rendered Helm pod + container securityContext: runAsNonRoot true, runAsUser 1000, readOnlyRootFilesystem true, allowPrivilegeEscalation false, capabilities.drop [ALL], seccompProfile RuntimeDefault; writable scratch via emptyDir /tmp + /run. The migration Job inherits the same hardened context (and only needs /tmp; the shim assembles URLs in process env, not on disk). No writable-rootfs abuse path. Bundled Postgres runs as the official image default user to own its data dir (documented dev-grade exception, single-replica, PVC-backed). Vectors 5/7; tests `test_dockerfile.py`, `test_helm.py`.
2. Secret exposure — NOT EXPLOITED. (a) Image layers: Dockerfile COPYs only pyproject.toml, src/, alembic.ini, docker-entrypoint.sh; `.dockerignore` excludes `.env*`, `*.pem`, `*.key`, `secrets`, `**/secrets`, and the whole `deploy/` tree. No secret-bearing file is in any COPY path; a grep of src/ + pyproject.toml found no baked credential (the lone PRIVATE KEY hit is a detection regex in `secret_detector.py`, not a secret, and is outside this change set). (b) Local secret files `deploy/secrets/{postgres_password,redis_password,sentinel_key_secret}` exist in the working tree but are git-ignored and untracked (`git ls-files` empty, `git check-ignore` confirms the `*` ignore rule, no commit history references them) — they are local dev artifacts, never committed, never in an image. (c) k8s pod spec: the bundled-PG password is `secretKeyRef` everywhere; no plaintext `value:` for any password in any Deployment/Job (rendered + grepped). (d) docker inspect env (Compose): `sentinel-app.environment` carries no `*_PASSWORD`; passwords arrive only as mounted file-secrets and are assembled into process env by the shim at start (same trust boundary as the file mount; honest /proc limitation noted in ADR §3). (e) Health/entrypoint: health bodies expose only status/postgres/redis/version (app release, not build/host); the entrypoint echo statements never print a password or assembled URL. Vectors 4/6/8; `test_health_endpoints.py::test_health_endpoints_no_sensitive_content`, `test_compose.py`.
3. NetworkPolicy bypass — NOT EXPLOITED (default-deny holds); external egress acknowledged (M1). Rendered NP lists both Ingress and Egress policyTypes (default-deny); egress is port-scoped to DNS + label-selected in-cluster Postgres/Redis/OTel pods + provider :443; no open all-port `to:` rule. The residuals are the FQDN-CNI limitation (M1) and the unported same-namespace ingress (L1). External-mode render (bundled=false) correctly drops the in-cluster pod rules and requires operator `extraEgress` (documented). Vector 11; `test_helm.py::test_helm_networkpolicy_restrictive`.
4. Helm injection — NOT EXPLOITED. Adversarial `secretData` and `env[].value` payloads containing double-quotes, newlines, and YAML breakout (extra: injected, privileged: true) were neutralized by the `| quote` pipe (rendered as a single escaped string). `providerEgressCIDRs` values are quoted. `image.tag`/`nameOverride`/`fullnameOverride` flow through `trunc 63 | trimSuffix` and printf/quote. No unquoted value reaches a manifest position that permits YAML or field injection. `helm lint` exits 0; `helm template` renders valid YAML in bundled + external modes.
5. Release supply-chain — NOT EXPLOITED. `actionlint` passes clean. Permissions are minimal at the workflow scope: contents write, packages write, id-token write, pages write. Signing is cosign keyless OIDC (Sigstore); the image is signed and a syft SPDX-JSON SBOM is generated and attested to the digest (not a mutable tag). Tag-to-build trust: the workflow triggers only on push tags v*; the version-derive step uses parameter expansion on GITHUB_REF_NAME (never eval) written to GITHUB_OUTPUT. GITHUB_OUTPUT injection requires a newline in the ref name, which git rejects (`git check-ref-format` confirms newlines and spaces are refused); shell-metachar tags (semicolon, dollar, parens) are not evaluated and at worst yield an invalid Docker tag that fails the build harmlessly. The only supply-chain hardening gap is the over-broad cosign verify identity-regexp (L4). Vector 12; `test_release_workflow.py`.
6. Health info disclosure — NOT EXPLOITED. /livez, /readyz, /healthz are unauthenticated by design (added to the three middleware operational-exempt frozensets, R1 Deviation 2 — additive literals, no branch/gate change; the `path in frozenset` checks are exact-match, so no /v1 surface is exempted). Bodies carry only status/postgres/redis/version; the forbidden-token test proves no password, secret, postgresql URL, redis URL, sk-, @, or bearer appears. /livez performs NO DB or Redis I/O (R5) — `test_livez_does_not_touch_db` patches `get_privileged_session` with an assert-on-call sentinel and the body reports postgres: not_checked. /readyz gates on Postgres only and honors F-009 gamma: Redis-down still returns 200 with redis: degraded (`test_readyz_200_with_degraded_flag_when_redis_down`); it reads `is_degraded()` and opens no fresh Redis connection (`test_readyz_does_not_trigger_redis_probe`). /healthz is a faithful alias; /health + /ready are byte-identical to ADR-0006 D2. Vectors 1/2/3/3b/4, regressions R-a/R-b.

## OTLP Export Deviation (R1 Deviation 1) — Verified Safe

`tracing.py::_configure_provider()` adds a BatchSpanProcessor(OTLPSpanExporter()) ONLY when OTEL_EXPORTER_OTLP_ENDPOINT is set; the wiring is wrapped so an export failure logs at WARNING and never touches the request path (R8). When the env var is unset, behavior is byte-identical to F-009 (no SpanProcessor added). The endpoint is read by the exporter from the standard OTEL_* env var — no endpoint is hardcoded in code, so there is no SSRF-by-config-default. This closes the F-009 deferral; the residual latent surface is collector-side debug verbosity (L5), gated by the upstream F-009 span-attribute discipline (error.type / error.module, never str(exc)).

## Residual / Honest Limitations

- NetworkPolicy external egress is :443/DNS to any IP (M1) — plain-NP FQDN limitation; CIDR-pinning + a FQDN-aware CNI are the documented mitigations (ADR §8/§10).
- Same-namespace ingress is not port-scoped (L1) — broader than required.
- Bundled Postgres/Redis are dev/demo-grade (single replica, default password sentinel, password-less Redis matching the frozen F-009 posture) — production must opt into managed services + an externally-managed Secret (documented; escape hatch verified to render).
- cosign keyless verification depends on Sigstore/Fulcio/Rekor availability (ADR §10) and the published verify identity is over-broad (L4).
- No live container build / image-history scan / kind-cluster server-side validation was executed in this pass (no Docker daemon or kind cluster available); image-layer and k8s-admission assertions are reasoned from the Dockerfile + `.dockerignore` COPY surface, the `helm template` render, `helm lint`, and `actionlint`. Server-side k8s validation is deferred to CI (honest gap, ADR §10).
- The <300 MB image-size figure is an ADR target measured at STEP 2, not certified here.
- The auditor does not certify the code as secure — there are no High/Critical findings in this pass.

**F-010 SECURITY VERDICT: PASS — Critical: 0, High: 0, Med: 1 (documented/accepted residual), Low: 5.**

---

## Conditions Resolution (post-audit)

No High/Critical → the PASS does not block the PR. Three Low findings were resolved immediately; the rest are accepted residuals.

| # | Resolution | Verification |
|---|-----------|--------------|
| L1 | Same-namespace ingress scoped to the gateway HTTP port only (`ports: [http]`) in `networkpolicy.yaml`. | `helm template` → all ingress rules port-scoped; deploy tests green. |
| L3 | `deploy/SELF_HOST.md` corrected: the non-existent `networkPolicy.allowBedrock` replaced with the real `networkPolicy.extraEgress` pattern (also covers external managed PG/Redis egress). | Doc now matches `values.yaml`. |
| L4 | `cosign verify` identity-regexp tightened to bind the specific release workflow + tag refs (`.../sentinel-release.yml@refs/tags/v`). | `actionlint` clean. |
| M1 | **Accepted residual** — plain k8s NetworkPolicy cannot express FQDN egress; `:443`/DNS-to-any-IP is inherent. Mitigations: `providerEgressCIDRs` + `extraEgress` + FQDN-aware CNI (ADR-0012 §8/§10). | — |
| L2 | **Accepted** — Compose collector exposes `pprof`/`zpages` (dispatch §5 spec), bound to `sentinel-net` only; the Helm ConfigMap omits them. | — |
| L5 | **Accepted (TODO F-010.2)** — `debug` `verbosity: normal` latent only; R9 span-hygiene keeps secrets off spans. TODO comment added. | — |

**Re-verification:** `helm lint` 0 failed, `helm template` valid (bundled + external), `actionlint` clean, 18 deploy tests pass. No src changes in this resolution (Helm/docs/workflow only).

---

## Fix-up addendum — PR #14 fix-up commit `ccf6113` (independent adversarial re-review)

Scope: review of the fix-up delta ONLY (image-variant split, dependency extras,
`COPY --chown`, release matrix, test-credential docs). Base commit `05a03fc` already
PASSED audit (0C/0H). Read-only; auditor did not write this code.

**Fix-up verdict: PASS — Critical: 0, High: 0, Med: 0, Low: 2 (accepted/pre-existing).**
No High/Critical findings in this pass — the fix-up does not block the PR merge.

### Threat model of the delta
New input/trust surface introduced = the optional-extras pattern, which adds three
runtime guarded-import paths (`bedrock _session`, `pii_detector _get_analyzer`, tracing
gRPC selector) plus a build-arg (`INSTALL_EXTRAS`) and a release-matrix tag scheme.
Verified each new boundary below.

### Probe results
1. **ImportError honesty / fail-safe (R3) — PASS.**
   - PII (`src/orchestration/detectors/pii_detector.py:139-160`): when Presidio is
     absent the `ImportError` is caught, `_analyzer_failed` latches, and a `RuntimeError`
     is raised. `PIIHook.inspect` (line 232-236) re-raises it; `HookRegistry._run_hook`
     (`src/orchestration/registry.py:176-184`) wraps any non-terminal exception as
     `HookFailSafeError` → 500, request NOT forwarded. **Fail-CLOSED confirmed — no
     silent pass.** The added `hint` is a static string; the existing comment-enforced
     rule "Never log exc message — may contain path info" is preserved (only
     `type(exc).__name__` + static hint are logged). No path/secret leak.
   - Bedrock (`src/gateway/router/providers/bedrock_provider.py:156-163`): absent
     `aioboto3` raises a `RuntimeError` with a static install hint (no path/secret). Lazy
     import preserved (module import / test collection never requires the extra).
   - Tracing (`src/gateway/observability/tracing.py:124-135`): gRPC-extra-absent
     `ImportError` is swallowed → degrades to the no-op span sink (R8); startup never
     crashes. This is correct fail-safe for telemetry (NOT a security control); the
     warning logs only a static hint + `type(exc).__name__`. No endpoint hardcoded —
     `OTLPSpanExporter()` reads `OTEL_EXPORTER_OTLP_ENDPOINT` itself.
2. **Slim image posture — PASS.** `Dockerfile` still `USER 1000`, `nologin` shell, no
   secrets baked (R4/R9 intact). `COPY --chown=sentinel:sentinel` grants ownership to
   the non-root uid only — NOT root, NOT world-write. The replaced `chown -R` is gone;
   no new write surface for root/other. (See Low-1 re: entrypoint ownership.)
3. **Release matrix — PASS.** Both matrix variants (`slim`,`full`) `cosign sign` and
   `cosign attest` by **immutable digest** (`@${{ steps.build.outputs.digest }}`), not by
   tag — so no unsigned/wrong image can occupy a signed tag. Tag namespaces are disjoint
   (slim → `-slim` only; full → `-full` + unsuffixed `:latest`/`:VERSION`), so slim cannot
   hijack `:latest`. OIDC identity-regexp unchanged + correct
   (`sentinel-release.yml@refs/tags/v`). Per-variant SBOMs named distinctly (no overwrite).
4. **OTLP HTTP default — PASS.** No new exposure vs gRPC: same span hygiene (R9), endpoint
   strictly env-driven, exporter only attached when `OTEL_EXPORTER_OTLP_ENDPOINT` is set.
   Helm/compose default endpoints moved `:4317`→`:4318` (transport change only).
5. **`claude-agent-sdk` removal — PASS.** Grep confirms zero imports under `src/`
   (only `orchestrator/` fleet harness + docs). Moving it to the `dev` extra is safe —
   no hidden runtime break.
6. **Docs / fixtures — PASS.** `.env.example` carries only placeholders
   (`REPLACE_ME_WITH_REAL_KEY`, empty `OTEL_EXPORTER_OTLP_ENDPOINT=`); the prior
   hardcoded `POSTGRES_PASSWORD=secret` example was REMOVED from `tests/README.md`
   (improvement). New tests use obvious dummies (`"ak"`,`"sk"`); no PII, no real secrets.

**Semgrep** (`p/python` + `p/security-audit` + `p/secrets`, `--severity=ERROR`) on the
three changed source files: **0 findings, 0 errors.**

### Findings (both Low — non-blocking)

| # | Sev | File:line | Issue | Fix |
|---|-----|-----------|-------|-----|
| FU-L1 | Low | `Anoryx-Sentinel/Dockerfile:93` | `COPY --chown=sentinel:sentinel docker-entrypoint.sh /usr/local/bin/...` makes the entrypoint owned by the runtime uid 1000, so a compromised process running as that uid could rewrite its own entrypoint (persistence across restart if the layer is writable). No privilege escalation (cannot gain root). Container is intended read-only-root-fs (mitigates). | Leave the entrypoint root-owned (`chmod +x` only, no `--chown` on that COPY), or document/enforce `readOnlyRootFilesystem: true`. Minor hardening. |
| FU-L2 | Low | `Anoryx-Sentinel/docs/adr/0012-deployment-and-release.md:211` | ADR text "`SENTINEL_PROVISION_APP_ROLE` is a local/CI test switch only (`0` in production)" is slightly imprecise: the Helm `migration-job.yaml:42` still sets it to `"1"` when the opt-in `.Values.migrations.provisionAppRole` is true (pre-existing, not changed by this fix-up). Not a regression; the role-provisioning path is gated + documented (`provisionAppRole=false` for managed PG). | Soften the ADR wording to "default `0`; opt-in for self-host first-run migrations via `migrations.provisionAppRole`" for accuracy. |

**Re-verification:** Semgrep clean (3 src files); `helm template` renders valid images for
slim (`0.10.0-slim`) and full (`0.10.0-full`); no top-level imports of the extracted heavy
deps in `src/` (slim collection safe); fail-safe BLOCK path traced end-to-end.
