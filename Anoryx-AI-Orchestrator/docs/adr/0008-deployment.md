# ADR-0008 — Deployment (Docker + Helm + K8s)

- Status: Accepted
- Date: 2026-07-07
- Task: O-008 (eighth Orchestrator task, first deployment task)
- Builds on: Anoryx-Sentinel's F-010 deployment (ADR-0012 Part 1, ADR-0027 Part 2) — the
  established deploy pattern this task mirrors, per the ecosystem roadmap ("Finish F-010
  first — it establishes the deploy pattern the other products' deployment tasks copy").
- Supersedes: nothing. Adds a Dockerfile, docker-compose stack, and Helm chart; does not
  alter any O-001…O-007 runtime code, contract, or persistence schema.

## Context

O-008 is "Deployment — Helm, K8s, mTLS provisioning, Vault." The roadmap's own F-010 entry
describes the SAME scope for Sentinel ("Vault/KMS secrets, mTLS provisioning"), but the
ADRs Sentinel actually shipped under (ADR-0012 §10, ADR-0027 "Honest deferrals") explicitly
REJECTED both for v1:

> "External secret managers (Vault / AWS-SM) required at v1 — REJECTED... Deferred to
> F-010.1" (ADR-0012 §10)
>
> "Vault / KMS for secret material — this Part uses K8s Secrets... Vault is a later
> hardening." / "Public TLS / cert-manager / hardened production ingress — the demo uses
> port-forward." (ADR-0027 "Honest deferrals")

Sentinel's own F-034 (internal service mesh auth / mTLS) and F-027 (provider key vaulting /
Vault-KMS) remain separate, unshipped, 🔮 SPECULATIVE roadmap tasks — there is no shipped
mTLS or Vault artifact anywhere in the ecosystem today to mirror.

The Orchestrator's own source, however, makes forward-looking promises that point AT this
task specifically: `contracts/openapi.yaml`'s "HONESTY BOUNDARIES" rule 14(a) states mTLS
certificate PROVISIONING is "DEFERRED to O-008," and `app.py`/`config.py`/`security.py`/
`database.py` docstrings each say mTLS termination / TLS policy is "O-008."

This ADR resolves that tension conservatively: it delivers the SAME Docker/Helm/K8s-native-
secrets pattern F-010 actually shipped (not the pattern the roadmap prose aspirationally
describes), and re-states the mTLS/Vault deferral explicitly and honestly here, rather than
building a first-of-its-kind mTLS/Vault integration with no prior art, no dedicated review
cycle, and no consuming task (D-010/R-010) ready yet to depend on it.

## Decision — resolved forks

| Fork | Decision |
|------|----------|
| **A** — scope vs. the roadmap's literal "mTLS provisioning, Vault" text | **A1**: ship Docker + Helm + K8s-native Secrets (mirrors F-010's ACTUAL shipped scope), and formally re-defer mTLS + Vault with this ADR — the same "honest deferral" move ADR-0012/ADR-0027 made for Sentinel itself. Building real mTLS/Vault now would be a genuine ecosystem FIRST with no shipped reference implementation, elevated risk for an unattended run, and no immediate consumer (D-010/R-010 are themselves unshipped and depend on this decision, not the other way around). |
| **B** — interim peer authentication for the ingest seam | **B1**: unchanged — the shared `ORCH_INGEST_HMAC_SECRET` (ADR-0002/ADR-0003) remains the peer authenticator until real mTLS ships. This was already the documented interim state; this ADR does not weaken it, only makes explicit that O-008 does not close it. |
| **C** — container image strategy | **C1**: a single multi-stage image (builder + runtime), non-root uid 1000, mirrors Sentinel's Dockerfile (ADR-0012 D1) exactly. **No slim/full variant split** — the Orchestrator has no optional heavy extras (no boto3/Presidio/spaCy), so one variant covers every deployment. |
| **D** — secret delivery | **D1**: file-based Docker secrets for Compose (entrypoint shim reads `/run/secrets/*`); native Kubernetes `Secret` via `envFrom: secretRef` for Helm (mirrors ADR-0012 D2 / ADR-0027 D3). Passwords/tokens never appear in `docker-compose.yml`, a Deployment/Job pod spec, or `docker inspect` output. |
| **E** — bundled datastore | **E1**: bundled Postgres only (dev/demo-grade, `postgres.bundled=true` default) with an `.external` escape hatch, same shape as Sentinel's. **No Redis, no MinIO, no worker, no separate frontend** — the Orchestrator has no bulk pipeline and serves its admin UI in-process (O-007), so none of Sentinel's other bundled stores apply. |
| **F** — migration ordering | **F1**: copies ADR-0027 D1 verbatim — the migrate Job is a NORMAL Job (not a Helm hook, which would race the not-yet-existing bundled Postgres on a fresh install), gated by a `wait-for-postgres` initContainer; the serve Deployment gates on schema-at-head via a `wait-for-migrate` initContainer polling `alembic current`. |
| **G** — health probes | **G1**: liveness/readiness/startup probes all target the single existing `GET /health` endpoint (no DB-gated check). The Orchestrator does not yet have Sentinel's `/livez` + `/readyz` split (ADR-0012 D5) — adding that split is APPLICATION code, out of scope for a deployment task, and is named here as a deferral rather than silently worked around. |
| **H** — NetworkPolicy | **H1**: restrictive-by-default (`Ingress` + `Egress` both listed), scoped egress to the bundled Postgres pod + DNS, mirroring ADR-0012 §8. Two rules are intentionally OPEN by default with an escape hatch, because the Orchestrator's peers are dynamic and not knowable at chart-render time: (a) egress to arbitrary Sentinel instances (the O-005 registry) is `:443` to any IP, restrictable via `sentinelEgressCIDRs`; (b) ingress on the ingest port from Sentinel instances outside this namespace is open, restrictable via `ingressCIDRs`. Both are the same "plain NetworkPolicy cannot match by hostname" honest limitation ADR-0012 §10 already documented for Sentinel's provider egress. |
| **I** — deploy-artifact tests | **I1**: `tests/deploy/test_dockerfile.py` / `test_compose.py` / `test_helm.py`, static-assertion + `helm lint`/`helm template` tests that ride the existing `orchestrator-ci.yml` pytest run (skipped where `helm` is absent), mirroring Sentinel's `tests/deploy/` pattern rather than inventing a new CI mechanism. |

## Honest deferrals (named, not half-built)

- **Vault / KMS for secret material** — this task uses native K8s Secrets (Fork D), same
  posture Sentinel's own F-010 shipped with. A dedicated secret-manager integration is
  future work, tracked at the Sentinel level as F-010.1/F-027 and not yet mirrored here.
- **mTLS between Sentinel and the Orchestrator ingest seam** — NOT provisioned by this
  chart. The interim peer authenticator is `ORCH_INGEST_HMAC_SECRET` (Fork B). Sentinel's
  own mTLS (F-034) is itself unshipped and speculative; there is no reference
  implementation to mirror. `contracts/openapi.yaml`'s "HONESTY BOUNDARIES" rule 14(a) is
  intentionally left pointing at this deferral rather than closed.
- **Public TLS / cert-manager / hardened production Ingress** — the demo uses
  `kubectl port-forward`; an operator wires their own Ingress + cert-manager at the edge
  (`ingress.enabled=false` by default).
- **HPA / autoscaling** — the `hpa.yaml` template exists (mirrors the chart's shape) but
  ships with `autoscaling.enabled=false`; KEDA-style queue-depth scaling does not apply (the
  Orchestrator has no bulk-worker/Redis-Streams queue).
- **`/livez` + `/readyz` split** — Fork G; deferred to an application-code change, not a
  deployment-task change.

## Alternatives considered

- **Build real mTLS now (cert-manager-issued certs on the ingest seam).** Rejected for this
  task: no prior ecosystem implementation to build from or review against, no dependent
  task ready to consume it yet, and doing so under an unattended, single-PR run without a
  dedicated security review cycle is exactly the kind of scope-widening-under-ambiguity
  this run is instructed to avoid. Left as a named, explicit deferral instead.
- **Wire an External Secrets Operator / Vault sidecar now.** Rejected for the same reason:
  Sentinel itself has not shipped this, so there is no established pattern to mirror, and
  introducing one unilaterally in the Orchestrator would diverge from — not follow — the
  "F-010 establishes the deploy pattern" directive.
