# ADR-0028 — Multi-Region Deployment (F-022)

- Status: Proposed
- Date: 2026-07-07
- Builds on: ADR-0027 (Helm single-cluster deployment — the chart this overlay
  extends), ADR-0012 (deployment & release — image variants, NetworkPolicy,
  securityContext), ADR-0004 (persistence — the append-only, hash-chained
  `events_audit_log`), and ADR-0005 (tenant isolation — RLS / `sentinel_app`).
- Supersedes: none (additive overlay on the ADR-0027 chart).
- Scope: **deployment / infrastructure layer only.** No `src/` application change.
  Every multi-region addition is gated behind `region.enabled` (default **false**),
  so with the flag off the chart renders **byte-identically** to ADR-0027 and the
  single-cluster deploy, tests, and demo bar are untouched.

## Context

ADR-0027 shipped a **single Kubernetes cluster** chart and explicitly named
multi-region as its successor (ADR-0027 "Honest deferrals": *"Multi-region /
active-active / geo-routing / cross-region replication — F-022 (the whole point of
this single-cluster prerequisite)."*). F-022 is that successor.

Multi-region for a zero-trust AI gateway is four distinct concerns, not one:

1. **Region identity** — each deployed cluster must know which region it is and
   what role it plays, for observability, routing, and residency labeling.
2. **Data residency** — a tenant's data must be able to stay in its jurisdiction;
   a region must **not** silently hold another region's residency-bound data.
3. **Geo-routing** — users are routed to the nearest healthy region, with failover
   to the active region.
4. **Cross-region replication of the two globally-uniform stores** — the **policy
   store** (a policy must be enforced identically in every region) and the
   **append-only audit log** (one tamper-evident record of record across regions).

Two properties of Sentinel's own data make (4) unusual and constrain the design:

- **`events_audit_log` is append-only and hash-chained** (ADR-0004): each row's
  `row_hash` binds `prev_hash`, so the chain is a strict linear sequence. Two
  regions cannot both extend the same chain without a global sequencer.
- **The policy store is signed + versioned** (`policies` / `policy_versions`,
  ADR-0009): policies are distributed downward and enforced; they must be uniform,
  and their signatures must survive replication byte-for-byte.

The design below is deliberately an **active/passive** posture with a
runbook-driven promotion, not an automated active-active data plane. The reasons
are in D2. This is honest about what a Helm chart can own (region-scoped
deployment substrate) versus what is edge/account-owned (a global load balancer)
or a distributed-systems problem out of a chart's scope (multi-writer conflict
resolution on an append-only chain).

## Decision

### D1 — Region identity as gated chart config (default off)

A new `region` values block: `name` (e.g. `us-east-1`), `role`
(`active` | `passive`), `residency` (a jurisdiction label, e.g. `us` / `eu`).
When `region.enabled=false` (default) **nothing** in the render changes — the
chart is byte-identical to ADR-0027. When enabled, region context surfaces two
ways, both additive:

- **Pod labels** — `topology.kubernetes.io/region`, `anoryx.io/region-role`,
  `anoryx.io/data-residency` on the gateway and worker pods (a `_helpers.tpl`
  partial). These are the k8s-native, operator-visible source of truth for
  scheduling, topology spread, and residency audits.
- **Env** — `SENTINEL_REGION`, `SENTINEL_REGION_ROLE`, `SENTINEL_DATA_RESIDENCY`
  on the gateway + worker. `GatewaySettings` uses `extra="ignore"`
  (`src/gateway/config.py`), so the app **accepts** these today without a code
  change and they are available to logging / OTel resource attributes.

**App-tier residency *enforcement* is a named deferral** (see Honest deferrals):
the deployment provides the region *context*; making the application route a
tenant's requests/data by residency is a later application feature, not this ADR.
This is stated plainly so the env is not mistaken for enforcement.

### D2 — Active / passive, not automated active-active

One region is `active` — the **sole writer** for the policy store and the audit
log. `passive` regions run **read-only** replicas of those two stores and a serve
stack that can be **promoted on failover** (runbook, D-below). Passive regions
MAY serve residency-local **reads**; **writes route to the active region.**

Automated **active-active multi-writer is explicitly NOT attempted.** Two writers
concurrently extending an append-only, hash-chained log (`events_audit_log`)
cannot both produce a valid single chain without a global sequencer — that is a
distributed-consensus problem, not a deployment one, and inventing a bespoke one
inside a Helm chart would be the opposite of the zero-trust, provable posture this
product is built on. Active/passive with an explicit, documented promotion is the
**correct and honest** posture at this stage. (Automated promotion / a failover
controller is likewise a named deferral, not a half-built one.)

### D3 — Cross-region replication via Postgres **logical** replication, scoped to the two global stores

Only three tables replicate active→passive: **`policies`**, **`policy_versions`**,
and **`events_audit_log`** (a values-driven `region.replication.tables` list
defaulting to exactly these). Rationale and safety:

- **Logical, not physical/streaming, replication.** Physical replication clones
  the *entire* cluster — every tenant, every table — which is **incompatible with
  data residency** (a region would hold another region's residency-bound rows).
  Logical replication (a `PUBLICATION` of a named table set → a `SUBSCRIPTION`)
  replicates **exactly** the two globally-uniform stores and nothing
  residency-bound.
- **Integrity survives.** Logical replication is row-faithful, so each audit
  row's `prev_hash` / `row_hash` and each policy's signature copy verbatim; the
  hash chain and signatures remain verifiable on the passive side. Because the
  passive copy is **read-only**, the chain cannot fork.
- **Delivered as rendered SQL, not auto-executed.** The chart renders a
  `region-replication` ConfigMap holding the **publication SQL** (on `active`) or
  **subscription SQL** (on `passive`), generated from values. An operator applies
  it (or opts into a bootstrap Job, `region.replication.bootstrapJob.enabled`,
  default false). It is **not** auto-run against a live database by default —
  cross-region networking, the subscription connection string, and its
  credentials are operator-owned and must not live in the chart. The generated SQL
  contains **no `DROP` / `DELETE` / `TRUNCATE`** (append-only safety, asserted by
  test).
- **RLS is orthogonal.** Logical replication operates at the table/row level via
  `REPLICA IDENTITY`; it is independent of RLS policies. Passive-side reads remain
  RLS-scoped through the same `sentinel_app` (NOBYPASSRLS) role.

### D4 — Geo-routing is edge configuration the chart *surfaces*, not owns

Global user routing (GeoDNS / a cloud global load balancer / GSLB, health-checked
with failover to `active`) lives **above** any single cluster's chart and is
account/provider-specific. The chart surfaces `region.geoRouting.annotations` onto
the gateway Service (and Ingress when enabled) so an operator wires their global
LB; the chart does **not** provision the GSLB. Named deferral.

### D5 — HA topology spread (optional, gated)

When `region.enabled` **and** `region.topologySpread.enabled`, the gateway emits
`topologySpreadConstraints` across `topology.kubernetes.io/zone` for intra-region
high availability. It is merged additively and stays off unless explicitly
enabled, so it never perturbs the default render.

### D6 — NetworkPolicy: cross-region egress via the existing escape hatch

Cross-region replication egress (Postgres `:5432` to the active region's DB
endpoint / CIDR) is **not** added to the default NetworkPolicy — doing so would
loosen the restrictive single-region default and break the
default-deny/scoped-egress test (ADR-0012 §8). Operators add exactly the
cross-region CIDR they need via the existing `networkPolicy.extraEgress` values
path (the same pattern already used for external managed Postgres/Redis and
Bedrock). The runbook documents the precise rule.

## Honest deferrals (F-022+ — named, not half-built)

- **App-tier residency enforcement** — the deployment provides region/residency
  *context* (labels + env); making the application *route* tenant data by
  residency is a later application feature.
- **Automated active-active multi-writer + conflict resolution** — active/passive
  with runbook promotion only (D2).
- **Automated failover / promotion controller** — promotion is runbook-driven
  (`deploy/MULTI-REGION.md`); no auto-promotion is shipped.
- **GSLB / GeoDNS provisioning** — edge/account-owned; the chart surfaces
  annotations only (D4).
- **Replication auto-bootstrap against live databases** — the SQL is rendered and
  applied by an operator; the bootstrap Job is opt-in and off by default (D3).

## Consequences

**Positive.** Region identity + residency labeling are first-class; the
replication design is correct and **integrity-preserving for exactly the two
global stores** (and residency-safe by construction, because it is logical and
table-scoped); the single-region default is **untouched** (byte-identical, fully
gated); there is **no `src/` change**, so the existing test suite carries no risk;
and the active/passive posture is stated honestly rather than overclaimed as
active-active.

**Negative / costs.** Passive promotion is **manual** (runbook), so failover has
an operator-in-the-loop RTO. Operators must themselves wire the GSLB, the
cross-region NetworkPolicy egress, and the replication subscription credentials.
Replication is **eventually consistent** — a policy or audit row written in the
active region is visible in a passive region only after logical-replication lag;
this is acceptable for policy distribution and audit archival and is called out in
the runbook (a passive region enforces the last-replicated policy set, which is
"audit-ready" evidence of what each region knew and when, not a claim of
zero-lag global consistency).

**Rollback.** `region.enabled=false` (the default) disables every addition; the
ADR-0027 single-cluster chart and the compose path are unaffected. No migration,
no schema change, no image change.
