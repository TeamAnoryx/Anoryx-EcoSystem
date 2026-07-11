# Multi-region deployment (F-022, ADR-0028)

Deploy Anoryx Sentinel across regions as **one active + N passive** clusters, with
data-residency labeling, geo-routing hooks, and cross-region replication of the two
globally-uniform stores (the policy store and the append-only audit log).

This is an **additive overlay** on the single-cluster chart (ADR-0027). It is fully
gated behind `region.enabled` (default **false**): with the flag off the chart is
byte-identical to the single-cluster deploy — read [DEPLOY-K8s.md](DEPLOY-K8s.md)
first, get one cluster working, then layer this on.

> Honest scope. This ships the **deployment substrate** for multi-region, not an
> automated active-active data plane. One region writes; passive regions are
> read-only replicas that you **promote by runbook** on failover. Automated
> multi-writer, an automatic promotion controller, a provisioned global load
> balancer, and app-tier residency *enforcement* are named deferrals (ADR-0028
> "Honest deferrals"). What is here is correct and honest; what is not here is not
> half-built.

---

## 1. Architecture

```
                 ┌─────────────── Global LB / GeoDNS (operator-owned) ───────────────┐
   users ───────▶│  route to nearest healthy region · health-checked failover→active │
                 └───────────────┬───────────────────────────────┬───────────────────┘
                                 ▼                                 ▼
                    ┌──────────────────────┐          ┌──────────────────────┐
                    │  ACTIVE  us-east-1    │          │  PASSIVE  eu-west-1   │
                    │  role=active          │          │  role=passive         │
                    │  writes: policy+audit │──logical──▶  read-only replica    │
                    │  PUBLICATION          │  replication  SUBSCRIPTION         │
                    └──────────────────────┘          └──────────────────────┘
```

- **Active region** — the sole writer for `policies`, `policy_versions`, and the
  append-only `events_audit_log`. Publishes them via Postgres **logical**
  replication.
- **Passive region(s)** — subscribe to the active region's publication and stand by
  for promotion. **Do NOT serve governed traffic on a passive region** — passive
  write-exclusion is not enforced by this chart (audit H1, §8); serving there forks
  the audit chain and halts replication. Keep the passive geo-routing weight at 0
  until you promote (§6).
- **Data residency** — each region carries `topology.kubernetes.io/region`,
  `anoryx.io/region-role`, and `anoryx.io/data-residency` pod labels plus
  `SENTINEL_REGION` / `SENTINEL_REGION_ROLE` / `SENTINEL_DATA_RESIDENCY` env.
  Because replication is **logical and table-scoped**, only the two global stores
  cross regions — nothing residency-bound is copied.

---

## 2. Prerequisites

- One working single-cluster install per region (DEPLOY-K8s.md), one cluster per
  region.
- Postgres reachable **between** regions for replication (a private link / peered
  VPC / VPN). The chart does **not** open this path for you.
- On the **active** region's Postgres: `wal_level = logical` (server config; a
  managed provider exposes this as a parameter — e.g. RDS `rds.logical_replication=1`).
- Each replicated table has a primary key / `REPLICA IDENTITY` — `policies`,
  `policy_versions`, and `events_audit_log` all do.

---

## 3. Deploy the active region

```sh
helm install sentinel-us deploy/helm/sentinel \
  -f deploy/helm/sentinel/values.yaml \
  -f deploy/helm/sentinel/values.region-active.example.yaml
```

The active overlay sets `region.role=active`, `residency=us`, and
`region.replication.enabled=true` (publication of the three global tables). Edit
`name` / `residency` / `geoRouting.annotations` for your environment.

## 4. Deploy a passive region

```sh
helm install sentinel-eu deploy/helm/sentinel \
  -f deploy/helm/sentinel/values.yaml \
  -f deploy/helm/sentinel/values.region-passive.example.yaml
```

Set `region.replication.activePrimaryConninfo` to the **active** region's primary
(host/port/db/user/sslmode) **without the password** — the password is injected at
apply time (§5), never committed. Use **`sslmode=verify-full`** with a pinned CA
(`sslrootcert=`) on that conninfo: the cross-region link carries signed policies and
the tamper-evident audit log, so a weaker mode (`require` encrypts but does not
verify the server cert) leaves it open to an on-path MITM that could tamper the
replicated stream.

---

## 5. Wire cross-region replication

The chart **renders** the SQL into a ConfigMap (`<release>-sentinel-region-replication`)
and, by default, does **not** apply it — cross-region networking and credentials are
yours to own. Two ways to apply it:

### 5a. Manual apply (recommended for managed databases)

**Active region** — create the publication once:

```sh
kubectl get configmap sentinel-us-sentinel-region-replication \
  -o jsonpath='{.data.publication\.sql}' | psql "$ACTIVE_ADMIN_DSN"
```

**Passive region** — create the subscription once, substituting the replication
password from your secret store (never commit it):

```sh
kubectl get configmap sentinel-eu-sentinel-region-replication \
  -o jsonpath='{.data.subscription\.sql}' \
  | sed "s|\${REPLICATION_PASSWORD}|$REPLICATION_PASSWORD|" \
  | psql "$PASSIVE_ADMIN_DSN"
```

> **Credential hygiene.** `CREATE SUBSCRIPTION` persists the connection string
> (including the substituted password) in the passive DB's `pg_subscription`
> catalog in plaintext, and it can surface in server logs. Before applying, set the
> passive Postgres to a quiet logging posture for the bootstrap window
> (`log_statement=none`, restrict `log_min_error_statement`), and **rotate the
> replication password after bootstrap**. Prefer a `.pgpass`/passfile conninfo
> option where your Postgres version supports it so the secret is not inlined.

### 5b. Opt-in bootstrap Job (bundled-store demo)

Set `region.replication.bootstrapJob.enabled=true`. A Job applies the rendered SQL
against the in-cluster bundled Postgres. On a passive region it reads
`REPLICATION_PASSWORD` from the app `envSecret` (add that key first). Managed
databases should prefer 5a — `CREATE SUBSCRIPTION` needs elevated privileges.

### 5c. NetworkPolicy — allow the replication egress

The restrictive default NetworkPolicy does **not** open cross-region Postgres
egress (that would loosen the single-region default). On the passive region, allow
exactly the active region's DB CIDR via `networkPolicy.extraEgress`:

```yaml
networkPolicy:
  extraEgress:
    - to: [{ ipBlock: { cidr: 203.0.113.0/24 } }]   # active region DB
      ports: [{ port: 5432, protocol: TCP }]
```

### 5d. Verify replication

```sh
# Active: publication exists and lists the three tables.
psql "$ACTIVE_ADMIN_DSN" -c "\dRp+ sentinel_global"

# Passive: subscription is streaming (srsubstate = 'r' = ready).
psql "$PASSIVE_ADMIN_DSN" -c "SELECT subname, subenabled FROM pg_subscription;"
psql "$PASSIVE_ADMIN_DSN" -c \
  "SELECT srrelid::regclass, srsubstate FROM pg_subscription_rel;"

# End-to-end: a policy written on active appears on passive after replication lag.
```

Replication is **eventually consistent**: a policy or audit row written on the
active region becomes visible on a passive region after logical-replication lag. A
passive region enforces the **last-replicated** policy set — audit-ready evidence of
what each region knew and when, not a claim of zero-lag global consistency.

---

## 6. Failover: promote a passive region

Promotion is **runbook-driven** (there is no auto-promotion controller — a named
deferral). When the active region is lost:

1. **Confirm the active region is truly down** (avoid split-brain — two writers on
   an append-only hash chain is exactly what the active/passive posture forbids).
2. **Drain the old publisher** if it is reachable: disable its writers
   (`kubectl scale deploy/... --replicas=0`) so no new rows land after cutover.
3. **Promote the chosen passive region's database** — detach it from replication so
   it becomes a standalone primary:
   ```sh
   psql "$PROMOTE_DSN" -c "ALTER SUBSCRIPTION sentinel_global_sub DISABLE;"
   psql "$PROMOTE_DSN" -c "ALTER SUBSCRIPTION sentinel_global_sub SET (slot_name = NONE);"
   psql "$PROMOTE_DSN" -c "DROP SUBSCRIPTION sentinel_global_sub;"
   ```
4. **Re-label the region active** — `helm upgrade` it with `region.role=active` (and
   `replication.enabled` as appropriate to re-publish to remaining passives).
5. **Repoint geo-routing** — raise this region's `anoryx.io/geo-weight` (or the
   equivalent in your global LB) so users route here.
6. **Rebuild replication** to the remaining/returning regions (§5) once the topology
   is stable.

> Step 3's `DROP SUBSCRIPTION` removes a *replication link*, not tenant data. The
> audit chain and policy rows are retained; the region simply stops receiving new
> ones from the (now-dead) old primary.

---

## 7. Geo-routing

The chart surfaces `region.geoRouting.annotations` onto the gateway Service (and
Ingress when enabled) so you can wire a global load balancer / GeoDNS (e.g.
`external-dns`, a cloud global LB, or a GSLB). The chart does **not** provision the
global LB — it is edge/account-owned. Health-check each region's `/readyz` and set
failover to the active region.

---

## 8. What this does and does not claim

**Does:** region identity + residency labeling; an integrity-preserving replication
design for exactly the three global stores (row-faithful → the audit hash chain and
policy signatures survive replication); **render-enforced residency scope** (the
`tables` allowlist fails the render if anything but the global stores is listed);
zero change to the single-region default (byte-identical when off, gated at the call
site); no `src/` change.

**Does not (and you must account for):** automatic active-active multi-writer;
automatic failover; a provisioned global load balancer; and app-tier residency
enforcement.

**Passive-region write-exclusion IS now enforced (audit finding H1 — resolved).**
The application refuses governed traffic on a passive region fail-closed: set
`SENTINEL_REGION_ROLE=passive` and the outermost `PassiveRegionGuardMiddleware`
returns `503` for every governed / audit-generating request **before** the
terminal audit writes anything — so a passive region cannot append to its local
`events_audit_log`, cannot fork the hash chain, and cannot collide on the
replicated `sequence_number`. Only k8s liveness/readiness probes are served on
passive (so the pod stays promotable); promotion is a config change to
`SENTINEL_REGION_ROLE=active` + restart. You should still keep the passive
`geoRouting` weight at 0 (governed requests routed there will simply 503).
**Deliberate tradeoff:** a passive region serves **no residency-local reads**
either — safely serving passive reads needs a cross-region global audit sequencer
(still deferred; see `docs/followups/f-022-passive-readonly-enforcement.md`).
Automatic failover and active-active remain deferred by name in ADR-0028, not partially
built.
