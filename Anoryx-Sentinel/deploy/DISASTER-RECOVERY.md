# Disaster recovery (F-024, ADR-0030)

Postgres backup/restore, an operator restore runbook, RPO/RTO drill
measurements, and a cross-region drill that builds on
[MULTI-REGION.md](MULTI-REGION.md)'s existing failover procedure.

> Honest scope. This ships a scheduled `pg_dump` backup + an operator-run
> restore CLI (`sentinel-dr`), gated off by default. There is **no automated
> failover or auto-promotion** here (that stays runbook-driven per ADR-0028) —
> a restore is always operator-triggered, always targets an explicit database,
> and is always followed by a hash-chain integrity check that must pass before
> the restored database is considered usable. The default backup sink (a
> local PVC) does **not** survive loss of the cluster/volume it lives on — see
> §1 and §5 before relying on this for real disaster recovery.

---

## 1. Architecture

```
                    ┌─────────────────────────┐
   CronJob (daily)  │  sentinel-dr backup      │──pg_dump─┐
   backup.enabled   │  (docker-entrypoint.sh   │          │
                     │   → sentinel-dr backup) │          ▼
                    └─────────────────────────┘   ┌───────────────┐
                                                    │  BackupSink   │
                                                    │  local | s3   │
                                                    └───────────────┘
                                                            │
   operator, manual   ┌─────────────────────────┐          │
   sentinel-dr restore│  1. fetch dump          │◄─────────┘
   --target-database- │  2. pg_restore --clean  │
   url ...            │  3. validate_chain()    │──raises ChainValidationFailed
                       │     (existing ADR-0004  │   if the audit trail cannot
                       │      hash-chain walk)   │   be trusted — never silently
                       └─────────────────────────┘   "partially OK"
```

Two sinks (`backup.sink` in `values.yaml`, `src/dr/backends/`):

| Sink    | Durability                                      | Extra deps      | Default |
|---------|--------------------------------------------------|------------------|---------|
| `local` | Same cluster/failure-domain as the DB — protects against logical corruption, NOT cluster/PV loss | none | ✅ |
| `s3`    | Off-cluster (S3/MinIO) — genuine DR posture       | `[dr-s3]` extra (boto3), `DR_S3_ACCESS_KEY`/`DR_S3_SECRET_KEY` in the app secret | opt-in |

**If you need real disaster-recovery posture (survive losing the whole
cluster), set `backup.sink: s3` and point it at storage outside this
cluster's own failure domain.** The `local` default exists so a zero-config
bundled install still gets *something* (protection against a bad migration,
an accidental `DELETE`, a corrupted table) — it is not, by itself, "disaster
recovery" in the full sense of the term.

---

## 2. Enable scheduled backups

```yaml
# values.yaml (or -f overrides.yaml)
backup:
  enabled: true
  schedule: "0 3 * * *"     # daily 03:00 UTC — tune to your RPO target (§4)
  sink: local                # or "s3" — see §1
  retentionDays: 14
```

```sh
helm upgrade sentinel deploy/helm/sentinel -f overrides.yaml
kubectl get cronjob sentinel-backup
```

For `sink: s3`, also set `backup.s3.endpoint` / `backup.s3.bucket` /
`backup.s3.region` and put `DR_S3_ACCESS_KEY` / `DR_S3_SECRET_KEY` into the
app `envSecret` (`secretData` if using `createEnvSecret: true`, or your own
pre-created Secret). The image must include the `[dr-s3]` extra
(`INSTALL_EXTRAS=all` or `dr-s3` at build time) — the `slim` variant does not
carry boto3 and `sentinel-dr backup` will fail loud with an actionable
`pip install anoryx-sentinel[dr-s3]` message if S3 is selected without it.

List what's been backed up:

```sh
kubectl exec -it deploy/sentinel -- sentinel-dr list
```

---

## 3. Restore

**Always restore into a database OTHER than your live one first, verify it,
then cut over** — never restore in place onto a database still serving
traffic.

```sh
# 1. Create (or point at) the target database.
kubectl exec -it deploy/sentinel-postgres -- psql -U sentinel -c \
  "CREATE DATABASE sentinel_restore_check;"

# 2. Restore the chosen backup into it (never defaults — target is required).
kubectl exec -it deploy/sentinel -- sentinel-dr restore \
  --key sentinel-backup-20260707T030000Z.dump \
  --target-database-url "postgresql://sentinel:<password>@sentinel-postgres:5432/sentinel_restore_check"

# 3. sentinel-dr restore already ran the hash-chain check internally and
#    printed `chain_rows_checked=N` on success, or exited non-zero with
#    "restore failed: restored hash chain failed validation at sequence=...".
#    A non-zero exit means STOP — do not promote this restore.

# 4. Once verified: point APP_DATABASE_URL / DATABASE_URL at the restored
#    database (or rename it into place), then `helm upgrade` / restart pods.
```

`sentinel-dr restore` never touches an implicit/default database — you must
always pass `--target-database-url` explicitly. This is deliberate: a restore
is destructive to whatever it targets, so there is no path where a
misconfigured environment variable accidentally restores over production.

---

## 4. RPO/RTO — drill-measured, not an asserted SLA

`tests/dr/test_backup_restore_drill.py` runs the REAL backup → restore →
chain-validate cycle against a live Postgres in CI (no mocks on the DB path)
and asserts the chain verifies. Run it yourself and read the timings it
prints:

```sh
pytest -q tests/dr/test_backup_restore_drill.py -s
```

**Honest framing:** this drill uses a small synthetic dataset (a handful of
policy + audit rows) — `pg_dump`/`pg_restore` duration scales with actual
data volume, so:

- **RPO** = your configured `backup.schedule` interval **+** backup duration
  at your actual data size. This is scheduled-snapshot RPO, not
  continuous/point-in-time recovery — there is no WAL archiving in this ADR's
  scope. Tighten `schedule` if your RPO tolerance is smaller than daily.
- **RTO** = restore duration **+** hash-chain validation time, both scaling
  with your actual audit-log row count, **plus** the manual steps in §3
  (creating the target DB, verifying, cutting over) — this runbook does not
  measure or bound the human-driven portion.

Do not extrapolate the CI drill's numbers directly to a production capacity
estimate — re-run the drill against a copy of your real data size to get a
number that means something for your deployment.

---

## 5. Cross-region drill

Builds on [MULTI-REGION.md §6](MULTI-REGION.md) (promote-a-passive-region
failover). Backup/restore is an **additional**, independent recovery path —
useful when the passive region's replica is itself lagging, corrupted, or
unavailable, not only as a backstop for a total regional loss:

1. **Baseline**: confirm the active region's `sentinel-dr list` shows a
   recent backup (§2) — either sink works here since this drill validates the
   restore mechanism itself, not cross-region network durability.
2. **Simulate loss**: as in MULTI-REGION.md §6 step 1, treat the active
   region as unreachable.
3. **Restore into the target region** instead of (or in addition to)
   promoting the passive replica:
   ```sh
   sentinel-dr restore --key <latest> \
     --target-database-url "postgresql://sentinel:<password>@<target-region-postgres>:5432/sentinel_dr_recovery"
   ```
4. **Validate**: the CLI's own chain check (§3 step 3) is your go/no-go gate.
   Additionally cross-check the restored `policies`/`policy_versions` row
   counts against the active region's last known state if you have
   observability access to both.
5. **Cut over**: same as MULTI-REGION.md §6 steps 4-6 (re-label region role,
   repoint geo-routing, rebuild replication once stable) — the restored
   database now plays the role a promoted passive would have.

This does not change ADR-0028's replication mechanism or its honest
limitations (passive read-only is not chart-enforced — see
`docs/followups/f-022-passive-readonly-enforcement.md`); it adds backup/
restore as a second, independent path to recovery alongside replica
promotion.

---

## 6. What this does and does not claim

**Does:** a working `pg_dump`/`pg_restore` cycle with a post-restore
hash-chain integrity gate (fail-safe — a restore that cannot be verified is
never silently treated as usable); a scheduled backup CronJob gated off by
default (byte-identical render when off); a pluggable local-or-S3 sink;
drill-measured (not asserted) RPO/RTO framing; a documented cross-region
recovery path alongside ADR-0028's replica-promotion failover.

**Does not (and you must account for):** point-in-time recovery (no WAL
archiving); automated failover or restore (both are always operator-run);
off-cluster durability by default (the `local` sink is same-cluster — set
`sink: s3` for real DR posture); a capacity-planned production RTO/RPO number
(§4's drill is a small-dataset CI measurement, not your deployment's SLA);
`Dockerfile` changes (the `postgresql-client-16` install, §1) are not
exercised by the PR-blocking CI gate (`sentinel-ci.yml` does not build the
image — only `sentinel-release.yml`, on a version tag, does), so validate it
on the next tagged release build.
