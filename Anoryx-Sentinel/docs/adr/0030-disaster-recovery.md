# ADR-0030 — Disaster Recovery (F-024)

- Status: Accepted (implemented)
- Date: 2026-07-07
- Builds on: ADR-0004 (persistence — the append-only, hash-chained
  `events_audit_log`, and `AuditLogRepository.validate_chain()` which this ADR
  reuses unchanged), ADR-0005 (tenant isolation — RLS / `sentinel_app` /
  privileged-role split, whose privileged connection backup uses), ADR-0028
  (multi-region deployment — the cross-region replication + manual-promotion
  failover this ADR's "cross-region drill" section builds on), ADR-0018 (F-015
  bulk pipeline — the S3/MinIO client + lazy-import-behind-an-extra discipline
  this ADR's S3 sink mirrors exactly).
- Scope: backup/restore tooling (`src/dr/`), a scheduled-backup Helm CronJob
  (gated off by default), and an operator runbook (`deploy/DISASTER-RECOVERY.md`).
  No `contracts/` change — internal operational tooling, no API/event/policy
  schema surface.

## Context

Roadmap F-024: "Backup/restore, failover runbook, RPO/RTO validated,
cross-region drill." ADR-0028 (F-022) already ships a **failover** runbook
(`deploy/MULTI-REGION.md` §6 — manual, operator-in-the-loop promotion of a
passive region) and cross-region **replication** of the two globally-uniform
stores (`policies`, `policy_versions`, `events_audit_log`). What was missing,
confirmed by a repo-wide search before starting this work: **there was no
backup/restore tooling anywhere in the repository** — no `pg_dump`/`pg_restore`
script, no CronJob, no runbook. Multi-region replication protects against a
single-region outage; it does **not** protect against logical corruption, an
operator error, or a bad migration replicated to every region before anyone
notices — which is what backup/restore is for.

Postgres is Sentinel's only stateful store (`src/persistence/models/`:
tenants, policies + policy_versions, the hash-chained `events_audit_log`,
virtual API keys, model inventory, SSO identities, tenant routing policy,
webhook config/delivery — 32 Alembic migrations' worth of schema). A backup is
therefore a single `pg_dump` of one database; a restore is a single
`pg_restore` plus one integrity check specific to Sentinel: the audit log's
hash chain must still verify after restore, or the restored database's audit
trail cannot be trusted (CLAUDE.md #5 — fail-safe, never silently proceed on
an integrity error).

## Decision

### 1. Backup (`src/dr/backup.py`, `src/dr/cli.py sentinel-dr backup`)

`pg_dump -Fc` (custom format — supports selective/parallel restore, unlike
plain SQL) against **`DATABASE_URL`, the privileged connection** — never the
`sentinel_app` (RLS-scoped) role, which would silently omit whatever tenant
rows the connecting session's RLS context happened to exclude. This mirrors
how Alembic migrations and hash-chain ops already run privileged
(`persistence/database.py`'s documented two-engine split).

The connection string is **never passed as a subprocess argv argument**
(`src/dr/pg_url.py`) — a password embedded in argv is visible to any other
process on the host via `ps`/`/proc`. It is split into `-h/-p/-U/-d` plus a
`PGPASSWORD` env var passed only to the child process's environment
(CLAUDE.md #4 — never logged, never in argv).

### 2. Storage sinks (`src/dr/backends/`)

Two interchangeable sinks behind one `BackupSink` interface:

- **`local`** (default) — a directory, meant for a PVC mount in-cluster. Zero
  extra dependencies, always available, always testable in CI (no external
  service). **Honest limitation, stated in both `values.yaml` and the
  runbook**: does NOT survive loss of the volume/cluster it lives on — it
  protects against logical corruption / accidental deletion / a bad
  migration, not a full cluster/PV loss.
- **`s3`** — S3/MinIO-compatible object storage, for genuine off-cluster
  durability. Same lib family as F-015 bulk / F-006 bedrock (boto3);
  lazy-imported behind the new `[dr-s3]` extra so a slim deploy that never
  enables S3-backed backup does not need boto3 installed — this is the exact
  same discipline as `src/bulk/storage/minio_backend.py` (ADR-0018 §6),
  reused deliberately rather than reinvented.

Backup keys embed a UTC timestamp (`src/dr/key_format.py`,
`sentinel-backup-{YYYYMMDDTHHMMSSZ}.dump`) — the sole source of truth for a
backup's `created_at` and for retention ordering, not filesystem/object-store
mtime (which a sink's storage layer may not preserve faithfully across a
copy/upload).

### 3. Restore (`src/dr/restore.py`, `sentinel-dr restore`) — fail-safe, never automated

`--target-database-url` is **always an explicit, required CLI argument** —
never defaulted to the running deployment's own `DATABASE_URL`. A restore is
destructive to whatever it targets; there is no automated or scheduled
restore path anywhere in this ADR (only backup is CronJob-driven). This
mirrors ADR-0028's "operator-in-the-loop" posture for failover — recovery
actions with a wide blast radius stay human-triggered.

After `pg_restore --clean --if-exists --no-owner`, `run_restore()` opens a
**second, independent connection** to the target database (not the source)
and calls the **existing, unmodified** `AuditLogRepository.validate_chain()`
(ADR-0004) — the same walk-and-recompute-every-`row_hash` check the audit
subsystem already uses, reused rather than reimplemented. **If the chain does
not verify, `run_restore()` raises `ChainValidationFailed` — it does not
return a "partially OK" result.** A restored database whose audit trail
cannot be verified must never be silently treated as usable (CLAUDE.md #5).

### 4. Scheduled backup CronJob (`deploy/helm/sentinel/templates/backup-cronjob.yaml`)

Gated by `backup.enabled` (default **false** — byte-identical render to the
chart before this ADR when off, same discipline as ADR-0028's `region.enabled`
gate). Runs `sentinel-dr backup` through the **same entrypoint shim**
(`docker-entrypoint.sh`) the migration Job already uses, so `DATABASE_URL` is
assembled from the password `secretKeyRef` exactly the same way — never lands
in the pod spec. No new container image: the gateway/worker image now also
carries `postgresql-client-16` (see §5), so the backup CronJob and an
operator's `sentinel-dr restore` both run from the one image already built and
signed for this deploy, rather than maintaining a second backup-specific image.

### 5. `pg_dump`/`pg_restore` binary — exact version match, not "close enough"

The runtime image (`Dockerfile`) now installs **`postgresql-client-16`** via
the official PGDG apt repository, pinned to major version 16 to exactly match
`postgres:16-alpine` (the server this chart deploys — `docker-compose.yml`,
`values.yaml`). This is a deliberate choice over the simpler `apt-get install
postgresql-client`, which on the `python:3.12-slim-bookworm` base resolves to
Debian's own **v15** client package: `pg_dump` dumping FROM a server **newer**
than its own major version is not a documented-supported direction (only the
reverse — an older server, newer client — is), so a same-major client is
required here, not merely close. `curl`/`gnupg` (needed only to add the PGDG
key) are purged again after install — build-only tools, never in the runtime
layer, mirroring the builder stage's own toolchain discipline.

### 6. RPO/RTO — measured, not asserted

Neither the roadmap line nor any prior ADR states a numeric RPO/RTO target
(confirmed by search — ADR-0028 §"Passive promotion is manual" only describes
an "operator-in-the-loop RTO" with no number). Rather than assert an
aspirational SLA, `tests/dr/test_backup_restore_drill.py` runs the REAL
backup → restore → chain-validate cycle against a live Postgres (no mocks on
the DB path) and reports actual measured timings. **Honest framing (see
"Honest limitations" below): these are drill measurements on a small
synthetic dataset in CI, not a production capacity-planned SLA** — pg_dump/
pg_restore duration scales with data volume, so a real RPO/RTO estimate for a
specific deployment must be extrapolated from that deployment's own data size,
not taken verbatim from this drill.

### 7. Cross-region drill

`deploy/DISASTER-RECOVERY.md` §"Cross-region drill" extends ADR-0028's
existing manual failover runbook (`deploy/MULTI-REGION.md` §6) with the
backup/restore mechanism as an **additional** recovery path alongside
logical-replication promotion: restore the latest backup into a fresh passive
region as a validated alternative to (or backstop for) promoting a
replication-lagging or corrupted passive replica. This is a documentation/
procedure addition — it does not change ADR-0028's replication mechanism.

## Honest limitations

- The `local` sink is the default and does not, by itself, satisfy "disaster
  recovery" against a full cluster/PV loss — only against logical corruption.
  Genuine DR posture requires `backup.sink: s3` with off-cluster credentials,
  which is opt-in, not default (a default-on external-storage requirement
  would break a zero-config bundled install).
- RPO is bounded by `backup.schedule` (default daily) **plus** backup
  duration — this is a scheduled-snapshot RPO, not continuous/point-in-time
  recovery (no WAL archiving/PITR in this ADR's scope).
- RTO in `deploy/DISASTER-RECOVERY.md` is a drill-measured figure on a small
  CI dataset, explicitly labeled as such — not a capacity-planned production
  SLA.
- A `pg_restore --clean --if-exists` exit code of non-zero is treated as a
  hard failure by `run_restore()` even though some non-zero exits reflect
  only non-critical warnings (e.g. ordering of drop statements on a
  non-empty target) — the conservative, fail-safe choice for a DR tool: an
  operator investigates rather than the tool guessing severity.
- CI does not build/run the `Dockerfile` (only `sentinel-release.yml`, on a
  version tag, does) — the PGDG `postgresql-client-16` install in §5 is
  therefore not exercised by this PR's own CI gate; it follows the standard,
  widely-documented PGDG recipe but should be validated on the next tagged
  release build.
