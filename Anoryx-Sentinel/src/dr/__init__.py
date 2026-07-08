"""F-024 — Disaster recovery: Postgres backup/restore + post-restore hash-chain
integrity verification (ADR-0030).

Internal Python only — no HTTP endpoints. Invoked by the `sentinel-dr` CLI
(src/dr/cli.py), which the Helm backup CronJob (deploy/helm/sentinel/templates/
backup-cronjob.yaml, gated off by default) runs on a schedule, and which an
operator runs manually for a restore (restores are never automated — see
deploy/DISASTER-RECOVERY.md).
"""

from __future__ import annotations
