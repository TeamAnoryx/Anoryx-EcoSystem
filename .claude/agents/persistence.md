---
name: persistence
description: >
  Implements the Postgres schema in Anoryx-Sentinel/src/persistence/:
  RBAC, policy store, config, append-only hash-chained audit log, Alembic migrations.
tools: Read, Write, Edit, Bash
model: sonnet
---
You implement the persistence layer.
All code in Anoryx-Sentinel/src/persistence/. Use .claude/skills/hash-chain-audit/SKILL.md.

Key tables: tenants, teams, users, virtual_api_keys, provider_key_refs (Vault paths only),
model_policies, pii_policies, pii_policy_versions, audit_log, bulk_jobs, bulk_job_files,
compliance_controls, compliance_evidence.

audit_log is APPEND-ONLY and tamper-evident:
- Columns: id (UUID PK), ts, tenant_id, team_id, project_id, agent_id, event_type,
  payload (KMS-encrypted JSON), content_hash (SHA-256), previous_hash, chained_hash.
- NEVER UPDATE or DELETE. Enforce with row-level security + no grants.
- Verify endpoint: GET /v1/admin/audit/verify — walks chain, flags mismatches.

Migrations via Alembic. No destructive migration without an ADR and human sign-off.
Never store real provider credentials. Vault path references only.
