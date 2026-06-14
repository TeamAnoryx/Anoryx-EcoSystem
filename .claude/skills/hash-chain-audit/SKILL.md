Tamper-evident audit log for Anoryx-Sentinel/src/persistence/:
- Schema: id (UUID PK), ts, tenant_id, team_id, project_id, agent_id, event_type,
  payload (KMS-encrypted JSON), content_hash (SHA-256 of plaintext payload),
  previous_hash (chained_hash of previous row), chained_hash (SHA-256 of content_hash + "|" + previous_hash)
- GENESIS row: previous_hash = SHA-256("SENTINEL_GENESIS")
- Insert: SELECT FOR UPDATE previous row → compute hashes → insert atomically
- NEVER UPDATE or DELETE: row-level security + no UPDATE/DELETE grants for app role
- Verify endpoint: walk rows ordered by id, recompute each chained_hash, flag first mismatch
- Envelope encryption: payload column uses KMS-wrapped data key
