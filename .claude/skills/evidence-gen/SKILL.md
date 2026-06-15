Compliance evidence pack for Anoryx-Sentinel/src/compliance/:
- Artifact structure: { control_id, framework, framework_version, check_fn_name,
  result: pass|fail|not_checked, evidence_data: {...}, checked_at: ISO ts,
  sentinel_version: str, disclaimer: "Automated evidence for audit preparation.
  Certification requires an accredited auditor." }
- Automated checks: encryption_at_rest (verify KMS config + roundtrip),
  audit_logging (query audit_log for rows in last 24h), rbac_enforced
  (all API calls had valid virtual key), pii_masking_active (active policy has rules)
- Export: ZIP of JSON evidence files signed with RSA private key from Vault;
  public key bundled in the ZIP for auditor verification
- The disclaimer above is NOT optional — it appears in every artifact and in the UI
