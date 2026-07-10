"""Production due-diligence gate (F-031, ADR-0037).

A pre-launch checklist that verifies a Sentinel deployment is production-ready:
  - secrets are vaulted (not raw env), reusing F-027 KeyVaultSettings;
  - the append-only audit hash-chain verifies intact, reusing F-003's
    AuditLogRepository.validate_chain();
  - Alembic migrations are applied to head (DB revision == script head);
  - no OPEN CRITICAL/HIGH security findings in the findings ledger;
  - core runtime config loads and passes SLO/sanity bounds.

Each check returns a CheckResult (pass/warn/fail + remediation). The
sentinel-preflight CLI runs them all and exits non-zero if ANY hard-fails —
a launch gate. Contract-free / CLI-only (see docs/adr/0037).
"""
