"""HIPAA Security Rule module (F-029, ADR-0035).

Three deliverables, all contract-free (no contracts/ change):
  1. HIPAA control map — src/compliance/frameworks/hipaa.yaml, loaded by the
     existing F-011 engine (mapping/gap_analysis/pack) via the CLI path.
  2. PHI patterns — a CURATED, BUILT-IN regex set (phi_patterns.py) reusing
     F-028's ReDoS-safe engine (data_protection.custom_pii.engine), distinct
     from F-028's per-tenant DB patterns.
  3. BAA-ready evidence summary — baa_export.py renders the HIPAA gap report +
     audit-control (hash-chain) attestation + PHI-safeguard statement into a
     Business-Associate-Agreement-oriented document.

Exposed via the sentinel-hipaa operator CLI (phi-scan, baa-summary).
"""
