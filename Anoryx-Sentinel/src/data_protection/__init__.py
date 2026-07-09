"""Data-protection pillar (F-005 built-in PII + F-028 custom client-defined PII).

F-005's built-in Presidio detector lives in src/orchestration/detectors/
pii_detector.py. F-028's per-tenant client-defined custom PII engine lives in
src/data_protection/custom_pii/ — a standalone regex engine (no Presidio/spacy
dependency) with per-tenant patterns, versioning, hot-reload, and a ReDoS-safe
matcher. See docs/adr/0034.
"""
