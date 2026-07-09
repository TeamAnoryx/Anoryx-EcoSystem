"""EU AI Act module (F-030, ADR-0036).

Three deliverables, all contract-free (no contracts/ change):
  1. EU AI Act control map — src/compliance/frameworks/eu_ai_act.yaml, loaded by
     the existing F-011 engine via the CLI path.
  2. High-risk classification helper — classification.py: Annex III high-risk
     screening + Article 5 prohibited-practice screening. Decision-SUPPORT, not
     legal advice.
  3. Article 13 transparency disclosure template — disclosure.py: generates an
     instructions-for-use / transparency-information document.

Exposed via the sentinel-euaiact operator CLI (classify, disclosure).
"""
