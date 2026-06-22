"""Anoryx Sentinel — Code Output Scanning package (F-016, ADR-0019).

Provides a post-response hook (``CodeScanDetector``) that extracts fenced
code blocks from LLM responses, scans them with Semgrep and Bandit, and
aggregates findings into a per-tenant verdict (PASS | WARN | BLOCK).

Honest framing (per CLAUDE.md / ADR-0019):
  "high-coverage detection" of known patterns — not "100% detection."
  "risk reduction" — not "blocks all vulnerabilities."
  "likely defect" — not "bug-free."

Public API::

    from code_scan.detector import CodeScanDetector
    from code_scan.extractor import extract_code_blocks, MAX_BLOCKS
    from code_scan.scanners import scan_block, ScannerError
    from code_scan.verdict import aggregate_verdict, Verdict
    from code_scan.config import load_code_scan_config, CodeScanConfig
"""
