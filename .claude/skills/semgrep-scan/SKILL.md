Semgrep procedures for Anoryx Sentinel:
- Command: semgrep scan --config=p/python --config=p/security-audit --config=p/secrets
  --severity=ERROR --json --no-git-ignore <path>
- Parse: results[].check_id, results[].path, results[].start.line,
  results[].extra.message, results[].extra.severity
- Triage before calling High/Critical: confirm exploitability — not all findings are real
- Suppression: # nosemgrep: <rule-id> only with a comment explaining why it's a FP
- Any p/secrets hit is minimum High severity
- Run against Anoryx-Sentinel/src/ in CI via .github/workflows/sentinel-ci.yml
