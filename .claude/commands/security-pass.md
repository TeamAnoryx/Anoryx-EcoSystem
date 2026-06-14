---
name: security-pass
description: Run security-auditor over a file or diff. Returns structured JSON findings.
---
Invoke security-auditor on: $ARGUMENTS
(Pass "diff" to use git diff main...HEAD)

If verdict BLOCK: print every finding with severity, file, line, issue, fix.
If any Critical: print ⛔ CRITICAL — HUMAN REVIEW REQUIRED. Do NOT auto-fix.
