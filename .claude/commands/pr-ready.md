---
name: pr-ready
description: Run the full oversight pipeline on the current diff. Returns PR-gate verdict.
---
Run full oversight on git diff main...HEAD:
1. code-reviewer → verdict
2. security-auditor → verdict (Critical → ⛔ HUMAN ESCALATION, stop)
3. test-engineer → verify Anoryx-Sentinel/tests/ pass
4. perf-load-engineer → only if diff touches src/gateway/ or src/bulk/
5. pr-gate → aggregate → output JSON verdict

Print pr-gate JSON. If READY: PR is labeled for human review.
Do NOT open a PR or push branches yourself. That is the human's action.
