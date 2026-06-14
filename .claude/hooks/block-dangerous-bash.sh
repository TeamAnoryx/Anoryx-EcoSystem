#!/usr/bin/env bash
# PreToolUse hook: blocks dangerous bash across the entire Anoryx EcoSystem.
# Exit 0 = allow.  Exit 2 = BLOCK (stderr shown to agent as reason).

set -euo pipefail
INPUT=$(cat)
CMD=$(echo "$INPUT" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('tool_input',{}).get('command',''))" \
  2>/dev/null || echo "")

if echo "$CMD" | grep -qE 'rm\s+-rf|rm\s+--recursive.*--force|find.*-delete'; then
  echo "BLOCKED: rm -rf and recursive forced deletes are not permitted." >&2; exit 2; fi

if echo "$CMD" | grep -qE 'curl[^|]*\|.*sh|wget[^|]*\|.*sh'; then
  echo "BLOCKED: curl/wget piped to a shell is not permitted." >&2; exit 2; fi

if echo "$CMD" | grep -qE 'git push.*--force|git push.*-f\b'; then
  echo "BLOCKED: Force-push is not permitted. Open a PR." >&2; exit 2; fi

if echo "$CMD" | grep -qE '\-\-no-verify'; then
  echo "BLOCKED: --no-verify skips the hook chain. Not permitted." >&2; exit 2; fi

if echo "$CMD" | grep -qiE 'psql.*prod|DATABASE_URL.*prod|PROD_DB'; then
  echo "BLOCKED: Direct production database access is not permitted." >&2; exit 2; fi

if echo "$CMD" | grep -qE 'kubectl.*(apply|delete|rollout).*(prod|production)'; then
  echo "BLOCKED: kubectl writes to production are not permitted. Use reviewed IaC PRs." >&2; exit 2; fi

exit 0
