#!/usr/bin/env bash
# PreToolUse hook: protects contract files and blocks secret patterns.
# Exit 0 = allow.  Exit 2 = BLOCK.

set -euo pipefail
INPUT=$(cat)

FILEPATH=$(echo "$INPUT" | python -c \
  "import sys,json; d=json.load(sys.stdin)
t=d.get('tool_input',{})
print(t.get('path', t.get('file_path', t.get('new_path',''))))" 2>/dev/null || echo "")

CONTENT=$(echo "$INPUT" | python -c \
  "import sys,json; d=json.load(sys.stdin)
t=d.get('tool_input',{})
print(t.get('content', t.get('new_string','')))" 2>/dev/null || echo "")

AGENT=$(echo "$INPUT" | python -c \
  "import sys,json; d=json.load(sys.stdin); print(d.get('agent_id',''))" 2>/dev/null || echo "")

# BLOCK: Anoryx-Sentinel/contracts/ — only api-architect may edit
if echo "$FILEPATH" | grep -qE 'Anoryx-Sentinel/contracts/'; then
  if [ "$AGENT" != "api-architect" ]; then
    echo "BLOCKED: Only api-architect may edit Anoryx-Sentinel/contracts/." >&2
    echo "Attempting agent: '$AGENT'. Route this task to api-architect." >&2
    exit 2
  fi
fi

# BLOCK: .env files anywhere in the monorepo
if echo "$FILEPATH" | grep -qE '\.env($|\.|/)'; then
  echo "BLOCKED: Writing to .env files is not permitted by agents." >&2; exit 2; fi

# BLOCK: secret patterns in written content
if echo "$CONTENT" | grep -qE \
  '(AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|sk-[a-zA-Z0-9]{48}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY)'; then
  echo "BLOCKED: Content contains a credential pattern. Use Vault/KMS references." >&2; exit 2; fi

exit 0
