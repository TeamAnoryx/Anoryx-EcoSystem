#!/usr/bin/env bash
# PostToolUse hook: auto-formats Python files and runs fast SAST after each write.
# Injects feedback to Claude via stdout JSON so the agent fixes issues next step.

set -euo pipefail
INPUT=$(cat)
FILEPATH=$(echo "$INPUT" | python3 -c \
  "import sys,json; d=json.load(sys.stdin)
t=d.get('tool_input',{})
print(t.get('path', t.get('file_path','')))" 2>/dev/null || echo "")

if ! echo "$FILEPATH" | grep -qE '\.py$'; then exit 0; fi
if [ ! -f "$FILEPATH" ]; then exit 0; fi

FEEDBACK=""

if command -v black &>/dev/null; then
  if ! black --check --quiet "$FILEPATH" 2>/dev/null; then
    black "$FILEPATH" 2>/dev/null || true
    FEEDBACK="$FEEDBACK\n[auto-fixed] black reformatted $FILEPATH"
  fi
fi

if command -v ruff &>/dev/null; then
  RUFF_OUT=$(ruff check "$FILEPATH" 2>&1 || true)
  if [ -n "$RUFF_OUT" ]; then
    ruff check --fix "$FILEPATH" 2>/dev/null || true
    FEEDBACK="$FEEDBACK\n[ruff] $RUFF_OUT"
  fi
fi

if command -v semgrep &>/dev/null; then
  SG_OUT=$(semgrep scan --config=p/python --config=p/secrets \
    --severity=ERROR --quiet --no-git-ignore "$FILEPATH" 2>&1 || true)
  if [ -n "$SG_OUT" ]; then
    echo "SAST finding on $FILEPATH:" >&2; echo "$SG_OUT" >&2
    FEEDBACK="$FEEDBACK\n[SAST] $SG_OUT"
  fi
fi

if [ -n "$FEEDBACK" ]; then
  python3 -c "import json,sys; print(json.dumps({'additionalContext': sys.argv[1]}))" \
    "Post-write checks on $FILEPATH: $FEEDBACK"
fi
exit 0
