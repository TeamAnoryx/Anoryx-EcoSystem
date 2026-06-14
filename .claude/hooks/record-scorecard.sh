#!/usr/bin/env bash
# SubagentStop hook: appends a scorecard row for Bench Coach analytics.
# Cross-platform stdin read — no select(), works on Windows/macOS/Linux.

set -euo pipefail
TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
mkdir -p Anoryx-Sentinel/orchestrator

# Read stdin into a variable. If there's no input (timeout/empty), use {}.
# 'read -t 1 -d ""' is the portable equivalent of a non-blocking stdin read.
INPUT=""
if IFS= read -r -t 1 -d "" INPUT 2>/dev/null; then
  :
fi
INPUT="${INPUT:-\{\}}"

# NOTE: `python` (not `python3`) — python3 is not on PATH in this environment;
# all hooks use `python` per commit a684ff4.
python - <<PYEOF "$TS" "$INPUT"
import json, sys
ts, raw = sys.argv[1], sys.argv[2]
try:
    data = json.loads(raw) if raw.strip() else {}
except Exception:
    data = {}
row = {
    "ts": ts,
    "agent": data.get("agent_id", "unknown"),
    "session_id": data.get("session_id", ""),
    "hook_event": data.get("hook_event_name", "SubagentStop"),
    "raw": data,
}
with open("Anoryx-Sentinel/orchestrator/scorecard.jsonl", "a") as f:
    f.write(json.dumps(row) + "\n")
PYEOF

exit 0
