#!/usr/bin/env bash
# SubagentStop hook: appends a scorecard row for Bench Coach analytics.

set -euo pipefail
TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
mkdir -p Anoryx-Sentinel/orchestrator

python3 -c "
import json, sys, select
raw = sys.stdin.read() if select.select([sys.stdin],[],[],0.1)[0] else '{}'
try: data = json.loads(raw)
except: data = {}
row = {'ts': '$TS', 'agent': data.get('agent_id','unknown'),
       'session_id': data.get('session_id',''), 'raw': data}
with open('Anoryx-Sentinel/orchestrator/scorecard.jsonl','a') as f:
    f.write(json.dumps(row)+'\n')
"
exit 0
