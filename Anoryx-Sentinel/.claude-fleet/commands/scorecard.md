---
name: scorecard
description: Show Bench Coach's agent scorecard and routing recommendations.
---
Invoke bench-coach with:
"Analyze Anoryx-Sentinel/orchestrator/scorecard.jsonl and
Anoryx-Sentinel/orchestrator/ledger.jsonl. Produce a full scorecard summary
with routing recommendations for each agent."

Format output as table:
agent | first_pass_rate | avg_findings | avg_retries | mean_est_cost_usd | verdict

Note: mean_est_cost_usd is a client-side estimate (total_cost_usd from SDK).
Reconcile against the Anthropic Usage and Cost API for authoritative figures.
