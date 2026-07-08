"""Delta live cost-to-value dashboards (D-008).

Read-only aggregates over the D-003 ledger (``ledger_entries``): real-time spend,
burn rate, top spenders, and cost-per-request, parametrized by tenant + an optional
team/project/agent scope and time window ("client/team-set parameters" — the
real-time project-parametrized view the roadmap asks for).

Honesty boundary: "cost-per-outcome" (from the roadmap's one-line description) is
NOT built here. Delta has no "outcome" domain concept (success/failure, task
completion) anywhere in its model — that is Sentinel's territory, not something
usage events carry today. Only cost-per-REQUEST is computed (spend / request count),
stated explicitly rather than implied to be something it is not. See
``docs/adr/0008-delta-cost-dashboards.md`` §1.
"""

from __future__ import annotations
