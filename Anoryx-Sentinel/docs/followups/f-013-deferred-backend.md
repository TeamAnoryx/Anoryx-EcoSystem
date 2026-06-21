# F-013 follow-up: dashboard backend completeness (F-013.1)

F-013 shipped the three dashboards frontend-only (R2: no silent backend
endpoints). Six panels are deferred because the F-011/F-012a APIs don't yet
expose the data. Each needs a backend addition with its own security review.

## Deferred (all traced to ADR-0016)
1. Per-model breakdown (security) — audit projection has no `model` field.
   Needs: add model to the event/audit projection.
2. Per-control gap list (compliance) — F-011 operator endpoint returns totals
   only. Needs: per-control passed/gap/not_covered read endpoint.
3. Evidence-pack ZIP download (compliance) — no download route; BFF is JSON-only
   and can't stream binary. Needs: a binary-streaming download route + BFF
   passthrough that preserves pack bytes exactly (tamper-evidence depends on it).
4. Full model inventory (governance) — partial; needs an inventory read.
5. WebSocket real-time feed — polling shipped in v1 (Fork 1 decision). Optional.
6. Shadow-AI feed detail — progressive; F-007 is detect-only (F-018 folded into
   F-007 per Path Y). No separate task; as complete as the backend is.

## Note
Items 2 and 3 are highest-value — the per-control gap report and the downloadable
evidence pack are what a compliance buyer most wants to click. Until they land,
the compliance dashboard shows the readiness score honestly but cannot show
per-control detail or download the pack. Bundle as F-013.1 before any
compliance-focused demo.
