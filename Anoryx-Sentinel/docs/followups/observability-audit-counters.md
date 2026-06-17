# Audit-write-failure observability counters

**Status:** Follow-up (deferred from F-008) · **Priority:** MED · **Effort:** ~2–3h fleet work

## Context

Both F-004 (gateway terminal audit) and F-008 (policy intake) emit ERROR-level structured logs
when an audit-log write fails, but neither increments any Prometheus counter:

- F-004 terminal audit: `terminal_audit_emit_failed_post_response`, `audit_append_failed`
  (`src/gateway/middleware/terminal_audit_wrapper.py`, `src/gateway/middleware/audit.py`)
- F-008 intake reject path: `policy_intake_reject_audit_failed`
  (`src/policy/intake.py`)

An audit-write failure is a silent-degradation event: the security outcome is preserved (a
rejection is still returned; an unauditable accept rolls back), but the compliance-evidence row is
lost. Today an operator can only alert via log-based rules on these event keys — there is no metric
to scrape or threshold on.

## Scope

Add a single counter, incremented on **every** audit-write failure across all audit-emitting code:

```
sentinel_audit_write_failures_total{component, event_type}
```

- `component`: e.g. `gateway_terminal_audit`, `policy_intake`, and any future audit emitter.
- `event_type`: the audit event variant whose write failed.

Wire it at each existing `log.error`/`log.exception` audit-failure site (F-004 terminal audit +
F-008 intake) so the counter and the structured log fire together. New audit-emitting code must
increment the same counter.

## Why deferred from F-008

Observability instrumentation (OpenTelemetry / Prometheus) is a **platform-infra** concern, not a
policy-engine concern. This gap **pre-existed F-008** (F-004 has it too) and should be fixed across
features at once, in one place, rather than bolted onto the policy engine alone.

## Interim mitigation

Log-based alerting on the structured event keys above works now and should be configured in the
alerting layer until this counter lands.

## Acceptance

- `sentinel_audit_write_failures_total` registered and incremented at the F-004 and F-008 failure
  sites, labeled by `{component, event_type}`.
- A test asserts the counter increments when an audit append is forced to fail (mirrors
  `test_audit_append_failure_on_accept_rolls_back_policy`).
- Alerting rule documented for the new metric.
