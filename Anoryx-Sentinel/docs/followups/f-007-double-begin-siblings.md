# Follow-up: latent `session.begin()`-after-`get_tenant_session` double-begins

Filed out of the ADR-0025 PR per Affu's scope decision (2026-06-26): keep that PR
to F-007 thresholds + the two double-begins the feature required, and track the
remaining siblings here separately.

## Root cause

`get_tenant_session` (src/persistence/database.py) runs
`SELECT set_config('app.current_tenant_id', …)` **before** it yields the session
(database.py:302). That `execute` autobegins a transaction, so any caller that then
does `async with session.begin():` raises `InvalidRequestError: a transaction is
already begun on this Session`. Where that error is caught by a broad `except`, the
control silently **fails open / disabled** on a real DB — invisible to tests that
stub the resolver or pass their own session. (Same class as the F-008/F-019
double-begins already repaired in history.)

## Fixed in the ADR-0025 PR (in scope — the judge needs them)

- `tenant_routing_policy_repository.get_classifier_config` — judge config read was
  returning UNCONFIGURED → judge inert.
- `orchestration/judge/invoker._model_authorized` — judge policy gate was returning
  False → every classifier model fell to policy_denied → judge never ran.

## Remaining siblings (NOT touched — fix separately)

| location | feature | effect on a real DB |
|---|---|---|
| `src/gateway/middleware/rate_limit.py:~353` | F-009 team-RPM tier | `limit=None` → the opt-in per-team RPM ceiling is silently not enforced (fail-open) |
| `src/gateway/middleware/egress_monitor.py:~95` | F-018 shadow-AI egress | egress binding None → the detect-only outbound monitor is silently disabled for the request |
| `src/persistence/database.py:~281` (docstring) | — | the usage example shows the bad `session.begin()`-after pattern; it is the copy-paste source of this whole bug class |

## Fix (each, one line)

Remove the redundant `async with session.begin():` and run the read directly on the
autobegun transaction (no commit needed for reads). Correct the database.py docstring
example. Then add a non-stubbed, real-DB test for each path (the stubbed/own-session
tests cannot catch this — only a fresh `get_tenant_session` against committed data
exposes it).

Source: independent security audit of the ADR-0025 PR
(docs/audit/f-007-thresholds-security-audit.md, findings Medium #1/#2 + Low docstring).
