# ADR-0026: Double-Begin Fail-Open Fix (F-009 rate-limit + F-018 egress)

- Status: Proposed
- Date: 2026-06-26
- Builds on: ADR-0005 (`get_tenant_session` GUC/autobegin contract), ADR-0006
  (F-009 multi-tier rate limiting), ADR-0010 (F-007 LLM-as-judge), ADR-0021
  (F-018 shadow-AI egress, detect-only), ADR-0025 (the PR that found this class)
- Supersedes: none

## Context

`get_tenant_session()` (`src/persistence/database.py`) runs
`SELECT set_config('app.current_tenant_id', …, true)` **before** it yields the
session. That `execute` **autobegins** a transaction. Any caller that then opens
`async with session.begin():` raises
`sqlalchemy.exc.InvalidRequestError: a transaction is already begun on this
Session` — **on every real-DB request, deterministically**, not only under load
or DB failure. Where a broad `except` catches that error, the control silently
**fails open / goes dark**. This is invisible to any test that stubs the session
factory or sets its own context, which is exactly how it shipped.

ADR-0025 (PR #31) found and fixed this in the F-007 judge path. The follow-up
`docs/followups/f-007-double-begin-siblings.md` catalogs two **live siblings in
shipped security controls** plus the docstring that propagates the pattern:

| site | feature | effect on a real DB (pre-fix) |
|---|---|---|
| `gateway/middleware/rate_limit.py:353` `_fetch_team_rpm_limit_from_db` | F-009 team-RPM tier | `begin()` raises → caught → `limit=None` cached → the opt-in per-team RPM ceiling is **silently never enforced** (fail-open) |
| `gateway/middleware/egress_monitor.py:95` `_resolve_allowed_providers` | F-018 shadow-AI egress | `begin()` raises → bubbles to the `chat_completions` bind-swallow → contextvar stays `None` → the outbound monitor is **fully dark on every request** (fail-open) |
| `persistence/database.py:282` (docstring) | — | the `Usage:` example shows the bad `begin()`-after pattern; it is the copy-paste source of the whole class |

These are not latency bugs; they are controls that do not control. F-018's
monitor has been dark on every real-DB request since it shipped (the `begin()`
raises unconditionally, not only on a DB error).

## Decision

Apply the ADR-0025 proven fix at each site — **remove the redundant
`session.begin()`; read directly on the autobegun transaction** — and correct
the surrounding error handling so it can no longer swallow a `begin()`-class
**logic** error. The narrowed `except` is the actual fix: the original bug was a
logic error (`InvalidRequestError`) hiding inside a too-broad `except Exception`.

The proven fix has **two shapes** (both already in `main` from PR #31):
1. `get_classifier_config` — removed `begin()`, **no** try/except; the error
   propagates to the caller's fail-safe.
2. `_model_authorized` — removed `begin()`, **kept** try/except → `False`
   (fail-safe); since `begin()` is gone, the `except` now only sees genuine infra
   errors.

Each site adopts the shape that matches its fail posture (below). `InvalidRequestError`
is **not** a subclass of `OperationalError`/`InterfaceError`, so the narrowed
`except (OperationalError, InterfaceError, TimeoutError, OSError)` lets a double-begin (and any future
logic defect) **propagate** instead of being swallowed.

### Fork 1 — F-009 rate-limit fail posture: **deliberate fail-open on connectivity**

A rate limiter is fundamentally an **availability** control, not a security
boundary. The Redis tenant-RPM and virtual-key-RPM tiers still cap every request
regardless of this DB read; only the opt-in **team-tier ceiling** depends on it.
Failing this read *closed* (deny/limit) on a transient Postgres blip would be a
self-inflicted DoS on legitimate team traffic. So on a **genuine DB-connectivity
error**, the team tier no-ops (`limit=None`) — deliberate, bounded fail-open.

The real correction: narrow `except Exception` → `except (OperationalError,
InterfaceError)` so the `begin()` logic error (and any future logic defect)
**raises** instead of silently disabling the tier. Also: **do not cache `None`
on a connectivity error** (the pre-fix code poisoned the TTL cache, extending the
no-op past the blip).

### Fork 2 — F-018 egress fail posture: **flag-on-uncertainty (not block, not dark)**

F-018 is **detect-only** (ADR-0021): it must never block the request, so
"fail-closed = deny" is off the table by design. But "fail-closed" for a monitor
means **don't go dark** — when it cannot verify the allow-list, it should *alert*,
not suppress. On a genuine DB-connectivity error, bind an **empty** allow-list so
every tracked outbound provider emits `shadow_ai_detected_outbound`. This is a
**two-layer** fix (removing `begin()` alone fixes only the healthy path):

1. `_resolve_allowed_providers`: remove `begin()` (read on autobegin).
2. `bind_egress_context`: `try/except (OperationalError, InterfaceError, TimeoutError, OSError)` →
   bind `allowed_providers=()` (flag-all) + explicit log; non-connectivity errors
   propagate.
3. `chat_completions.py:256-261`: narrow the outer `except Exception` →
   `except (OperationalError, InterfaceError, TimeoutError, OSError)` so a logic defect surfaces instead
   of re-darkening the monitor; the "never block on a connectivity bind failure"
   intent is preserved for the connectivity case.

**Noise tradeoff (honest):** during a DB outage an empty allow-list flags the
request's *own* legitimate provider call. That is the intended "I could not
verify" posture for a detect-only monitor; the alternative — going dark — is the
bug. The monitor never blocks, so the only cost is alert volume during an outage.

### Fork 3 — sweep: **clean, no other same-class sites**

A full `\.begin(` sweep over `Anoryx-Sentinel/src` confirms every other
occurrence is `get_privileged_session()` → `.begin()` (correct — privileged
sessions do not autobegin) or a contract-documenting comment. The only same-class
`get_tenant_session`→`begin()` sites are the two runtime functions above + the
`database.py:282` docstring. A regression assertion (vector 5) encodes this so it
cannot silently return.

## Why this is the real fix (not just a posture change)

The bug that bit F-007 was a **logic** error (`InvalidRequestError`) caught by a
`except Exception` that was meant to absorb *infra* errors. Narrowing the
`except` to the DB-connectivity family is what closes the swallow: a future
`begin()`-style logic defect now **raises loudly** (caught in tests/CI) instead
of silently disabling the control. The fail-open/closed posture is secondary; the
primary win is that the swallow can no longer hide a logic bug. This is why each
site gets a **second** test that injects a *non-connectivity* error and asserts
it propagates — proving the narrowing on code, not on paper.

The connectivity family is `(OperationalError, InterfaceError, TimeoutError, OSError)`.
`sqlalchemy.exc.TimeoutError` (pool-checkout timeout) and `OSError` are named
**explicitly** because the two SQLAlchemy connection classes do NOT cover the
**dominant** real failures: a down/restarting Postgres, where asyncpg raises a builtin
`ConnectionRefusedError` (an `OSError`), and a `command_timeout`, which raises the
builtin `TimeoutError` (also `OSError`). `OSError` covers connect-refused, DNS
(`socket.gaierror`), and command-timeout. Crucially, `InvalidRequestError` /
`ProgrammingError` are **not** `OSError` and not in this family, so the double-begin and
any logic defect still propagate. Omitting `OSError` (the original narrow set) turned a
DB outage into a request-blocking 500 — a never-block violation for F-018 and a self-DoS
for F-009 (independent audit High; vectors 2c/2d/4c/4d guard it).

## Threat model (vectors → test paths)

| # | vector | expectation | proof |
|---|---|---|---|
| 1 | F-009 team-RPM really enforced via a real autobegin session | pre-fix: silently skipped (test FAILS); post-fix: ceiling applied | `test_team_rpm_limit_read_on_real_db` |
| 2 | F-009 logic-error propagates (R1 add-on) | inject a non-connectivity error → `_fetch_team_rpm_limit_from_db` **raises**, not swallowed | `test_team_rpm_logic_error_propagates` |
| 2b | F-009 connectivity error fails open | injected `OperationalError` → `limit=None`, proceeds (Redis tiers still cap); `None` not cached | `test_team_rpm_fails_open_on_db_connectivity_error` |
| 2c | F-009 pool-timeout fails open | injected `sqlalchemy.exc.TimeoutError` (pool checkout) → `limit=None`, not cached, never blocks | `test_team_rpm_fails_open_on_db_pool_timeout` |
| 2d | F-009 down-DB / cmd-timeout fails open | injected builtin `ConnectionRefusedError` / `TimeoutError` (OSError) → `limit=None`, not cached | `test_team_rpm_fails_open_on_raw_oserror` |
| 3 | F-018 egress monitor really runs via a real autobegin session | pre-fix: dark (test FAILS); post-fix: allow-list resolved & bound | `test_egress_monitor_resolves_committed_allowlist` |
| 4 | F-018 logic-error propagates (R1 add-on) | inject a non-connectivity error → `bind_egress_context` **raises**, not swallowed | `test_egress_logic_error_propagates` |
| 4b | F-018 connectivity error flags, not dark | injected `OperationalError` → empty allow-list bound (every tracked egress flagged) | `test_egress_binds_empty_allowlist_on_db_connectivity_error` |
| 4c | F-018 pool-timeout flags, not dark/block | injected `sqlalchemy.exc.TimeoutError` → empty allow-list bound (never a 500) | `test_egress_binds_empty_allowlist_on_db_pool_timeout` |
| 4d | F-018 down-DB / cmd-timeout flags, not block | injected builtin `ConnectionRefusedError` / `TimeoutError` (OSError) → empty allow-list bound (never a 500) | `test_egress_binds_empty_allowlist_on_raw_oserror` |
| 5 | no remaining same-class sites | static sweep asserts zero `get_tenant_session`→`session.begin()` sites | `test_no_remaining_double_begin_after_get_tenant_session` |
| 6 | healthy-DB no regression | both controls behave exactly as intended; only change is "now runs" | covered by vectors 1 & 3 healthy path |

The vector-1 and vector-3 tests must **fail on the pre-fix line** (begin() restored)
and pass after — that is the proof the bug is genuinely fixed, not merely that the
old (blind) suite still passes.

## Consequences

- **+** Two shipped security controls that were silently fail-open now actually
  run on a real DB (risk reduction in the security path).
- **+** The narrowed `except` closes the swallow that hid the original logic bug;
  a future `begin()`-class defect raises loudly instead of disabling a control.
- **+** Per-site fail posture is now deliberate and documented (F-009
  availability-preserving fail-open; F-018 alert-preserving flag-on-uncertainty).
- **−** During a DB outage, F-018 flags every tracked provider (including the
  legitimate one) — bounded alert noise, never a block (accepted tradeoff).
- **−** A genuine *logic* defect at these sites now surfaces as an error rather
  than a silent no-op — intended: it surfaces loudly rather than silently disabling
  the control, which CI is positioned to catch (no sweep is exhaustive).
- **−** A server-side `statement_timeout` (a DB-hardening GUC, not currently set)
  surfaces as a generic `sqlalchemy.exc.DBAPIError`, deliberately NOT in the catch set
  (catching `DBAPIError` broadly would re-swallow `ProgrammingError` logic defects). If
  `statement_timeout` is ever configured, this path must be revisited — a documented
  residual (independent audit Medium).
- No schema/migration change (head stays `0032`). No contract change. No
  feature/logic change beyond removing `begin()` + correcting the swallow.

## Honest residual

- This fixes the **two known siblings** + the docstring source. The sweep (R5) is
  clean for `get_tenant_session`→`session.begin()`, but it is a grep sweep of the
  current tree — it does not prove no future caller reintroduces the pattern
  (vector 5 + the corrected docstring are the guardrails against that).
- F-009's team tier remains a *deliberate* fail-open on connectivity loss; a
  determined actor who can induce a Postgres outage removes only the team-tier
  ceiling, not the Redis tenant/vkey ceilings.
- F-018 remains **detect-only** — it flags, never blocks; the empty-allow-list
  posture raises alert volume during an outage rather than improving detection
  quality. No monitor catches every shadow-AI egress (ADR-0021 residual stands).

## Rollback

Pure code revert — no migration, no data change. Reverting the four source edits
restores the prior (fail-open) behavior; the new tests are additive. Because the
fix changes only error-path handling, a healthy-DB deployment behaves identically
before and after except that the two controls now actually run.
