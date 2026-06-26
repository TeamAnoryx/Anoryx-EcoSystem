# Security Audit — F-007-FU Double-Begin Fail-Open Fix (ADR-0026)

- Auditor: Independent Security Auditor (arms-length; did not write or review the change)
- Date: 2026-06-26
- Branch: `task/F-007-fu-double-begin-native`
- Verdict: **BLOCK** (1 High, 1 Medium, 2 Low)
- Decision record under review: `Anoryx-Sentinel/docs/adr/0026-double-begin-fail-open-fix.md`
- Controls in scope: F-009 team-RPM rate limit, F-018 shadow-AI egress monitor
- Posture: zero-trust; Sentinel's own code is a target; no benefit of the doubt.

## 1. Scope

Working-tree change (uncommitted) on `task/F-007-fu-double-begin-native`:

| File | Change |
|---|---|
| `src/gateway/middleware/rate_limit.py` | `_fetch_team_rpm_limit_from_db`: removed `session.begin()`; narrowed `except` to `(OperationalError, InterfaceError, SATimeoutError)`; `return None` (no cache) on connectivity error |
| `src/gateway/middleware/egress_monitor.py` | `_resolve_allowed_providers`: removed `session.begin()`; `bind_egress_context`: try/except connectivity -> bind empty allow-list (flag-all) |
| `src/gateway/routes/chat_completions.py` (~265-271) | Outer egress-bind `except Exception` narrowed to the same 3 connectivity classes |
| `src/persistence/database.py` (~278-285) | Docstring corrected (autobegin contract) |
| `tests/double_begin/` (new) | conftest + `test_rate_limit_real_db` + `test_egress_real_db` + `test_sweep` |

Out of scope: any code not in the diff. Live Postgres on `localhost:5432` was used for empirical verification.

## 2. Method

1. Threat-modelled the change: the new trust boundary is the **DB-failure exception surface**. The original bug was a *logic* error (`InvalidRequestError`) absorbed by a too-broad `except`; the fix relies on the **completeness and correctness of an enumerated connectivity exception set**. That set is the attack surface.
2. Read all four changed files in full and the surrounding admission/egress call paths (`check_rate_limit` -> `_redis_primary_check` -> `_get_team_rpm_limit_async`; `create_chat_completion` outer handler).
3. Verified the SQLAlchemy 2.0.51 / asyncpg 0.31.0 exception-translation behaviour by reading the installed dialect (`_asyncpg_error_translate`, `_handle_exception`) **and** by empirically inducing four realistic DB failures against the live DB.
4. Re-ran the new test package post-fix (green) and pre-fix (via `git stash`) to confirm the vectors genuinely fail on the unpatched source.
5. Ran the required tooling: Semgrep (`p/python`, `p/security-audit`, `p/secrets`, `--severity=ERROR`), `ruff`, `black`.
6. Ran an independent, stricter (multi-line/aliased) sweep for `get_tenant_session(...) -> .begin()` beyond the single-line static test.
7. Honest-language review of the ADR and the new comments.

### Tooling results

- **Semgrep** (3 rulesets, ERROR severity) on the four changed source files: **0 results, 0 errors**.
- **ruff**: No issues found. **black --check**: all 9 files unchanged.
- **Test package** post-fix: `9 passed` (the two real-DB vectors RAN, not skipped — DB was reachable).
- **Test package** pre-fix (`git stash` of the four source files): `8 failed, 1 passed` — vectors 1 and 3 (the non-stubbed real-DB ones) FAILED, proving the double-begin is genuinely fixed.

## 3. Per-claim verification

| # | Claim under audit | Result |
|---|---|---|
| 1 | Both controls genuinely run on a real DB; vectors 1 & 3 are non-stubbed | **Confirmed.** Vector 1 sets `_get_tenant_session = get_tenant_session` (real autobegin) and reads cross-session COMMITTED data; vector 3 calls `bind_egress_context` with NO patch of `_resolve_allowed_providers` (real `get_tenant_session`). Both FAIL pre-fix (begin() raises) and PASS post-fix. No hidden stub of the autobegin. |
| 2 | Connectivity exception set complete AND correct | **FAILED — see Finding 1 (High) + Finding 2 (Med).** `InvalidRequestError` correctly propagates, but the set misses the builtin OSError family (ConnectionRefusedError on DB-down), builtin TimeoutError (command_timeout), and generic DBAPIError (statement_timeout). |
| 3 | Non-stubbed tests genuinely failed pre-fix | **Confirmed** via `git stash` reproduction (8 failed, 1 passed). Only `test_egress_logic_error_propagates` passes pre-fix (degenerate: pre-fix had no try/except, so the ValueError propagated anyway). |
| 4 | F-018 never-block invariant holds on every path | **FAILED — Finding 1.** On connect-refused, `bind_egress_context` propagates a `ConnectionRefusedError` that reaches the route uncaught -> 500 -> blocks the request. Violates ADR-0021. |
| 5 | F-009 fail-open is bounded (Redis tiers still cap; no cache poisoning) | **Confirmed for the handled path.** `_redis_primary_check` caps via Tier 1 (virtual-key) and Tier 3 (tenant) independent of the team-tier DB read; the handled connectivity error returns `None` WITHOUT caching (no TTL poisoning); the success path caches correctly; cache key is server-resolved `(tenant_id, team_id)` — no injection/poisoning vector. **But** the *unhandled* connect-refused path (Finding 1) turns this bounded fail-open into a 500. |
| 6 | Sweep completeness (R5) — no other `get_tenant_session -> begin()` sites | **Confirmed.** A stricter independent sweep (tolerating multi-line args / aliases over 57 `as name:` sites) found only one match — a false positive where a comment mentions `get_tenant_session(tenant_id)` while the real binding is `get_privileged_session()` (correct). No real offenders. |
| 7 | Honest language in ADR + comments | **Partial — Finding 4 (Low).** No banned absolute-claim words, but the ADR/comments assert fail-open / never-block on "connection loss" while the dominant connection-loss mode is unhandled — the record overstates delivered coverage. |

## 4. Findings

### Finding 1 — High — Connectivity except set misses the builtin OSError family (DB-down 500s both controls)

- Files: `src/gateway/middleware/egress_monitor.py:132`, `src/gateway/middleware/rate_limit.py:372`, `src/gateway/routes/chat_completions.py:271`
- The narrowed catch is `(OperationalError, InterfaceError, sqlalchemy.exc.TimeoutError)`. `sqlalchemy.exc.TimeoutError` is **pool checkout** timeout only. The most common real connectivity failure — Postgres down / restarting / failing over — surfaces at the SQLAlchemy/asyncpg boundary as a **builtins.ConnectionRefusedError** (an `OSError`), which is in none of the three classes.

Empirical evidence (live DB, SQLAlchemy 2.0.51 + asyncpg 0.31.0):

| Induced failure | Class at the boundary | Caught by fix? |
|---|---|---|
| Pool checkout timeout | `sqlalchemy.exc.TimeoutError` | YES |
| Backend terminated mid-query | `sqlalchemy.exc.InterfaceError` | YES |
| **DB down (connection refused)** | **`builtins.ConnectionRefusedError`** | **NO** |
| asyncpg command_timeout | `builtins.TimeoutError` | NO (Finding 2) |
| server statement_timeout | `sqlalchemy.exc.DBAPIError` (generic) | NO (Finding 2) |

Confirmed through the **real** `get_tenant_session` app engine path with the URL pointed at a refused port: both `_fetch_team_rpm_limit_from_db` and `bind_egress_context` raised `builtins.ConnectionRefusedError`.

- Exploit path:
  - **F-018 (never-block violation):** `bind_egress_context` is called unconditionally for every `/v1/chat/completions`. On a DB blip, `_resolve_allowed_providers` raises `ConnectionRefusedError` -> not caught at `egress_monitor.py:132` -> propagates to the caller's `except (OperationalError, InterfaceError, SATimeoutError)` at `chat_completions.py:271` (no catch) -> the route's only outer handler is `except GatewayError` -> uncaught -> 500. The user's AI request is **blocked** for 100% of traffic during the outage. ADR-0021 detect-only / never-block is violated — the exact invariant Fork 2 claims to preserve.
  - **F-009 (self-DoS):** `_fetch_team_rpm_limit_from_db` raises `ConnectionRefusedError` -> propagates through `_get_team_rpm_limit_async` -> `_redis_primary_check` -> not caught by `except (RedisConnectionError, RedisTimeoutError)` -> 500 for every request carrying a `team_id`. This is precisely the self-inflicted DoS that Fork 1's deliberate fail-open exists to prevent.
- Why High: a security-control fix that does not deliver its documented safety posture under the single most common connectivity failure, with total blast radius during the event, on a gateway in the critical path of all enterprise AI traffic, and a documented-invariant (ADR-0021) violation — proven on the real code path.
- Fix: `except (OperationalError, InterfaceError, SATimeoutError, OSError)` at all three sites. `OSError` covers `ConnectionRefusedError`, the builtin `TimeoutError` from command_timeout, and `socket.gaierror` (DNS). `InvalidRequestError` and `ProgrammingError` are not `OSError`, so the double-begin / logic-defect propagation guarantee is preserved. Add tests injecting raw `builtins.ConnectionRefusedError` and `builtins.TimeoutError`.

### Finding 2 — Medium — Latent timeout classes escape the set (command_timeout, statement_timeout)

- Files: `rate_limit.py:372`, `egress_monitor.py:132`, `chat_completions.py:271`
- Currently latent: no `command_timeout` connect arg and no `statement_timeout` GUC are configured. If either is introduced (statement_timeout is a common DB-hardening step), a slow tenant_routing_policy read raises `builtins.TimeoutError` (OSError) or the generic `sqlalchemy.exc.DBAPIError` respectively — both outside the set — reproducing the Finding 1 outcome under load rather than outage.
- Fix: the `OSError` addition closes command_timeout. For statement_timeout, either catch `DBAPIError` where `connection_invalidated` is True, or explicitly document statement_timeout as out-of-scope and assert no `statement_timeout` GUC is set in the deployment.

### Finding 3 — Low — Test suite shares the code's blind spot

- File: `tests/double_begin/test_rate_limit_real_db.py`, `test_egress_real_db.py`
- Connectivity vectors inject only the SQLAlchemy wrapper classes; none inject a raw `OSError`/`ConnectionRefusedError`. The suite stays green even though the dominant failure mode is unhandled — the same dynamic that originally hid the double-begin bug.
- Fix: add vectors raising `builtins.ConnectionRefusedError` and `builtins.TimeoutError` and assert fail-open (F-009) / flag-empty bind (F-018).

### Finding 4 — Low — ADR/comments overstate delivered coverage (honest language)

- File: `docs/adr/0026-double-begin-fail-open-fix.md` (Fork 1/Fork 2/Consequences); comments at `rate_limit.py`, `egress_monitor.py`, `chat_completions.py`
- The record claims the controls fail-open / never-block on "connection loss," but connect-refused (the dominant connection-loss mode) 500s. A delivered-posture overstatement on a security-control decision record — a Sentinel honest-language / fail-safe non-negotiable.
- Fix: implement Finding 1 (making the claim true), or correct the ADR/comments to enumerate the exact handled classes.

## 5. What holds (verified)

- The double-begin defect is **genuinely fixed**: vectors 1 & 3 are truly non-stubbed (real `get_tenant_session` autobegin, COMMITTED cross-session data), FAIL pre-fix and PASS post-fix.
- `InvalidRequestError` and other logic defects (`ValueError`, `ProgrammingError`) correctly **propagate** — not in the catch set (vectors 2 and 4 confirm).
- F-009 fail-open on a **handled** connectivity error is bounded: Redis virtual-key (Tier 1) and tenant (Tier 3) tiers still cap; `None` returned without caching (no TTL poisoning); cache key server-resolved (no poisoning/injection).
- F-018 empty-allow-list flag-all works.
- Sweep R5 clean under a stricter multi-line/aliased sweep.
- Semgrep ERROR = 0; ruff clean; black clean.
- No secrets/PII introduced; error logging uses `error_class` (type name) only, never the message (L3 preserved). No SQLi (parameterized ORM select), no SSRF/path-traversal/insecure-deserialization; no new dependency.

## 6. Verdict

**BLOCK.** Finding 1 is High and mandates human escalation. The change correctly fixes the double-begin logic error and its fail-open behaviour for two of the five realistic connectivity failure classes, but does **not** deliver its documented fail-open (F-009) / never-block (F-018, ADR-0021) posture for the most common one — a down/restarting Postgres — which 500-blocks both controls. Verified on the real code path against the live DB, not on the test stubs.

## 7. Residual risk (after the recommended fix)

- With `OSError` added, the connect-refused and command_timeout cases match the documented posture.
- `statement_timeout` (generic `DBAPIError`) remains a residual unless explicitly handled or documented out-of-scope (Finding 2).
- The enumerated-exception-set approach is inherently fragile against driver/version changes; the regression vectors + corrected docstring are the only guardrails; the sweep is a point-in-time grep, not a proof against future reintroduction.

## 8. Reproduction appendix

- Post-fix: `SENTINEL_PROVISION_APP_ROLE=1 PYTHONPATH=src python -m pytest tests/double_begin -v` -> 9 passed (real-DB vectors ran).
- Pre-fix proof: `git stash push -- <the four source files>`; re-run -> `8 failed, 1 passed` (vectors 1 & 3 red); `git stash pop`.
- Real-path probe: real `get_tenant_session` app engine with the URL pointed at a refused port -> both `_fetch_team_rpm_limit_from_db` and `bind_egress_context` raised `builtins.ConnectionRefusedError` (independently reproduced by the main session).

## 9. Re-audit (post-fix) — VERDICT: PASS, BLOCK LIFTED

After Finding 1 was fixed (added `OSError` to all three connectivity except tuples →
`except (OperationalError, InterfaceError, SATimeoutError, OSError)`; new vectors 2d/4d;
ADR + comments corrected; `statement_timeout` documented as a residual), an independent
re-verification (read-only; no tree-mutating git):

1. **Finding 1 (High) CLOSED — empirically, real `get_tenant_session` path, down DB:**
   F-009 `_fetch_team_rpm_limit_from_db` → returned `None` (fail-open), not cached, did
   NOT raise; F-018 `bind_egress_context` → bound empty allow-list `()` (flag-all), did
   NOT raise. No 500. Matches ADR-0021 never-block + Fork-1/Fork-2 posture.
2. **Logic defects still PROPAGATE:** `issubclass(ProgrammingError, OSError)` and
   `issubclass(InvalidRequestError, OSError)` are both `False` — the `OSError` widening
   cannot mask a double-begin or any SQL logic defect.
3. **Test package: 13 passed** (incl. 2d/4d parametrized + non-stubbed real-DB 1 & 3).
   Finding 3 (test blind spot) closed.
4. **ruff** clean; **black --check** 9 files unchanged; **Semgrep** (`p/python`,
   `p/security-audit`, `p/secrets`, ERROR) 0 results on the four changed source files.
5. Honest-language (Finding 4) corrected — claims now match delivered behavior.

**Residual (Low, accepted):** `statement_timeout` → generic `sqlalchemy.exc.DBAPIError`
is deliberately NOT caught (catching `DBAPIError` broadly would re-swallow
`ProgrammingError` logic defects); not configured in deployment; documented in ADR-0026
Consequences with a "revisit if configured" note.

**Final verdict: PASS.** No High/Critical findings. The double-begin fix is genuinely
proven (pre-fix fail proof recorded in §8) and now delivers its documented fail-open
(F-009) / never-block (F-018) posture for the dominant connectivity failures.
