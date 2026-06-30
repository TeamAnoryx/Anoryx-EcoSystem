# D-004 Security Audit — Delta Event Ingest from the Orchestrator

**Auditor:** Independent Security Auditor (arms-length red-team). Did not write this code.
**Target:** branch `task/D-004-event-ingest`, worktree `E:\Anoryx-EcoSystem\worktrees\d-004`
**Date:** 2026-06-30
**Change under review:** Orchestrator `forward_outbox` push dispatcher
(`Anoryx-AI-Orchestrator/src/orchestrator/dispatch/`) → Delta inbound consume seam
(`Delta/src/delta/ingest/`), idempotent balanced double-entry posting into the D-003
ledger; new migrations Delta `0002_ingest_posting.py` and Orchestrator
`d004_forward_dispatch_state.py`.

## Scope

In scope: the D-004 additions only (consume + posting; enforcement D-005 / kill-switch
D-006 / dashboards D-008 are out of scope and absent). Reviewed:
`Delta/src/delta/ingest/{app,router,hmac_verify,posting,resolver,dlq,errors,config}.py`,
`Delta/src/delta/persistence/models.py` (ingest_dead_letter table), both new migrations,
the touched D-003 trust boundaries (`ledger.py`, `money.py`, `usage.py`,
`persistence/{database,ledger_store}.py`, migration `0001`), and the Orchestrator
dispatcher + signer + privileged session. ADR-0004 read for intent/threat model.

## Methodology

1. Threat-modelled the new trust boundary: a new network-facing HTTP surface
   (`POST /v1/ingest/usage`) authenticated by a shared HMAC, fed by a cross-tenant
   BYPASSRLS drain. New input surface = the wire `UsageEvent` JSON + three signed headers.
2. Static review of every changed file against the 10 focus vectors.
3. **Semgrep** `p/python` + `p/security-audit` + `p/secrets`, `--severity=ERROR`, on all
   changed files (27 scanned): **0 findings, 0 scan errors**.
4. Ran the real suites against the live Postgres (`delta-postgres-d004`,
   127.0.0.1:5544): Delta ingest **42 passed / 1 skipped**; cross-product seam
   **1 passed** (real Orchestrator inbound → real dispatcher → real Delta app → real ledger).
5. Authored adversarial probes against the live DB/app (below).

### Adversarial probe results (live DB, BYPASSRLS-verified where relevant)

| Probe | Attempt | Result |
|---|---|---|
| A | Insert ledger entry for tenant B referencing tenant A's account | **BLOCKED** `ForeignKeyViolationError fk_entry_account` |
| B | `GUC=A`, insert row with `tenant_id=B` | **BLOCKED** `InsufficientPrivilegeError` (RLS WITH CHECK) |
| C | Direct single-leg (unbalanced) insert + commit | **BLOCKED** deferred trigger (`has 1 entries (needs >= 2)`) |
| D | 8-way concurrent first-write of same `event_id` | `applied=1, replays=7, errs=0` → **exactly one** balanced debit |
| G | `delta_app` UPDATE/DELETE on `ingest_dead_letter` | **BLOCKED** `permission denied` (SELECT+INSERT only) |
| H | `orchestrator_app` UPDATE `forward_outbox` | **BLOCKED** `permission denied` (privileged-only transition) |
| E | `verify_signature` with unicode-digit timestamp in-window | RAISES `UnicodeEncodeError` → failsafe 503 (LOW-1) |
| — | over-range `1e30` / `NaN` / `Inf` / negative cost | rejected at `Money.from_wire_cents` → `invalid_cost`, no post |

## Findings

| Severity | File:line | Issue | Exploit scenario | Recommendation |
|---|---|---|---|---|
| LOW | `Delta/src/delta/ingest/hmac_verify.py` (timestamp parse) | `int(timestamp_header)` accepts Unicode decimal digits, but `_expected_signature` does `timestamp.encode("ascii","strict")` → `UnicodeEncodeError`; the router doesn't wrap `verify_signature`, so the catch-all returns **503 instead of 401**. | A caller sends `X-Orchestrator-Timestamp` with unicode digits numerically within ±300 s + any `sha256=…`. `verify_signature` raises → 503. **No ledger write, no auth bypass, no leak** — but the "every malformed input returns False" contract is violated and a forged request gets a retryable 503 not a terminal 401. | Reject non-ASCII timestamps before encoding (`if not timestamp_header.isascii(): return False`). **FIXED in this pass.** |
| INFO | `Delta/src/delta/ingest/router.py` → `dlq.py` | A NUL byte (`U+0000`) survives `raw.decode("utf-8","replace")` into the stored snippet; the `ingest_dead_letter.original_payload` JSONB insert then fails non-transiently (PG cannot store NUL). Event preserved only in the emergency-audit log line, not the DLQ table. | Reaching the JSON-parse path requires a valid HMAC (secret-holder/dispatcher), whose bodies originate NUL-free from JSONB → unreachable on the real path. Not a silent loss (logged, no secret), but the DLQ row is absent. | Strip `U+0000` from the snippet before insert. **FIXED in this pass** (snippet NUL-stripped). |
| INFO | `Delta/src/delta/ingest/hmac_verify.py` (ADR §3.3) | No nonce/replay cache; a captured valid signed request is replayable within ±300 s. | For `usage` events the ledger idempotency key (`event_id`) makes a replay a no-op → no double-debit, so the risk is neutralized today. | Acceptable as-is; add a seen-signature cache if a non-idempotent endpoint is later mounted on this seam. |
| INFO | `Delta/.../migrations/versions/0002_ingest_posting.py` | Migration reversibility validated by inspection + the existing CI round-trip, not independently re-run this pass (to avoid disturbing concurrent sessions). | n/a — downgrade reverses every object in dependency order and never drops the `delta` schema. | None; flagged for transparency. (Round-trip independently re-run green by the builder this pass.) |

No Critical, High, or Medium findings.

## Per-focus-area verdicts

1. **Tenant confusion (cross-tenant write): PASS.** RLS context derived only from the
   validated payload `tenant_id` via `get_tenant_session`, set as a transaction-local GUC
   through a parametrized `set_config` — the payload cannot inject/override it. Defense in
   depth confirmed live: composite same-tenant FK (probe A), RLS WITH CHECK (probe B), and
   the D-003 deferred trigger re-checking entry-tenant == txn-tenant. The dispatcher's
   BYPASSRLS drain writes no ledger; each row's tenant travels in its own payload.
2. **Idempotency non-bypassable: PASS.** DB-enforced partial-unique `(tenant_id,
   idempotency_key)` + `ON CONFLICT DO NOTHING`. Replay → `applied=False`; 8-way concurrent
   first-write → exactly one debit (probe D); end-to-end re-delivery → one debit.
3. **Balance nets to zero: PASS.** Two equal/opposite legs by construction;
   `Money.from_wire_cents` rejects float/NaN/Inf/negative/over-range; DB deferred trigger
   rejects an unbalanced single-leg even on a direct insert (probe C). Integer cents (BIGINT).
4. **Seam auth: PASS** (with LOW-1, now fixed). HMAC-SHA256 over `"{ts}.{body}"`,
   constant-time compare, ±300 s window; signer and verifier agree on signing string +
   secret (live seam + unit tests). Missing/wrong-secret/tampered/expired → 401, no write.
5. **DLQ — never silently dropped: PASS.** Permanent → `ingest_dead_letter` + 4xx; transient
   (`OSError`/`ConnectionError`/`TimeoutError`/SQLAlchemy `Operational/Interface/Timeout`) →
   503, not dead-lettered; bounded `attempt_count`; unknown-tenant → tenant-NULL privileged
   write, RLS-invisible; partial-unique dedup bounds poison replays. Non-transient
   DLQ-write-failure → full emergency audit log + 422 (no secret), not event loss.
6. **Account resolution: PASS.** `uuid5` over validated `(tenant_id, currency, role)` —
   never from payload; get-or-created `ON CONFLICT DO NOTHING` in the posting txn; FK + RLS
   make a cross-tenant/non-existent account reference impossible. Currency forced to default.
7. **Error handling / fail-open: PASS.** No blind `except` returns 200; every exception
   resolves to 503 (transient) or DLQ+4xx (permanent). `is_transient` walks the
   `__cause__`/`__context__` chain incl `OSError` (ADR-0026). No double-begin. A down DB → 503.
8. **Migration / RLS: PASS.** `ingest_dead_letter` is ENABLE+FORCE RLS with the fail-closed
   NULLIF predicate, SELECT+INSERT-only grant, deny_update/deny_delete USING(false) — UPDATE/
   DELETE denied live (probe G). Composite UNIQUE target + composite FK added; Orchestrator
   status-CHECK widened to admit terminal states. Downgrade reverses in dependency order.
9. **Injection / secrets: PASS.** All SQL parametrized (no identifier/string interpolation
   of user data); migration identifiers from constants, DLQ reason CHECK from a fixed tuple.
   No secret/signature/payload-secret logged; secret fail-loud and never echoed; emergency
   log uses `%r` with no secret. Semgrep ERROR = 0.
10. **Other: PASS.** LOW-1 (fixed), INFO NUL-in-DLQ (fixed), INFO replay-window (neutralized
    by idempotency). No deserialization, SSRF (dispatcher posts only to configured
    `delta_url`), or path-traversal surface introduced.

## Overall verdict

**PASS-WITH-NOTES.** No High or Critical findings — no BLOCK, no human escalation triggered.
Tenant isolation, exactly-once idempotency, balanced posting, seam authentication,
dead-lettering, and append-only/RLS migration hardening all hold under live adversarial
testing. The single LOW (HMAC unicode-timestamp → 503 vs 401) and the INFO NUL-byte DLQ
snippet were **fixed in this pass**; the replay-window INFO is neutralized by event-id
idempotency. This is not a claim that the code is "secure" — it states there are no
High/Critical findings in this pass.
