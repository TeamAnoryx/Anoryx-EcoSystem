# F-011 Compliance Evidence Engine - Independent Security Audit

- Auditor role: Independent Security Auditor (adversarial; did not author this code).
- Date: 2026-06-20
- State: main + uncommitted F-011 surface; live Postgres at migration 0012 head.
- Authoritative design: docs/adr/0013-compliance-evidence-engine.md
- Method: static read of the full F-011 surface; threat-model; empirical exploitation
  against the LIVE Postgres (seed real rows, run real queries); full suite; semgrep.

## Verdict

PASS-WITH-CONDITIONS.  Critical: 0 | High: 0 | Medium: 1 | Low: 2 | Info: 3.

No High or Critical findings in this pass, so this does NOT auto-BLOCK/escalate. M-1 is a
real, live-DB-confirmed evidence-integrity defect (silent under-count + truncated chain
segment) touching the R8 honesty guarantee; fix it (or get explicit Affu sign-off) before
F-011 evidence is shown to any real auditor.

## Scope

- src/compliance/{constants,errors,mapping,evidence,gap_analysis,pack,cli}.py
- src/compliance/frameworks/{soc2,iso27001}.yaml + mapping.schema.json
- src/gateway/routes/compliance.py + mount in src/gateway/main.py (L70, L238-241)
- src/persistence/models/events_audit_log.py + migration 0012_compliance_event_variants.py
- src/policy/cli.py registration + src/compliance/cli.py
- contracts/events.schema.json (2 variants) + contracts/openapi.yaml (2 paths)
- tests/compliance/* + tests/gateway/test_compliance_endpoints.py
- Trust primitives: persistence/database.py, gateway/middleware/{auth,tenant_context}.py,
  persistence/repositories/audit_log_repository.py, policy/crypto.py

## Per-attack findings

### 1. Cross-tenant evidence leakage (top threat) - NO BREAK
- read_chain_segment (evidence.py:296) and generate_evidence (evidence.py:223) use
  get_tenant_session(tenant_id) ONLY; neither touches get_privileged_session. Confirmed by
  read and by vector 10 (asserts current_user equals sentinel_app and GUC equals tenant_id).
- get_tenant_session (database.py:250) is fail-closed: empty/whitespace tenant_id raises
  TenantContextRequiredError before any connection (database.py:286). GUC is set via a BOUND
  parameter in set_config(..., is_local=true) (database.py:302-305) - no GUC injection. RLS
  collapses empty-string to NULL to zero rows (fail-closed); a mid-tx clear narrows, not widens.
- Tenant is server-resolved from the verified Bearer key (tenant_context.py:163). The route
  never reads tenant_id from query/body/header. GET has no tenant_id param. POST body model
  ExportRequest is closed (extra=forbid, compliance.py:84) so an injected tenant_id returns 422
  (compliance.py:336-343). sentinel_app is NOBYPASSRLS. The privileged session is used only for
  the auth fingerprint lookup and the best-effort meta-audit append.

### 2. Evidence-log mutation (R1) - NO BREAK
- Vector 1 is positive proof: a before_cursor_execute listener captures every SQL statement and
  asserts none are INSERT/UPDATE/DELETE on events_audit_log. All three read helpers issue only
  SELECT. AuditLogRepository has no update/delete. The two meta-audit appends
  (_emit_compliance_event, compliance.py:152) are SEPARATE from the read path, run after
  generation, and are best-effort (exceptions swallowed+logged, never fail the request).

### 3. Pack forgery / replay - NO BREAK (self-contained-pack property documented)
- Layer B signs canonical_claims(record) - the FULL record incl. the embedded chain block
  (pack.py:264,393). Altering any embedded hash breaks the ES256 signature (vectors 2+6 pass).
  crypto.verify_compact_jws pins alg ES256 BEFORE using the key (crypto.py:222); raw sig length
  enforced at exactly 64 bytes (crypto.py:100).
- HONEST KNOWN PROPERTY (in scope, not a defect): the verifying pubkey is bundled in the ZIP;
  an attacker who fully rebuilds and re-signs with their own key + bundles their own pubkey.pem
  defeats a verifier who trusts the in-ZIP key. Trust anchor is OUT-OF-BAND key dist (INFO-1).

### 4. Disclosure in packs (R6) - NO BREAK
- read_chain_segment SELECTs ONLY (sequence_number, prev_hash, row_hash) (evidence.py:284-288);
  _query_chain_tip selects (sequence_number, row_hash) only. The pack record is metadata + opaque
  hashes + statuses + counts + disclaimer; no keys/prompts/content. Vectors 11/12 scan canonical
  bytes AND in-ZIP evidence.json. PackSigningKeyError yields a generic 500, no key path leaked
  (compliance.py:359-362).

### 5. Compliance over-claiming (R8) - NO BREAK
- YAML honesty: soc2 CC6.7/A1.2 and iso A.5.30 have empty sentinel_controls so not_covered;
  CC9.2/A.8.28 use explicit status_override not_applicable. gap_analysis forces not_covered/
  not_applicable to count 0 before classification; readiness = passed/(total-NA); applicable 0
  yields 0.0 (never 1.0). Score recomputable (vector 15). DISCLAIMER on every artifact.
  audit-ready, never compliant.

### 6. Auth (R5) - NO BREAK
- /v1/compliance/* is NOT in _AUTH_EXEMPT_PATHS (auth.py:70, tenant_context.py:53); exempt set is
  operational probes + metrics_path only. AuthMiddleware is innermost (main.py:205); unauth yields
  401 before the handler (auth.py:127-148). resolve_tenant_context needs virtual_key_row (set only
  by AuthMiddleware). Vector 13 (unauth 401) passes.

### 7. 4-site + migration - CONSISTENT; reversible
- Both variants consistent across VALID_EVENT_TYPES (events_audit_log.py:71-72),
  ACTION_TAKEN_BY_EVENT_TYPE=logged (114-115), events.schema.json (L1097/L1141, oneOf L33-34),
  ck_eal_event_type (migration 0012 _WITH_F011). 0012 down_revision 0011; upgrade widens,
  downgrade narrows to _THROUGH_F009 (loss-free; no new columns). Emitted events satisfy their own
  schema; pack_content_hash matches a 64-hex pattern; framework_version matches its pattern.

### 8. Injection / DoS - NO BREAK (one O(n) characteristic, documented)
- SQL: SQLAlchemy expression language + bound params; event_type filter is in_(frozenset);
  framework allowlisted. YAML: yaml.safe_load + JSON-Schema + unknown-key rejection +
  evidence_event_types must be in VALID_EVENT_TYPES. ZIP: fixed 4-file set, fixed names, no
  caller-controlled entry names so no zip-bomb/traversal; filename from allowlisted framework.
  INFO-2: no max-window cap (O(events in window)), documented honest v1 characteristic.

### 9. 16-vector validation - RUN, NON-VACUOUS, GREEN
- 108 passed (tests/compliance + tests/gateway/test_compliance_endpoints.py). Vectors assert real
  properties (SQL capture; current_user/GUC; committed-row RLS scoping; window bounding;
  forged-JWS verify-fail; PII/secret scans; not_covered surfacing; readiness recompute).

## STEP-7 HIGH-4 re-check (string-comparison window filter) - RE-OPENED as M-1

HIGH-4 was rejected because event_timestamp is String(64) (confirmed: events_audit_log.py:133-135;
migration 0005:67) so isoformat() returning a string IS required. That part is correct. The
rejection stopped one step short: the filter does a LEXICOGRAPHIC string comparison
(evidence.py:141-142,163,290-291) and the two sides use DIFFERENT RFC3339 serializations.

- PRODUCTION rows write the Z form: now(UTC).isoformat().replace(+00:00 with Z) giving
  2026-01-15T12:00:00Z (audit.py:128,186,325; orchestration/context.py:109;
  policy/audit_events.py:78; shadow_ai_detector.py:107,150).
- The compliance bound writes the OFFSET form: t1.isoformat() giving 2026-01-15T12:00:00+00:00.

At string index 19 the stored row has Z (ASCII 90) while the bound has + (43) or . (46). Z sorts
AFTER + and ., so a same-second/sub-second boundary mis-orders a real row vs the bound. The threat
model missed it because the seeders write ts.isoformat() (offset form), which the live gateway
never emits (L-2).

## Findings

### M-1 (Medium) - Lexicographic timestamp window filter drops production-format rows
- File: src/compliance/evidence.py:141-142, 163, 290-291
- Issue: String(64) event_timestamp compared lexicographically against t0/t1.isoformat().
  Production rows are the Z form; the bound is the +00:00 / .ffffff+00:00 form. Z sorts after + and
  . at index 19, so in-window rows can be silently excluded and boundary rows mis-bounded.
- Impact (LIVE-DB CONFIRMED):
  1. Under-count: 2 events at 12:00:00Z in window [11:00, 12:00:00.001+00:00] are counted as 1;
     the Z-format (production) row is dropped.
  2. Truncated chain segment: 3 contiguous prod rows :00Z/:01Z/:02Z with t1=12:00:02.5 yield
     read_chain_segment returning 2 of 3 links.
  3. The truncated segment STILL passes verify_chain_links_offline (True) because non-contiguous
     gaps are not asserted, so the auditor gets an INCOMPLETE pack that looks internally valid.
     readiness and passed/gap depend on these counts -> honesty/R8 concern.
  4. Remotely triggerable, no special privilege: _parse_datetime accepts fractional-second t1
     (e.g. 12:00:02.5Z) and normalizes to the offset bound. A tenant calling
     GET /v1/compliance/evidence with t1 set to now hits it.
- Fix: cast the column in SQL to TIMESTAMPTZ and compare against datetime objects, mirroring
  policy/enforcement.py:200 (cast(EventsAuditLog.event_timestamp, DateTime(timezone=True))).
  Add a regression seeding a Z-format row asserting it is counted at a sub-second boundary.

### L-1 (Low) - Operator CLI accepts an arbitrary --tenant
- File: src/compliance/cli.py:159-230. RLS still scopes the read (sentinel_app NOBYPASSRLS), but
  the CLI lets a host operator generate evidence for any named tenant. Requires shell +
  APP_DATABASE_URL (already privileged); not HTTP-reachable; documented operator/dev path. Note
  for the F-012 operator/cross-tenant threat model.

### L-2 (Low) - Threat-model seeders use a non-production timestamp serialization
- Files: tests/compliance/test_evidence_threat_model.py:71; test_pack_export_threat_model.py:709
  (ts.isoformat(), offset form). This is why M-1 slipped a green suite. Fix: seed in the Z form +
  add a sub-second-boundary regression (fails today, passes after M-1).

### INFO-1 - Self-contained pack trust anchor is out-of-band key distribution
- The bundled pubkey.pem is convenience; authenticity needs the genuine out-of-band public key.
  Add one explicit sentence to the manifest/disclaimer.

### INFO-2 - No maximum-window cap on evidence/export (O(events in window)).
- Consider a max-window guard + endpoint rate limiting before GA.

### INFO-3 - pack_content_hash / framework_version are not mapped to audit columns
- They ride the bus event only (per ADR D7) but DO participate in compute_row_hash
  (row_data=dict(event)). Consistent with design; request_id is the forensic join key.

## Tooling
- Test suite: 108 passed vs live Postgres, SENTINEL_PROVISION_APP_ROLE=1.
- Semgrep: scan --config p/python,p/security-audit,p/secrets --severity ERROR over F-011 src
  yields 0 ERROR-severity findings, 0 scan errors.

## Final verdict: PASS-WITH-CONDITIONS
1. Fix M-1 (TIMESTAMPTZ-cast the window filter) OR get explicit Affu sign-off to ship with M-1
   tracked, BEFORE F-011 evidence is shown to any real auditor.
2. Add the L-2 production-format-row regression alongside the M-1 fix.
3. INFO-1/2/3 are documentation/hardening nits for GA.

---

## Addendum — M-1 resolved (post-audit fix, same branch)

**M-1 (Medium, evidence integrity) — FIXED.** The window filter in
`src/compliance/evidence.py` no longer does a lexicographic string compare on the
`String(64)` `event_timestamp`. All three query sites (event-count, chain-tip,
`read_chain_segment`) now compare on a timestamptz CAST
(`cast(EventsAuditLog.event_timestamp, DateTime(timezone=True))`, module-level
`_EVENT_TS`), mirroring the `src/policy/enforcement.py` precedent — a true instant
comparison, independent of 'Z' vs '+00:00' serialization. Production audit writers
always emit the 'Z' form; those rows are now bucketed correctly.

**L-2 (Low, test gap) — FIXED.** The threat-model seeder `_make_event_data` now
writes the production 'Z' form (`ts.isoformat().replace("+00:00","Z")`) instead of
the '+00:00' form, so the window tests exercise the exact serialization the live
gateway emits. A dedicated regression test,
`test_window_counts_production_z_form_at_fractional_boundary`, seeds a 'Z'-form row
at instant T and asserts it is counted by a window ending at T+1ms — the precise
scenario that previously undercounted.

**Non-vacuity proof:** pre-fix, `'…T12:00:00Z' < '…T12:00:00.001000+00:00'` is
`False` (char@19: `Z`=0x5A vs `.`=0x2E), so the 'Z' row was excluded at the
boundary; the cast makes the comparison correct. Verified: 8/8 evidence vectors
(incl. the new regression), 109/109 compliance + endpoint tests, ruff/black clean.

**Revised conditions status:** condition 1 (fix M-1) — DONE; condition 2 (add the
production-'Z' regression test) — DONE. INFO-1/2/3 remain GA-time doc/hardening
nits. Net: 0 Critical / 0 High / 0 open Medium.

---

## Addendum — Test isolation strategy (STEP 9)

F-011's cross-tenant RLS isolation (vectors 7, 8, and the cross-tenant endpoint test)
is verified **empirically, not structurally**: each commits real tenant-A and tenant-B
rows across a second real RLS connection and asserts tenant A's evidence returns zero
tenant-B rows. This is deliberate — cross-tenant evidence leakage is F-011's
highest-severity threat (R2), so the proof must exercise the live RLS boundary, not a
mocked or single-session approximation. These three tests use a **scoped, non-autouse**
`truncate_audit_log_after` fixture that `TRUNCATE`s `events_audit_log` in teardown
(`TRUNCATE` bypasses the append-only `BEFORE DELETE` trigger, which blocks row-level
`DELETE`), restoring the empty-table precondition for the persistence genesis chain test
under any ordering. All other F-011 DB tests use a no-commit savepoint pattern (zero
table pollution). Verified: full repo suite 888 passed; post-suite `events_audit_log`
row count = 0; F-011 coverage 96% (every module ≥89%); semgrep 0; repo-wide ruff/black
clean. See ADR-0013 §10.1.
