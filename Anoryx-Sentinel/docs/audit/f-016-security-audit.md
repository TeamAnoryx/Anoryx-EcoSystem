# F-016 Code Scanning on LLM Outputs — Security Audit

- **Feature:** F-016 (post-response code-scanning detector: Semgrep + Bandit over fenced LLM code blocks) — ADR-0019
- **Auditor:** security-auditor (independent red-team, Opus), STEP-10 gate
- **Date:** 2026-06-22
- **Scope:** src/code_scan/ (extractor, scanners, verdict, config, detector) + rulesets/; src/orchestration/registry.py (run_code_scan); src/gateway/routes/chat_completions.py (non-stream run_code_scan + stream _scan_buf accumulation + post-completion call); src/persistence/models/events_audit_log.py + migration 0020; contracts/events.schema.json (code_scan_* variants); contracts/ids.md (code-scan slug).
- **Environment:** semgrep 1.166.0 + bandit installed; Postgres up; PYTHONPATH=src.
- **Verdict:** BLOCK — 1 Critical, 1 High, 1 Med, 4 Low. The scanner-isolation controls (the headline risk surface) are sound; the feature is blocked because it does not run at all in production (Critical) and an unbounded per-block timeout amplification is reachable in the non-streamed hot path (High).

---

## Threat model of the change

A new trust boundary appears: the LLM response text is attacker-influenceable (a malicious prompt can steer the model into emitting output crafted to attack the scanner) and is fed to two subprocess scanners in the gateway hot path. The scanner is therefore the primary attack surface (ADR-0019 sec 2.2). The detector is also the first F-016 surface that writes per-verdict audit rows and reads per-tenant config under RLS. Vectors below map to the ADR sec 5/6/9 controls and sec 12 test matrix.

---

## Vectors tested

### Vector 1 — Scanner resource exhaustion in the hot path — PARTIAL / FAIL (amplification)

- Extractor caps fire BEFORE scanning — PASS. Empirically: per-block cap truncates a ~1.2 MB block to exactly 65,536 bytes (truncated=True); total-bytes cap holds cumulative at 511,992 <= 524,288 (32 blocks skipped); block-count cap holds at 20 blocks (30 skipped). extractor.py is pure, no subprocess.
- Per-subprocess timeout kills — PASS. A 30 s sleeper with the timeout shrunk to 2 s raised ScannerError(timeout) in 2.1 s; a dead proxy did not hang the real semgrep (offline). Missing binary maps to ScannerError(binary_not_found). Output-overflow is checked on the raw length before capping (scanners.py:254).
- Timeout is per-subprocess, NOT total — FAIL (amplification). There is no aggregate scan-time budget (grep for deadline/total-timeout/monotonic in src/code_scan/ returns nothing). The timeout is 30 s on each subprocess.run. With MAX_BLOCKS=20 and Python blocks running both semgrep and bandit (2 subprocesses/block), worst-case synchronous wall-clock on the non-streamed path = 20 x 2 x 30 s = 1200 s (20 min) holding the request/worker open. A prompt steering the model to emit 20 small Python blocks each with a catastrophic-backtracking construct weaponizes this. See HIGH-1.

### Vector 2 — Shell / command / path injection via code content — PASS

- Content is written to a temp file and passed by path as an argv element; subprocess.run(argv, shell=False). A payload containing os.system(touch ...), backticks, dollar-paren, semicolons, double-ampersand and pipe produced no side-effect file on write and none after a real semgrep scan (static only — never executed).
- Filename is server-chosen. _write_block_to_tempdir derives the filename solely from a fixed language-to-extension map (block.py/block.txt/...); a model-supplied language of ../../etc/passwd was ignored and the file landed as block.txt inside the mkdtemp dir (path confirmed under the system temp root). No traversal: the model cannot influence the write path.
- Cleanup on every path. shutil.rmtree(ignore_errors=True) runs in a finally in both run_semgrep and run_bandit; 0 leftover sentinel_scan_* dirs after runs including the error path. No symlink risk (fresh unguessable mkdtemp, server filename).

### Vector 3 — Network egress / phone-home — PASS

- Invocation: --config <local file>, --metrics=off, --disable-version-check. With all proxies pointed at a black-hole port (127.0.0.1:1) and SEMGREP_SEND_METRICS=off, the real semgrep completed in 6.3 s and returned findings — no hang, no failure, so no network dependency. A local --config path does not trigger the registry fetch; --metrics=off forces telemetry off regardless. Bandit ships rules in-package (no fetch). ADR text says --offline; the implemented flags plus a local config are the effective equivalent and were empirically verified hermetic (LOW-3 doc nit only).

### Vector 4 — Fail-safe correctness (error/timeout/oversize/missing-binary/garbage to WARN) — PASS (detector), with a 500-escape caveat

- ScannerError maps to _handle_scanner_error which returns DetectorResult(action=pass) plus a code_scan_error event (verified end-to-end). A generic exception in the scan loop is wrapped into a synthetic ScannerError(type name) on the same WARN path (verified with a forced MemoryError). Never PASS-that-hides (a code_scan_error row is always written), never BLOCK.
- emit() failure inside the error path is swallowed (verified) so it cannot mask the degrade.
- Caveat (MED-1): on the PASS/WARN/BLOCK success paths, await context.emit(...) is not wrapped; if emit raised, inspect() would propagate and _run_hook would wrap it to HookFailSafeError, so the gateway returns 500 — contradicting ADR sec 6 (scanner error to WARN, never a 500). Production HookContext.emit() is contractually no-raise (swallows all DB errors, returns False), so this is not currently exploitable, but the asymmetry is a latent fail-open-to-500 and should be hardened.

### Vector 5 — Streaming honesty — PASS

- run_code_scan on a stream context (_is_stream=True) with a BLOCK-threshold finding returned WITHOUT raising HookBlockedError and emitted exactly one code_scan_warned with verdict=block plus block_suppressed_by_streaming=true (contract-valid: CodeScanWarnedEvent.verdict enum includes block; the field is the variant-only optional). The gateway calls run_code_scan(_scan_buf, ctx) in the generator finally, wrapped in try/except Exception with log.error, so no mid-stream error frame is ever injected.
- _scan_buf is hard-bounded. chat_completions.py:803-810 appends chunk text only while _scan_buf_bytes < _CODE_SCAN_MAX_TOTAL_BYTES (512 KiB), truncating the final chunk to the remaining budget. A long stream cannot exhaust gateway memory via the scan buffer.

### Vector 6 — Tenant scoping / isolation — PASS in principle (mooted by Critical)

- load_code_scan_config reads via PolicyRepository.get_active_policies_for_scope(tenant_id, code_scan) on the caller session — RLS-scoped, no parallel config system, no cross-tenant read path. Absent/disabled/unparseable policy maps to _DISABLED_CONFIG (default-OFF, fail-safe). Events are stamped with the caller real tenant/team/project (never WILDCARD). No cross-tenant surface in the code. Mooted in production by CRIT-1 (config is never actually loaded), but the design is correct once the session wiring is fixed.

### Vector 7 — Audit integrity (no double-emit, hash chain, action mapping, no leakage) — PASS

- Exactly one event per verdict. Non-stream BLOCK raised HookBlockedError and emitted exactly one code_scan_blocked (count==1). The previously-fixed HIGH double-emit is gone: registry.run_code_scan explicitly does NOT re-emit (registry.py:236-244 comment + verified) — the detector inspect() is the sole emitter for every path. No second row, hash chain intact (single append via get_privileged_session in HookContext.emit).
- action_taken matches ACTION_TAKEN_BY_EVENT_TYPE for all four events (verified programmatically): code_scan_passed/warned/error to logged, code_scan_blocked to blocked; all four in VALID_EVENT_TYPES. 4-site discipline intact: model constants, migration 0020 CHECK widen, and contracts/events.schema.json four variants all consistent.
- No code/secret/PII/stack-trace in events or logs. Event payloads carry only verdict/language/finding_count/top_severity/scanner plus a bounded error_class; _handle_scanner_error and log.warning carry only scanner + error_class. ScannerError stores a bounded class string, never the offending code or a traceback.

### Vector 8 — Honest language — PASS

- Ruleset messages, README, and ADR consistently use likely defect / high-coverage detection / risk reduction; the detector docstring states it does NOT guarantee the code is safe or bug-free. No secure / 100% detection / blocks all claims found.

### Migration round-trip — PASS

- 0020 head; down_revision=0019. Live-DB round-trip verified: upgrade head, downgrade 0019, upgrade head — all clean (DROP+ADD CHECK, the established widening pattern).

### Semgrep on changed files (auditor protocol) — PASS

- semgrep --config p/python --config p/security-audit --config p/secrets --severity=ERROR --json over all seven changed source files: 0 ERROR-severity findings.

---

## Findings

### CRIT-1 — Detector is a permanent no-op in production (the entire feature never runs) — BLOCK

File: src/code_scan/detector.py:85 (session = getattr(context, "_db_session", None)), interacting with src/orchestration/context.py (HookContext has NO _db_session field) and src/gateway/routes/chat_completions.py:860-889 (_make_post_context builds the post-response HookContext and sets only _is_stream, never _db_session).

Exploit / impact path: CodeScanDetector.inspect obtains its DB session exclusively via getattr(context, "_db_session", None). The production post-response context is built by _make_post_context, which constructs a fresh HookContext(...) and sets ctx._is_stream and nothing else. HookContext does not declare _db_session, so the attribute is ALWAYS absent in the live gateway. _load_config(session=None, ...) short-circuits to _DISABLED_CONFIG (detector.py:218), so inspect returns DetectorResult(action=pass) with no scan and no event for every request, every tenant, regardless of the code_scan policy.

Verified empirically with a production-shaped context: a response containing os.system(user_input) + eval(payload) (a clean BLOCK under a low/low tenant config) produced action=pass, event=None, and ZERO emitted events; the scanner never ran. The control is a silent fail-open of the whole feature: a tenant who opts in and enables BLOCK believes vulnerable non-streamed code is being rejected; it is not.

Why the test suite (49 green) misses it: unit tests use make_mock_context which manually sets ctx._db_session = session (tests/code_scan/conftest.py:279); the gateway tests inject STUB detectors (_BlockingCodeScanDetector / _SuppressedStreamCodeScanDetector) whose inspect ignores config and returns a hardcoded result. No test exercises the real build_hook_context to _make_post_context to CodeScanDetector.inspect path, so the missing session is never observed.

Fix: stop threading the session through the context. Mirror the established pattern used by every other config-reading detector (injection_detector._resolve_classifier_config takes only context.tenant_context and opens its own session). Have CodeScanDetector open get_tenant_session(tenant_id) itself (RLS-scoped) for the load_code_scan_config read, and change load_code_scan_config to open its own tenant session rather than requiring a caller-supplied _db_session. Add a gateway-level test that drives a REAL HookContext (not a stub detector and not a hand-set _db_session) end-to-end through /v1/chat/completions with an enabled code_scan policy and asserts a code_scan event is actually written and a BLOCK-threshold finding yields 403.

### HIGH-1 — Unbounded total scan wall-clock (per-block timeout amplification) in the non-streamed hot path — BLOCK

File: src/code_scan/scanners.py:57 and :237-244 (per-subprocess timeout only); src/code_scan/detector.py:241-244 (_scan_all_blocks loops over all blocks with no aggregate budget); src/code_scan/extractor.py:56 (MAX_BLOCKS=20).

Exploit / impact path: the timeout bounds a SINGLE subprocess, not the scan. _scan_all_blocks iterates every extracted block; each Python block calls scan_block to run_semgrep AND run_bandit (2 x 30 s). A malicious prompt steers the model into emitting 20 small Python fenced blocks, each containing a construct that drives semgrep/bandit toward their per-process timeout (catastrophic-backtracking-style content, or pathological AST). Each subprocess runs the full 30 s before being killed; total = 20 x 2 x 30 s = 1200 s of synchronous work on the non-streamed path, holding the worker and the client request open. This is reachable precisely because the input is attacker-influenceable (ADR sec 2.2) and the non-streamed scan is synchronous inside run_code_scan (Fork 3). Even non-malicious latency is concerning: a single real small block already took ~6 s of semgrep startup here; 20 blocks x 2 scanners compounds it. ADR sec 5 promises bounds across Vectors 1 and 6 but only the per-subprocess dimension is implemented.

Fix: add an aggregate deadline for the whole scan (a total wall-clock budget enforced across all blocks/scanners using time.monotonic()); once exceeded, stop scanning remaining blocks and degrade to code_scan_warned/code_scan_error (scan budget exceeded), fail-safe WARN, consistent with sec 6. Additionally lower MAX_BLOCKS and/or SCANNER_TIMEOUT_SECONDS, or scan blocks concurrently with a single shared deadline, so the worst-case latency a tenant can inflict on its own non-streamed requests is a few seconds, not 20 minutes.

### MED-1 — emit() failure on the PASS/WARN/BLOCK success paths can escape to 500 (fail-open-to-500) — report

File: src/code_scan/detector.py:150, 165, 182, 196, 209 (await context.emit(event, ...) unguarded on the success paths, unlike _handle_scanner_error:256-259 which guards it).

Path: if emit raised on a verdict path, inspect would propagate to HookFailSafeError to 500. Not currently exploitable because production HookContext.emit is contractually no-raise, but the inconsistency contradicts ADR sec 6 and depends on an external invariant. Fix: wrap the success-path emit calls in the same best-effort try/except used by the error path (the action is already decided; an emit failure must not change it).

### LOW-1 — config.py logs tenant_id while the adjacent comment says it must not — report

File: src/code_scan/config.py:144-145. The log.warning call passes tenant_id=tenant_id even though the next-line comment states tenant_id must never be logged in detail. tenant_id is a UUID (not PII), so impact is low, but the comment/code contradiction should be resolved. Fix: remove the tenant_id field from the log call or correct the comment.

### LOW-2 — No RLIMIT_NPROC (no fork containment) on the scanner subprocess — report

File: src/code_scan/scanners.py:138-149 sets RLIMIT_AS + RLIMIT_CPU only. A fork-bomb in scanned content is not directly possible (static-only, no execution), and semgrep/bandit are trusted binaries, so this is defense-in-depth. Fix (optional): also set RLIMIT_NPROC in the POSIX preexec_fn. On the Windows dev host all rlimits are a documented no-op (timeout is the only backstop), acceptable for dev, but production must be POSIX for the memory/CPU caps to apply (already documented in ADR sec 5).

### LOW-3 — ADR/README say offline; implementation uses metrics-off + disable-version-check — report (doc nit)

File: ADR-0019 sec 5 / rulesets/README.md vs scanners.py:316-317. Verified hermetic empirically, so this is a wording mismatch only. Fix: align the docs to the implemented flags (or add the offline flag for newer semgrep as belt-and-suspenders).

### LOW-4 — Test/impl drift: gateway stub events use uppercase verdict BLOCK — report

File: tests/gateway/test_code_scan_gateway.py:117,148 use verdict=BLOCK (uppercase) while the real detector and contracts/events.schema.json use lowercase block. Harmless (stubs do not validate against the schema) but the stubs no longer mirror the real detector wire shape, weakening their value as regression guards. Fix: lowercase the stub verdicts to match the contract.

---

## What is solid (do not re-litigate)

Extraction caps (byte/block/total) fire before any scanner; subprocess timeout/missing-binary/output-overflow all degrade to a bounded ScannerError to WARN; content is passed by server-chosen path with shell=False and is never executed; temp dirs are cleaned in finally; scanning is hermetic/offline (empirically, with a dead proxy); the streamed path never raises HookBlockedError and _scan_buf is hard-capped at 512 KiB; exactly one event per verdict with correct action_taken mapping and no double-emit; no code/secret/PII/stack-trace in events or logs; migration 0020 is a clean reversible round-trip; honest language throughout.

---

## Verdict

BLOCK. Two escalating findings:
- CRIT-1: the detector never runs in production (session is read off a context attribute the live gateway never sets), so the entire control silently fails open while the test suite is green. This is the most serious class of defect for a security product: a control that looks present but is inert.
- HIGH-1: the timeout is per-subprocess with no aggregate budget, so a malicious prompt can inflate a single non-streamed request to ~20 minutes of synchronous scanner work (amplification DoS), the exact attacker-influenceable hot-path risk ADR sec 2.2/5 set out to bound.

Both must be fixed and covered by a test exercising the REAL gateway -> context -> detector path (not a stub detector, not a hand-injected _db_session) before this PR merges. MED-1 should be hardened in the same pass; the four Lows are reported for cleanup. Re-audit required after remediation.

---

## Remediation & Re-audit (2026-06-22)

> Provenance note: the independent re-audit agent run hit repeated transient API
> stream failures (ConnectionRefused / idle-timeout) and could not persist its
> own summary. The closures below were verified empirically by the implementer
> via the cited tests and code locations; the verdict is offered for the human
> (Affu) STEP-9 gate, who may re-run a fresh independent auditor at discretion.
> Test counts observed green locally (postgres up, PYTHONPATH=src,
> SENTINEL_PROVISION_APP_ROLE=1).

### CRIT-1 — detector prod no-op — **CLOSED**
- `src/code_scan/detector.py:85-101` reads `tenant_id` from
  `context.tenant_context.tenant_id` (the field the live gateway sets); no
  `_db_session` is read from the context.
- `src/code_scan/config.py:125-164` `load_code_scan_config(tenant_id)` opens its
  OWN RLS-scoped `get_tenant_session(tenant_id)` (empty tenant_id → disabled,
  fail-closed; any DB/parse error → disabled, fail-safe).
- Regression guards: `tests/code_scan/test_code_scan_threat_model.py::
  TestCrit1RealHookContextNotNoOp::test_real_hook_context_triggers_scan_not_noop`
  (real `build_hook_context`, no `_db_session`) and
  `tests/gateway/test_code_scan_gateway.py::test_real_detector_blocks_nonstreamed_via_policy`
  (asserts `load_code_scan_config` awaited with the real tenant_id AND a 403
  `policy_blocked`). Both fail if the detector ever no-ops again.
- Evidence: `tests/code_scan` 50 passed; `tests/gateway` 337 passed.

### HIGH-1 — amplification DoS (no aggregate scan budget) — **CLOSED**
- `detector.py:47` `MAX_TOTAL_SCAN_SECONDS = 60`; `:285-296` enforces a
  `time.monotonic()` deadline across the whole block loop in `_scan_all_blocks`,
  raising `ScannerError("budget","scan_budget_exceeded")` (→ fail-safe WARN)
  once exceeded, instead of allowing 20×2×30s ≈ 1200s.
- Regression guard: `...::test_total_budget_exceeded_degrades_to_warn`.
- 60s is well under the worker/request timeout (120–300s). Acceptable for v1;
  may be lowered later if real-world latency warrants.

### MED-1 — unguarded success-path emit — **CLOSED**
- `detector.py` PASS/WARN/BLOCK emits are now wrapped in best-effort
  `try/except` (e.g. :165-168, :183-186, :203-206, :220-223, :236-239), matching
  the error-path guard. An emit failure cannot become a 500, and (action already
  decided before emit) cannot swallow a block.

### LOW-1/2/3/4 — **CLOSED**
- LOW-1: `config.py:155` — tenant_id removed from the warning log.
- LOW-2: `scanners.py:155` — `RLIMIT_NPROC` set in the POSIX `preexec_fn`.
- LOW-3: `rulesets/README.md` — wording aligned to the implemented hermetic
  flags (`--metrics=off --disable-version-check`); egress-free behavior already
  verified.
- LOW-4: `tests/gateway/test_code_scan_gateway.py` — stub verdicts lowercased
  (`"block"`) to mirror the contract enum.

### NEW (found during remediation) — non-stream content-extraction no-op — **CLOSED**
- A second effective no-op, NOT in the original audit, surfaced by the new
  real-path gateway test: the non-stream path passed
  `json.dumps(completion.model_dump())` to `run_code_scan`. `json.dumps` escapes
  newlines, so fenced ``` code blocks (which need real newlines) were never
  extracted → every non-streamed response silently PASSed.
- Fixed in `src/gateway/routes/chat_completions.py:405-422`: `run_code_scan` now
  receives `_code_scan_text` = the raw assistant message content(s) joined with
  real newlines; the outbound-secret hook still scans the full JSON envelope
  (its regexes need no newlines, so its behavior is unchanged). The streamed path
  was always raw text (`_scan_buf` from `_extract_chunk_content`) and is
  unaffected. Empty/multi-choice content handled (`or ""`, join over choices).
- Regression guards: `test_real_detector_blocks_nonstreamed_via_policy` (403 on
  vulnerable code) + `test_real_detector_clean_passes` (200 on clean code).

### Residual / accepted
- No open Critical, High, or Medium findings.
- Standing honest-scope limitations (unchanged, documented in ADR-0019 §4/§13):
  BLOCK applies to non-streamed responses only (streamed → WARN+audit);
  static-only (gVisor deferred); curated offline ruleset (not the full registry
  packs); Python-focused; default-OFF per tenant.
- Defense-in-depth note: enabling code-scan adds one `get_tenant_session` DB
  round-trip per scanned response on the hot path — bounded, the same
  per-request session pattern the rest of the gateway uses; no connection
  exhaustion beyond existing pool limits.

### Revised verdict
**PASS-with-conditions.** Both escalating findings (CRIT-1, HIGH-1), MED-1, all
four Lows, and the additional non-stream no-op are closed with regression tests.
The "conditions" are the standing, documented honest-scope limitations above —
not open defects. Recommended for the human STEP-9 gate; Affu may commission a
fresh independent re-audit if implementer-verified closure is insufficient for
sign-off.
