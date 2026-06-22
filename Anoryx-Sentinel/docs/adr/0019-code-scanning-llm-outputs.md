# ADR-0019 — Code Scanning on LLM Outputs (F-016)

- **Status:** Proposed
- **Date:** 2026-06-22
- **Deciders:** (code-scanning owner / implementer), persistence (migration `0020` widening `ck_eal_event_type`, `events_audit_log` constants), api-architect (contract — `events.schema.json` 4 new variants + `ids.md` `code-scan` principal slug; **no new `openapi.yaml` endpoint, no new error_code**), security-auditor (extended-adversarial gate — the scanner running over attacker-influenceable input in the hot path is the highest-risk surface in F-016), Affu (solo founder & product owner — resolved the STEP-0 forks during planning: **Fork 1 streaming/BLOCK = (a) Hybrid** — real BLOCK on non-streamed, WARN+audit on streamed; **Fork 2 execution = static-only, gVisor DEFERRED**; **Fork 3 sync/async = derives from Fork 1** — sync non-streamed, emit-after-completion streamed; **Fork 4 posture = default-OFF, per-tenant opt-in**; approves this ADR at the STEP-1 gate).
- **Supersedes / amends:** Builds **on top of** and **does not modify** ADR-0007 (F-005 hooks/detectors — F-016 **reuses** `build_default_registry()` + `HookRegistry.run_post_response` and adds a **5th `PostResponseHook`**; existing detector logic unchanged), ADR-0009 (F-008 policy — F-016 **reuses** `PolicyRepository.get_active_policies_for_scope` with a new `policy_type="code_scan"`; engine unchanged), ADR-0005/0006 (tenant isolation / RLS Option α — F-016 reads config and writes events under the caller's existing tenant session; **no new bypass**), ADR-0006 (gateway — F-016 attaches inside the existing `create_chat_completion` handler only; **no new endpoint, no reordered middleware, no changed error envelope**), ADR-0003/0004 (persistence / hash-chain audit — F-016 **appends** 4 new event variants via the existing append-only writer; never mutates rows). Governed by `contracts/openapi.yaml`, `contracts/events.schema.json`, `contracts/ids.md`. **The contracts win over this ADR on any conflict.**
- **Feature:** F-016 — a **post-response code-scanning detector** that extracts fenced code blocks from an LLM response, runs **Semgrep** (`p/python` + `p/security-audit` + `p/secrets`, pinned + offline) and **Bandit** over them in a **bounded, isolated subprocess**, aggregates the findings into a verdict `PASS | WARN | BLOCK`, and **fails safe to WARN** on any scanner error. It is the **first detector whose purpose is to protect the developer from bad code the model emits** rather than to protect the org from the user.

> Honest-language note (per CLAUDE.md): this document says "high-coverage detection," "risk reduction," and "likely defect" — never "100% detection," "blocks all vulnerabilities," "secure code," or "certified." F-016 raises the cost of shipping obviously-vulnerable model output; it does not guarantee the code is safe.

---

## 1. Context and Decision Summary

### 1.1 Context (what exists today)

Every Sentinel detector to date protects the **organization** from the **caller / exfiltration**: PII, prompt-injection, secret-leak, and shadow-AI detectors (ADR-0007/0010) all read request/response **text** and act (mask / block / log). The raw material F-016 builds on:

- **Hook framework** (ADR-0007): `src/orchestration/hooks/base.py` defines `PostResponseHook` (abstract: `detector_slug` property + `async inspect(content, ctx) -> DetectorResult`); `DetectorResult.action: Literal["pass","mask","block"]`. `src/orchestration/registry.py` `build_default_registry()` wires the chain; `run_post_response(text, ctx)` runs the post-upstream hooks and is **fail-safe** (an unexpected detector exception becomes a BLOCK, never a silent pass). `src/orchestration/context.py` builds the per-call `HookContext` carrying `emit(event, detector_slug=...)` and `is_stream`.
- **Response path** (ADR-0006/0007): `src/gateway/routes/chat_completions.py`. **Non-streamed** — `run_post_response(response_text, ctx)` runs **before** the `JSONResponse` is built (so a hook can block or mutate the body); `_error_response(...)` (l.142-166) builds the `Error` envelope. **Streamed (SSE)** — the **200 status and headers are committed before the generator runs** (`StreamingResponse`, l.795); content is flushed per chunk; the post-response hooks run on a **bounded 8 KiB sliding window per chunk** (l.749-770); a mid-stream block emits one `SSEErrorEvent` (`event: error`, standard `Error` envelope, `error_code: policy_blocked`) and closes **without** `data: [DONE]`.
- **F-007 judge** (ADR-0010): `src/orchestration/judge/invoker.py` — the precedent for a post-response analysis step that **degrades safely**: on any timeout/parse/provider error it falls back to a regex score and **always emits `classifier_degraded`** ("Never 'allow'"). F-016 mirrors this degrade-and-audit posture, degrading to **WARN**.
- **Per-tenant policy** (ADR-0009): `src/persistence/repositories/policy_repository.py::get_active_policies_for_scope(tenant_id, policy_type)` — RLS-scoped read returning `Policy` rows whose `policy_payload` (Text JSON) the caller parses. F-016 adds a new `policy_type="code_scan"`. No parallel config system.
- **Events 4-site discipline**: `VALID_EVENT_TYPES` (`src/persistence/models/events_audit_log.py:40`, 42 types) + `ACTION_TAKEN_BY_EVENT_TYPE` (`:99`) + `ck_eal_event_type` CHECK (created in `0005`, widened by DROP+ADD in `0008`/`0015`/…) + `contracts/events.schema.json`. **Migration head = `0019`.**
- **Frozen error envelope** (ADR-0007 §1.1): `Error.error_code` enum is fixed; the **403 `Forbidden` / `policy_blocked`** response explicitly "covers an inspection finding (e.g. detected secret leak or injection) blocks it." All 4 existing detectors block via `policy_blocked`.
- **Optional-extra discipline** (ADR-0012, F-010 slim): heavy scanners live behind a `[project.optional-dependencies]` extra, never in the base image. `semgrep` is currently a `dev` dependency (unpinned); `bandit` is absent.

**What does not exist:** any detector that reasons about the **code** an LLM emits (as opposed to the text); any **subprocess scanner** in the response path; any execution of model-generated content. F-016 adds the first two and **explicitly does not add the third**.

### 1.2 Decision (one paragraph)

We add a **`src/code_scan/` package** providing a **5th `PostResponseHook`** (`CodeScanDetector`, `detector_slug="code-scan"`) that: (1) **extracts** fenced markdown code blocks with language tags, **bounded** by per-block, block-count, and total-byte caps (DoS guard); (2) runs **Semgrep** (`--offline`, vendored/pinned rulesets `p/python` + `p/security-audit` + `p/secrets`) and **Bandit** over each block in a **subprocess that is isolated and bounded**: the block is written to an unguessable temp file in a fresh per-scan dir and passed **by path** (never shell-interpolated), with a hard **timeout**, **output-size cap**, **memory/CPU cap** (POSIX `resource` limits; best-effort on Windows dev), **no network**, and guaranteed cleanup; (3) aggregates normalized findings (`{rule_id, severity, line}`) into a verdict **`PASS | WARN | BLOCK`** by **per-tenant severity thresholds**, **failing safe to WARN** on any scanner error/timeout/crash (emitting a distinct `code_scan_error` event); (4) acts per **Fork 1 (a)** — on a **non-streamed** response the scan runs **synchronously inside `run_post_response`** and a `BLOCK` verdict **rejects the body** with the existing **`policy_blocked` (403)** envelope; on a **streamed** response the full text is **accumulated up to the byte cap** and scanned **once after the stream completes**, yielding **WARN + audit only** because the bytes are already on the wire (no honest block is physically possible); (5) is **default-OFF, per-tenant opt-in** via a new F-008 `code_scan` policy carrying the enable flag, severity→verdict thresholds, and per-verdict action; (6) emits **4 new event variants** (`code_scan_passed` / `code_scan_warned` / `code_scan_blocked` / `code_scan_error`) added **4-site** with a **reversible migration `0020`**, attributed honestly to the caller's tenant + a new reserved **`code-scan`** principal slug. **Static analysis only** — the extracted code is **never executed** (gVisor deferred to v2). **No `/v1` auth, no F-003/F-003b/F-004/F-005/F-006/F-008 engine logic, no error envelope, and no endpoint is modified** — F-016 is purely additive: a detector + scanner wiring + config field + events.

### 1.3 What changes vs. what is frozen

| Frozen (MUST NOT change) | Changes (F-016) |
|---|---|
| ADR-0007 hook framework, existing 4 detectors | **Reused unchanged.** Add a 5th `PostResponseHook`, registered in `build_default_registry`. |
| ADR-0006 middleware order, `/v1` endpoints, **`Error.error_code` enum** | **Unchanged.** Non-streamed BLOCK reuses the existing **`policy_blocked` (403)** envelope; **no new error_code**, no new endpoint. |
| ADR-0009 policy engine | **Reused.** New `policy_type="code_scan"` row; no new config system. |
| ADR-0005/0006 RLS role/GUC model | **Reused.** Config read + event write under the caller's tenant session. No new bypass. |
| ADR-0003/0004 append-only hash-chained audit | **Appended to.** 4 new event variants via the existing writer; rows never mutated. |
| F-005 secret detector (text DLP) | **Unchanged + boundary stated (§7).** F-016 does **not** redact. |

---

## 2. Decision: the threat model is inverted (frame F-016 correctly)

Most of Sentinel protects the **org** from the **user** (exfiltration, injection, shadow-AI). **F-016 protects the developer from the model.** The asset being defended is the developer who will copy-paste the model's code; the adversary is **bad code in the response** (SQLi, command injection, hardcoded secrets, weak crypto, unsafe deserialization). This reframing drives three consequences recorded here so no one re-derives the wrong posture:

1. A finding is a **quality/safety signal about the output**, not evidence of an attacking caller. Default action is therefore **WARN (observe), not BLOCK**.
2. The **scanner itself is the primary attack surface** (§5), because the input it parses is **attacker-influenceable**: a malicious prompt can steer the model into emitting output crafted to attack Semgrep/Bandit (ReDoS, parser DoS, resource exhaustion) in the hot path.
3. F-016 makes **no claim** that passing code is safe. "high-coverage detection" of *known* patterns, "risk reduction," "likely defect" — never "secure."

---

## 3. Decision: the four forks (Affu-resolved at STEP 0)

**Fork 1 — streaming / BLOCK action model (resolved (a) Hybrid; this was the no-default gate).**
The physical constraint: F-006 commits the 200 + streamed bytes to the client **before** any post-response hook can see a complete code block, and Semgrep/Bandit are **whole-file subprocess scanners** that cannot run per-8 KiB-chunk. Therefore:
- **Non-streamed** (`stream=false`): the full body exists before `JSONResponse`; the scan runs **synchronously** and a `BLOCK` verdict **really rejects** the response. ✅ honest BLOCK.
- **Streamed** (`stream=true`): scanning can only happen **after** the bytes are flushed; the verdict is **WARN + audit**, never BLOCK. The would-block case is recorded honestly (§4).
- *Rejected alternatives:* **(b) buffer all responses** — restores BLOCK everywhere but **destroys token-streaming UX** and adds full-response latency to every request; rejected because the latency/UX cost is paid by every tenant to cover a minority verdict on a minority of responses. **(c) scan non-streamed only** — simplest, but leaves streamed code output **completely uncovered**; rejected as too weak.

**Fork 2 — execution model (resolved: static only, gVisor DEFERRED).** Semgrep/Bandit parse the code; the code is **never run**. Dynamic/gVisor sandbox execution of model-generated code is a large new attack surface with no current demand and is deferred to a future version. R1.

**Fork 3 — sync vs async (resolved: derives from Fork 1).** Non-streamed → **synchronous** in `run_post_response` (required to enable BLOCK). Streamed → **emit-only after stream completion** (cannot block; runs once on accumulated text). Not an independent choice.

**Fork 4 — default posture (resolved: default-OFF, per-tenant opt-in).** A tenant must enable `code_scan` in policy. Rationale: the scanner adds **subprocess latency** to the response path and is the **primary attack surface**; tenants who do not opt in pay neither cost. Mirrors F-009's team-opt-in precedent. When enabled, the default per-verdict action is **WARN audit-only**; BLOCK is itself opt-in per tenant.

---

## 4. Decision: streaming-BLOCK honesty (R7 — the load-bearing limitation)

> **Code-scan BLOCK applies only to non-streamed responses.** For streamed responses the verdict is **WARN + audit** — the response bytes are committed to the client before the complete code block exists to scan, so **no honest block is possible**. This is a fundamental property of streaming, not an implementation gap.

Enforcement of this honesty:
- The API and any UI surface a **BLOCK guarantee only for non-streamed responses**. Nowhere is a streamed-BLOCK guarantee claimed.
- When a streamed response produces findings that *would* cross the BLOCK threshold, F-016 emits **`code_scan_warned`** (action `logged`) with the event detail field **`block_suppressed_by_streaming: true`** — giving operators honest observability ("this would have blocked on a non-streamed response") **without** a false block. No 5th event type is invented for this.
- The streamed accumulation is **bounded by the same total-byte cap** as the extractor (memory-exhaustion guard, consistent with ADR-0007 §5's rejection of unbounded accumulation). If the response exceeds the cap, scanning is skipped and a `code_scan_warned`/`code_scan_error` event records "response too large to scan in full."

---

## 5. Decision: scanner isolation + bounds (R2/R3 — the primary security control)

The scanner reads **attacker-influenceable** text in the hot path. Every dimension is bounded:

| Bound | Control |
|---|---|
| **Extraction** | Max blocks/response, max bytes/block, max total bytes/response — caps applied **before** any scanner is invoked. Oversized input is truncated/skipped, not scanned. (Vector 2) |
| **Timeout** | Each scanner subprocess has a hard wall-clock timeout (`subprocess` `timeout=`, killed on expiry → WARN). Defends ReDoS / catastrophic backtracking. (Vectors 1, 6) |
| **Memory / CPU** | POSIX `resource.setrlimit` (RLIMIT_AS / RLIMIT_CPU) in a `preexec_fn` on the child; best-effort/no-op on Windows dev (documented), with the timeout as the cross-platform backstop. |
| **Output size** | Scanner stdout/stderr capped; oversized output is truncated and treated as an error → WARN. |
| **No network** | Semgrep `--offline` against **vendored/pinned local rulesets**; no live rule fetch, no telemetry. Verified empirically (Vector 3). |
| **No shell** | The block is written to a temp **file**; the scanner is invoked with an **argv list** (`shell=False`) and the **path** is passed as an argument. Code content is **never** interpolated into a shell string. (Vector 4) |
| **Temp isolation** | Each scan uses a fresh `mkdtemp` dir with an unguessable name; the block filename is **server-chosen** (never derived from a model-supplied fenced "filename"); the dir is removed in a `finally`. No path traversal: the model cannot influence the write path. (Vector 4) |
| **No execution** | Static analysis only; the temp file is read by the scanner, never executed. (R1) |

---

## 6. Decision: fail-safe = WARN (R4)

Any scanner error, timeout, crash, non-zero-with-no-parseable-output, or oversized output → verdict **WARN** (not PASS, not BLOCK):
- **Not PASS** — a silent pass would hide a scan that never ran (fail-open).
- **Not BLOCK** — a crafted output that reliably crashes the scanner would otherwise let an attacker **DoS every legitimate non-streamed response** (fail-closed weaponized).
- The error is itself audited as **`code_scan_error`** (distinct from `code_scan_warned`), recording the scanner name + a bounded error class — **never** the scanner stack trace and **never** the offending code. This degrade-and-audit posture mirrors the F-007 judge (ADR-0010 `classifier_degraded`). Empirically tested (Vectors 5, 6).

Note the asymmetry vs ADR-0007: the F-005 hook chain fail-safes to **BLOCK** because it protects the org and a missed inspection is an org risk. F-016 fail-safes to **WARN** because it protects the developer and a fail-closed BLOCK on untrusted input is itself the DoS vector. Both are "never silently pass." This difference is intentional and recorded.

---

## 7. Decision: boundary vs the F-005 secret detector (no duplication)

Semgrep `p/secrets` overlaps in spirit with the F-005 secret detector. The boundary:

| | F-005 secret detector | F-016 Semgrep `p/secrets` |
|---|---|---|
| Purpose | **DLP** — stop a leaked credential reaching the client | **Code quality** — flag a hardcoded secret *pattern* in emitted source |
| Operates on | the whole response **text** | only **extracted fenced code blocks** |
| Action | **masks** → `[REDACTED:<type>]` | contributes to the **verdict**; **does not redact** |
| Event | `secret_leaked` | `code_scan_*` (finding folded into the verdict) |

**Chain order makes them non-conflicting:** the F-005 outbound secret hook runs and **masks first**; by the time `CodeScanDetector` scans the (already-masked) block, literal secrets are typically gone, so `p/secrets` mostly fires on **structural** hardcoded-credential patterns rather than re-flagging a value F-005 already redacted. F-016 **never redacts** and never emits `secret_leaked`. Stated here so the two are not merged or set against each other.

---

## 8. Decision: verdict model, action mapping, and error reuse

Verdict aggregation maps the worst finding severity against the tenant's thresholds to `PASS | WARN | BLOCK`, then maps onto the framework's `DetectorResult.action`:

| Verdict | `DetectorResult.action` | Event | Response effect |
|---|---|---|---|
| PASS | `"pass"` | `code_scan_passed` | none |
| WARN | `"pass"` | `code_scan_warned` | none (audit only) |
| BLOCK (non-streamed) | `"block"` | `code_scan_blocked` | reject body, **`policy_blocked` (403)** |
| would-BLOCK (streamed) | `"pass"` | `code_scan_warned` + `block_suppressed_by_streaming:true` | none (bytes already sent) |
| scanner error/timeout | `"pass"` | `code_scan_error` | none (fail-safe WARN) |

**Error-code decision (refines the plan): no new error_code.** ADR-0007 froze the `Error.error_code` enum and the **403 `policy_blocked`** response already "covers an inspection finding blocks it"; all 4 existing detectors block through it. The F-016 non-streamed BLOCK **reuses `policy_blocked`** for consistency and to honor CLAUDE.md's "changes no error envelope." Precise attribution lives in the **audit event** (`code_scan_blocked`), not in a new client-facing code. (The F-015 `not_found` addition was for a *new endpoint surface*, not a detector block — not applicable here.)

---

## 9. Decision: per-tenant config (reuse F-008, no parallel system)

New `policy_type="code_scan"`, read via `get_active_policies_for_scope(tenant_id, "code_scan")` (RLS-scoped). `policy_payload` JSON shape:

```json
{
  "enabled": true,
  "thresholds": { "warn": "low", "block": "high" },
  "actions":    { "warn": "audit", "block": "reject" }
}
```

- **Absent policy ⇒ disabled** (default-OFF, Fork 4). The detector returns `PASS`/no-op cheaply without invoking a scanner.
- `thresholds` map severity (`low|medium|high|critical`) to the verdict boundary; `block: "high"` means findings ≥ high yield BLOCK.
- `actions.block: "reject"` enables BLOCK on non-streamed; `actions.block: "audit"` downgrades even a BLOCK-threshold verdict to WARN (audit-only) for tenants that want signal without rejection. (Vector 9)
- Config is tenant-scoped under RLS; one tenant's `code_scan` policy is never visible to another. (Vector 12)

---

## 10. Decision: events (4-site) + reversible migration 0020

Four new variants, added at all four sites in lockstep:

| Site | Change |
|---|---|
| `VALID_EVENT_TYPES` (`events_audit_log.py:40`) | add `code_scan_passed`, `code_scan_warned`, `code_scan_blocked`, `code_scan_error` |
| `ACTION_TAKEN_BY_EVENT_TYPE` (`:99`) | `code_scan_blocked → {"blocked"}`; the other three → `{"logged"}` |
| `contracts/events.schema.json` (**api-architect only**) | add the 4 event objects (common envelope + bounded F-016 fields: `verdict`, `language`, `finding_count`, `top_severity`, `scanner`, optional `block_suppressed_by_streaming`; **never** the code, **never** a scanner stack trace) |
| `ck_eal_event_type` (migration **`0020`**, down_revision `"0019"`) | DROP + ADD the CHECK to include the 4 new types; downgrade restores the prior constraint (reversible round-trip, Vector via STEP 10) |

New reserved attribution slug **`code-scan`** in `contracts/ids.md` (the detector's `detector_slug` / event `agent_id`), matching the `^[a-z0-9]+(-[a-z0-9]+)*$` pattern. Events are attributed to the caller's tenant + the `code-scan` principal.

---

## 11. Module layout (`Anoryx-Sentinel/src/code_scan/`)

| File | Responsibility |
|---|---|
| `extractor.py` | Fenced-block parse + language tag; per-block / block-count / total-byte caps; non-code → empty cheaply. (Vector 2) |
| `scanners.py` | Bounded/isolated Semgrep (`--offline`, pinned rulesets) + Bandit subprocess wrappers; temp-file-by-path; timeout/mem/output caps; no network/shell; cleanup. Returns normalized findings. (Vectors 1,3,4) |
| `verdict.py` | Findings → `PASS\|WARN\|BLOCK` by tenant thresholds; fail-safe WARN. (Vectors 5,6,7,8) |
| `config.py` | Load `code_scan` policy via `get_active_policies_for_scope`; default-OFF. (Vectors 9,12) |
| `detector.py` | `CodeScanDetector(PostResponseHook)`, `detector_slug="code-scan"`; config-gate → extract → scan → verdict → `DetectorResult` + `ctx.emit(...)`. Registered in `build_default_registry`. Non-streamed: inline in `run_post_response` (BLOCK-capable). Streamed: invoked once after stream completion on bounded-accumulated text (WARN only). (Vectors 10,11) |
| `rulesets/` | Vendored/pinned Semgrep rule packs (`p/python`, `p/security-audit`, `p/secrets`) for `--offline`. |

Dependency: new `pyproject.toml` extra **`code-scan`** pinning `semgrep` + `bandit`, added to the `all` aggregate (F-010 slim: not in the base image).

---

## 12. Adversarial threat model → test paths (`tests/code_scan/`)

| # | Test | Asserts |
|---|---|---|
| 1 | `test_redos_payload_times_out_to_warn` | catastrophic-backtracking payload hits timeout → WARN, no hang |
| 2 | `test_oversized_code_block_bounded` | huge block capped (byte/block limit), no memory exhaustion |
| 3 | `test_scanner_no_network` | Semgrep runs offline; no rule fetch / egress |
| 4 | `test_no_shell_injection_via_code_content` | shell metachars / path-traversal in content passed by path, not interpreted |
| 5 | `test_scanner_crash_yields_warn_audited` | forced scanner error → WARN + `code_scan_error` |
| 6 | `test_scanner_timeout_yields_warn` | timeout → WARN |
| 7 | `test_known_vulnerable_code_warns_or_blocks` | `os.system` / SQL string-concat → finding → WARN/BLOCK per threshold |
| 8 | `test_clean_code_passes` | clean code → PASS |
| 9 | `test_verdict_threshold_per_tenant` | severity→verdict respects per-tenant config |
| 10 | `test_block_applies_to_nonstreamed_response` | BLOCK rejects/replaces a non-streamed response (`policy_blocked` 403) |
| 11 | `test_streamed_response_handled_per_fork1` | streamed → WARN+audit, no false BLOCK; would-block sets `block_suppressed_by_streaming` |
| 12 | `test_scan_results_tenant_scoped` | config/results/events tenant-scoped; no cross-tenant visibility |

DB-test note (F-011 lesson): tests touching the events table provision their own DB gate — `code_scan` sorts before `compliance`/`persistence` alphabetically and cannot rely on their fixtures.

---

## 13. Honest scope (explicit deferrals)

- **Static analysis only.** gVisor / dynamic execution of model-generated code is **DEFERRED**. The code is never run. (Fork 2 / R1)
- **BLOCK is bounded to non-streamed responses.** Streamed = WARN + audit; this is a fundamental streaming limit, stated in the contract, not a TODO. (Fork 1 / R7)
- **Scanners are pinned + offline.** No live rule updates; rule freshness is a deliberate trade for hermeticity and DoS safety. Updating rules is a dependency bump, not a runtime fetch.
- **Python-focused.** Semgrep `p/python` + Bandit give the strongest coverage for Python; other languages get Semgrep's general `p/security-audit` rules only, with lower recall. Stated as a known limitation, not hidden.
- **No new detection logic.** F-016 wires Semgrep/Bandit and aggregates their output; it invents no bespoke vulnerability heuristics.
- **Default-OFF.** A tenant sees nothing until it opts in. (Fork 4)

---

## 14. Rollback

- **Migration:** `alembic downgrade -1` restores the pre-0020 `ck_eal_event_type` constraint (the new event rows would then violate the CHECK, so downgrade is a clean-room rollback before any `code_scan_*` row is written, or after pruning them — same posture as prior event-widening migrations).
- **Feature:** the detector is gated by per-tenant `code_scan` policy and default-OFF; disabling it for all tenants (or not registering it in `build_default_registry`) fully neutralizes F-016 with no schema change.
- **Dependency:** the `code-scan` extra is optional; an image built without it simply never loads the scanners (the detector treats a missing scanner binary as a scanner error → WARN, never a crash).

---

## 15. Hard-rule compliance

R1 no execution (§3 Fork 2) · R2 bounded scanner (§5) · R3 path-not-shell (§5) · R4 fail-safe WARN, audited (§6) · R5 tenant-scoped under RLS (§9, Vector 12) · R6 reuse F-005 hooks + F-008 config (§1.2, §9) · R7 streamed-BLOCK honesty documented (§4) · R8 no engine/auth/envelope edits beyond detector hook + config field + events (§1.3, §8) · R9 no regressions; scanners behind optional extra (§11).
