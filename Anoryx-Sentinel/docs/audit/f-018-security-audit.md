# F-018 Shadow-AI Detection - Independent Security Audit (arms-length red-team)

- Feature: F-018 - read-time detection/attribution layer over F-007 shadow_ai_detected_outbound egress events. Classifies into review CANDIDATES with a confidence band, attributes to team/project, emits shadow_ai_candidate_detected, surfaces in the admin governance panel. DETECT-ONLY (no blocking).
- ADR: docs/adr/0021-shadow-ai-detection.md (Proposed)
- Auditor posture: independent; did NOT write this code; no benefit of the doubt; actively tried to break it.
- Date: 2026-06-24
- VERDICT: PASS - no Critical or High findings in this pass. Critical 0, High 0, Med 0, Low 4.

> Honest-language note (CLAUDE.md): risk-reduction assessment, not proof of absence of defects.
> Reported as "no High/Critical findings in this pass" - never "secure".

---

## Method
- Read ADR-0021 (intent + section 9 threat model) first, then every in-scope file.
- Traced attribution end-to-end: admin endpoint -> enforce_admin_scope -> get_candidates -> get_tenant_session (RLS) -> classify -> attribution_key -> raw-event server-stamped columns -> privileged emit.
- Semgrep p/python + p/security-audit + p/secrets, --severity=ERROR, on all in-scope Python files.
- Empirically PROVED hash-chain backward-compat + tamper-evidence with a runtime script against canonical_json / compute_row_hash.
- Ran the F-018 suite: 47 pure unit + 12 DB-backed isolation/e2e/endpoint = 59 passing.

---

## Per-vector results (ADR-0021 R1-R10)

### 1. Attribution forgery (R4) - the crux - DEFENDED
No caller-supplied value (body, header, query) can influence the attributed team_id/project_id.
- attribution.py:30-35 - attribution_key reads ONLY row.team_id, row.project_id, row.detected_endpoint, row.selected_provider from the raw outbound row.
- Server-stamped at egress: shadow_ai_detector.py:162-168 builds the event from egress.tenant_context (resolved virtual-key identity), NOT client input; selected_provider is host-derived and CHECK-constrained to (openai,anthropic,bedrock).
- classifier.py:120-133 copies team/project verbatim; service.py:59-69 (_candidate_event) copies them into the emitted event. No request-body field is read on this path.
- The only caller-controllable input is path {tenant_id}: UUID-validated (admin/util.py:22) and, for SSO operators, tenant-pinned (admin/scope.py:83). It scopes the read; it cannot set a team/project on another tenant candidate.
- Cross-tenant framing path: none. SSO operator is tenant-pinned. Break-glass is cross-tenant by design (audited recovery) but can only READ another tenant genuine candidates - the team/project still derive from that tenant real server-stamped egress rows; break-glass cannot inject an attribution.
- Tests: test_attribution.py + test_e2e_nonstubbed.py pass.

### 2. Honesty boundary (R1) - PRESENT, NON-REMOVABLE, NO OVER-CLAIM
- constants.py:51-60 HONESTY_DISCLAIMER single source of truth; returned on EVERY response incl. zero-candidate case (models.py:33-42; service.py:125).
- API: admin/shadow_ai.py:90-106 always returns disclaimer; openapi.yaml marks it required on AdminShadowAiCandidateList.
- UI: shadow-ai-feed.tsx:80-106 renders backend disclaimer verbatim; no hide/dismiss control (non-removable is structural). Inert React text - no dangerouslySetInnerHTML.
- Over-claim scan (blocks|comprehensive|verdict|confirmed|guilty|violation|100%) over src/shadow_ai/ returns only NEGATED usages (NOT a verdict). Every row labelled candidate (models.py:30, admin/shadow_ai.py:46 Literal, UI badge Candidate).

### 3. Tenant isolation (R5/R10) - DEFENDED
- Reads on get_tenant_session(tenant_id) - sentinel_app role (NOBYPASSRLS); RLS filters every query to the GUC tenant (database.py:249-306).
- list_for_tenant_by_event_type (audit_log_repository.py:472-501) adds explicit WHERE tenant_id == tenant_id on top of RLS; parameterized select() - no text(), no concat.
- Privileged emit writes candidate.tenant_id = the path tenant_id threaded through classify(). A candidate is always written under the target tenant. enforce_admin_scope pins SSO operators (scope.py:81-90).
- Tests test_isolation.py pass (cross-tenant invisible).

### 4. Hash-chain integrity (F-003 core - HIGH scrutiny) - PROVEN
Opt-in-when-present extension (hash_chain.py:140-149) mirrors F-014 actor_id exactly.
- Backward compat (empirically proven): for a representative pre-F-018 row the canonical JSON is BYTE-IDENTICAL whether the 3 new keys are absent or present as None. No confidence_band/fired_signals/candidate_key key appears. compute_row_hash matches. Stored hashes stay valid; validate_chain passes over history.
- Tamper-evidence when present (empirically proven): a candidate row binds band/signals/key into the hash. Mutating the band, mutating the signal string, or NULL-ing candidate_key each changes the recomputed hash -> chain breaks at that row. No path to alter a candidate band/signals without breaking the chain.
- Three-way agreement: _candidate_event sets fields -> append (audit_log_repository.py:307-310) writes them into BOTH row_data (feeds compute_row_hash) AND the columns -> _row_to_hash_data (:143-148) reads them back. canonical_json applies the opt-in. All three agree.
- confidence_band satisfies ck_eal_confidence_band; fired_signals (max 36 chars) fits String(128); candidate_key (sha256[:64]) fits String(64). No emit-time 500.

### 5. Metadata-not-payload (R7) - CONFIRMED
Classifier/service read only identity, endpoint host/path, provider, counts, timestamps. No request/response body read or stored. detected_endpoint stripped of query/fragment/userinfo at the F-007 emitter and re-enforced by the schema pattern. test_detection_observes_metadata_not_payload passes.

### 6. Config / CRIT-2 (R6) - NO NEW policy_type
git diff shows NO change to _VALID_POLICY_TYPES (policy_repository.py:33 untouched). F-018 reuses F-007 per-tenant allowed_providers. The F-016 CRIT-2 unstorable-config trap does not apply.

### 7. F-007 seam (R2) - CONSUMES, does NOT rebuild
No httpx hook added; no raw shadow_ai_detected_outbound re-emitted. F-018 reads existing rows and emits ONE new variant shadow_ai_candidate_detected. test_seam.py passes.

### 8. Read-triggered emit / dedup race / cap - BOUNDED (Low, disclosed)
- Reads bounded (MAX_RAW_EVENTS=1000, MAX_CANDIDATE_LOOKBACK=1000, clamped by _LIST_MAX_LIMIT=1000).
- Emission capped at MAX_CANDIDATES_PER_EMIT=50 (service.py:106-123); cap hit logged, not silently truncated; RETURNED list never truncated.
- Dedup key embeds the UTC-day window_bucket -> at most one row per group per day under serial polling.
- Concurrent-poll race can double-record but cannot corrupt the chain (append advisory lock serializes). Bounded by concurrency x groups x 50/call; requires real prior egress. Disclosed in ADR-0021 section 6 D6. Finding F-018-L1.

### 9. Fail-closed (CLAUDE.md rule 5) - CONFIRMED
service.py:126-130 wraps analysis in try/except Exception, re-raises as ShadowAiServiceError; admin/shadow_ai.py:84-88 surfaces a clean 500. Never returns a partial/empty no-shadow-AI result on error. Mid-loop failure 500s after committing already-emitted candidates (own transactions); next poll idempotent via dedup.

### 10. Secrets/PII in logs/errors (CLAUDE.md rule 4/6) - CLEAN
- 500 detail is a static string; no exception/row data leaks.
- Service logs emit only tenant_id (UUID) + the cap constant; exc_info deliberately omitted with a comment (a raw DB error may carry row data).
- endpoint is host/path-only (no credentials possible) and never logged.

---

## Semgrep
Command: semgrep scan --config=p/python --config=p/security-audit --config=p/secrets --severity=ERROR --no-git-ignore <in-scope files>
- 1 ERROR: avoid-sqlalchemy-text at audit_log_repository.py:243.
- Triage: false positive for F-018 / not introduced by this change. Line 243 is pre-existing F-003 code (pg_advisory_xact_lock with a hardcoded integer constant) - no user input, no injection surface. The new F-018 query (list_for_tenant_by_event_type) uses parameterized select().where() only.
- 0 secrets findings.

---

## Findings

### F-018-L1 (Low) - concurrent-poll dedup race can double-record a candidate
- File: src/shadow_ai/service.py:99-123
- Exploit path: N concurrent GETs all read existing_keys before any emits, all emit the same candidate_key. Bounded (concurrency x groups x 50/call), requires real prior egress, does not corrupt the chain (advisory lock). Disclosed ADR-0021 D6.
- Fix: accept for v1, or add a UNIQUE partial index on (tenant_id, candidate_key) WHERE event_type=shadow_ai_candidate_detected and treat the insert conflict as a benign skip.

### F-018-L2 (Low) - agent_id slug documentation drift
- File: contracts/events.schema.json (ShadowAiCandidateDetectedEvent description)
- Issue: description says agent_id is gateway-core; emitter sets shadow-ai (constants.py:17 DETECTOR_SLUG); attribution.py docstring says defense. Three different slugs documented.
- Exploit path: none. agent_id is the emitter slug, not attribution; shadow-ai matches the agent_id pattern so events validate. Reviewer confusion only.
- Fix: reconcile the schema description to the emitted slug shadow-ai (api-architect).

### F-018-L3 (Low) - partial emit on mid-loop failure
- File: src/shadow_ai/service.py:118-123
- Exploit path: transient DB error on candidate k commits 1..k-1 then 500s. Not misleading (fail-closed 500, not empty); next poll idempotent via dedup. Robustness note only.
- Fix: optional - emit all NEW candidates in one privileged transaction; weigh against the per-row lock-bounding rationale behind MAX_CANDIDATES_PER_EMIT.

### F-018-L4 (Low) - Semgrep ERROR baseline (pre-existing)
- File: src/persistence/repositories/audit_log_repository.py:243 (pre-existing)
- Exploit path: not exploitable - hardcoded integer constant, no user input. Not introduced by F-018.
- Fix: add a nosemgrep:avoid-sqlalchemy-text justification, or bind the lock id as a parameter, to keep the ERROR baseline clean.

---

## Counts
- Critical: 0
- High: 0
- Medium: 0
- Low: 4

## Escalation
No High or Critical findings - no human escalation required by the BLOCK rule. The 4 Low items are non-blocking; F-018-L1 and F-018-L2 are recommended before merge for chain-row cleanliness and contract/code consistency.

## Verdict
PASS - no High/Critical findings in this pass. The crux controls (R4 attribution non-forgeability, R5/R10 tenant isolation, F-003 hash-chain backward-compat + tamper-evidence, R1 honesty boundary, R6 no-new-policy_type) are all implemented and, where empirically checkable, proven.
