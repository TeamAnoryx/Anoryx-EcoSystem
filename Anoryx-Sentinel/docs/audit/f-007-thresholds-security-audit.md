# Security Audit - F-007 Per-Tenant Classifier Thresholds (ADR-0025)

- Branch: task/F-007-thresholds-native (base main)
- Auditor: independent red-team. Did not author this code.
- Date: 2026-06-26
- Verdict: PASS (CLEAN) - no High/Critical findings in this pass.
- Semgrep p/python + p/security-audit + p/secrets, severity=ERROR, changed Python files: 0 findings.

## Scope
Working-tree diff vs main. Deep-audit target = F-007 thresholds: 3 nullable columns on
tenant_routing_policy (migration 0032) making the LLM-as-judge band + confidence floor per-tenant,
the admin GET/PATCH surface, and a fix to two pre-existing double-begin bugs. The diff also carries
an O-001 Orchestrator contract-only addition (no runtime), out of this feature threat surface.
Local Docker down: DB-gated tests run on CI (authoritative). 65 DB-free tests + ruff/black green
locally. The local DB-test non-run is NOT a finding.

## Invariant verification (security core)

### R1 - NO-DOWNGRADE (final >= regex_score for every threshold): CONFIRMED
- injection_detector.py:461 - final = min(1.0, max(regex_score, verdict.score)). Blend is always
  max(regex, judge) clamped to 1.0; regex_score already clamped to [0,1] at :259, so final >= regex.
- Thresholds never enter the blend. They gate (a) whether the judge runs (:372 band [floor, skip))
  and (b) whether its verdict counts (:457 confidence floor). Both off-paths return _regex_verdict
  (exact F-005 outcome), never allow.
- Adversarial/compromised judge output contained 3 ways: judge/base.py:91 verdict_from_dict raises
  JudgeParseError if score/confidence outside [0,1] => invocation_failed => regex; the max() floor
  blocks a low/negative score from pulling final below regex; the min(1.0,...) clamp bounds a high
  score. No reachable judge output or threshold lowers final below regex.
- Block threshold stays GLOBAL (settings.injection_score_threshold, :355), not per-tenant.
- NaN/Inf rejected at Pydantic ge/le AND DB range CHECKs. Cannot reach the resolver.

### R2 - FAIL-CLOSED (every judge failure => regex, never allow): CONFIRMED
- injection_detector.py:457 - any JudgeFellBack (unconfigured/policy_denied/degraded/
  invocation_failed) OR confidence < floor => _regex_verdict.
- _resolve_classifier_config (:98-107) - any exception => UNCONFIGURED => run_judge(preset=None) =>
  JudgeFellBack => regex. invoker.run_judge: every except path returns a typed JudgeFellBack and
  emits a hash-chained audit event; CancelledError (BaseException) intentionally propagates.

### R8 - classifier-DISABLED => no config DB read, regex byte-identical: CONFIRMED
- inspect runs _judge_gates_pass (:360) BEFORE _resolve_classifier_config (:366). The gate returns
  False first on classifier_enabled is not True (:398), absent provider_registry (:400), or a
  jailbreak-family first rule (:402); each returns _regex_verdict with no DB read. Test
  test_classifier_off_does_no_config_read asserts resolve.assert_not_called().

### RLS / tenant isolation: CONFIRMED
- get_classifier_config opens get_tenant_session(tenant_id) (RLS, GUC is_local).
  resolve_classifier_config adds defense-in-depth WHERE tenant_id == tenant_id AND
  tenant_id == caller_tenant_id. A request can only read its own tenant row.
- Admin GET/PATCH: enforce_admin_scope tenant-pins SSO operators (scope.py:83 - 403 unless
  admin_auth.tenant_id == path tenant_id) and gates writes to tenant_admin (:87; auditor => 403 on
  PATCH). Break-glass is intentionally cross-tenant. RLS session scoped to the path tenant. Tenant A
  cannot read or set tenant B thresholds.

### Admin set surface - out-of-range / inverted band: CONFIRMED backstopped
- Pydantic ge=0/le=1 on all three fields (schemas.py:203-205) => 422 out of range.
- Inverted band (floor>skip) has no Pydantic cross-field rule; DB ck_trp_classifier_band backstops
  and update_config maps IntegrityError => 400 invalid_config_value (control.py:139-142), generic
  message. Bounded update allow-list (repo :212-222) rejects any field outside the 6 permitted;
  model_fields_set means only sent fields are written.

### Migration 0032 reversible + CHECKs correct: CONFIRMED
- revision 0032, down_revision 0031 (linear). upgrade adds 3 nullable NUMERIC(4,3) cols + 3 range
  CHECKs + 1 band CHECK; downgrade drops band CHECK, range CHECKs, then columns (reversed). Additive
  + nullable, NULL => code default => byte-identical until set. CHECK SQL matches ORM __table_args__.

## Bugfix review - two pre-existing double-begins (in this PR)
- repo:233 get_classifier_config and invoker.py:135 _model_authorized each previously did a nested
  begin() AFTER get_tenant_session (which autobegins via set_config before yield, database.py:302).
  That raised InvalidRequestError, swallowed by the except, forcing the judge inert / every model
  into policy_denied on a real DB.
- (a) Fix correct: both are reads, now run on the autobegun tx with the is_local tenant GUC active.
- (b) No tx-leak / RLS bug: the read tx holds the transaction-local GUC; on context exit close()
  rolls back the pending read-only tx. Nothing written; GUC clears with the tx; no cross-conn leak.
- (c) Posture not weakened: a still-failing _model_authorized returns False (:156-160) =>
  JudgeFellBack(policy_denied) => regex verdict. Fail-closed, never allow.

## Findings

### Low (informational) - band CHECK does not cover floor-vs-default-skip
injection_detector.py:414-419. ck_trp_classifier_band only validates column-vs-column; when
classifier_skip_threshold is NULL it resolves at runtime to judge_skip_score (0.9), so an operator
can set floor=0.95 with skip NULL, producing an empty band [0.95, 0.9). Non-exploitable: an empty
band means the judge never runs => final = regex (R1 holds; only reduces escalation, never
downgrades). Documented in ADR-0025. No code change required.

### Low - stale docstring footgun (pre-existing, out-of-diff)
persistence/database.py:281-284. The get_tenant_session usage example still shows a nested begin()
after the session - the exact pattern that raises InvalidRequestError (autobegin) and produced the
bugs this PR fixes. Fix: correct the docstring to read-directly / commit-explicitly to stop the
copy-paste recurrence.

### Medium - PRE-EXISTING / OUT-OF-DIFF sibling double-begin: team rate-limit fail-open
gateway/middleware/rate_limit.py:352-353. Same nested begin() after get_tenant_session (autobegins)
=> InvalidRequestError => caught at :361 => limit = None => the opt-in F-009 team-RPM tier is
silently disabled on a real DB. Exploit: a tenant that configured team_rpm_limit gets no team-tier
enforcement; a team can exceed its RPM ceiling (key/tenant Redis tiers are a separate path and still
apply, bounding blast radius - Medium, not High). Fix: remove the redundant nested begin(), mirroring
this PR fix. Empirical confirmation deferred (local DB down); asserted by strong analogy to the
pattern this PR fixes and the codebase F-019 occurrence. Fold into this PR or a tracked follow-up.

### Medium - PRE-EXISTING / OUT-OF-DIFF sibling double-begin: egress monitor fail-open
gateway/middleware/egress_monitor.py:94-95. Same nested begin() in _resolve_allowed_providers; the
InvalidRequestError propagates to bind_egress_context and is caught by the try/except at
chat_completions.py:256-261 => egress_context_bind_failed => the per-request egress / shadow-AI
outbound monitor is silently disabled (fail-open of a detect-only defense-in-depth control). Fix:
remove the redundant nested begin(). Same confirmation caveat.

## Notes
- events.schema.json and policy.schema.json untouched (absent from diff): thresholds are config,
  not emitted, and the locked policy schema is not the classifier home.
- No secrets / credentials / plaintext PII in changed source or test fixtures (Semgrep p/secrets
  ERROR = 0; test scan strings are injection patterns, not PII).
- Error surfaces leak no content: config/judge errors log request_id / error_type / provider kind
  only; admin CHECK violations return generic 400; judge/base.py:97 charset-sanitizes verdict reason.

## Conclusion
In-scope F-007 thresholds feature is CLEAN - no High/Critical. R1/R2/R8, RLS isolation, admin
authz/validation backstop, and migration reversibility all hold. The double-begin bugfix is correct
and strengthens posture. Two Medium findings are PRE-EXISTING sibling double-begins outside this diff
(team rate-limit and egress monitor fail-open); they do not block this PR but warrant escalation/fix.
