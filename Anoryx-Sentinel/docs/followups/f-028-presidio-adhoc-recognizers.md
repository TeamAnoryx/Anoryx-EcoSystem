# Follow-up: per-tenant custom patterns as Presidio ad-hoc recognizers ("ML hooks")

**Context:** F-028 (ADR-0034) ships the client-defined REGEX engine as a
standalone, spaCy-independent matcher (`src/data_protection/custom_pii/`). The
roadmap line also says "regex + **ML hooks**". This follow-up covers the "ML
hooks" reading: letting a tenant's custom patterns participate in Presidio's
NLP-based analysis pass rather than running as a separate regex stage.

**Why deferred (not skipped):** the standalone regex engine is the higher-value,
lower-risk half — it works on the slim image (no spaCy), is ReDoS-hardened, and
already satisfies the core need ("mask my EMPLOYEE_ID"). Coupling custom
patterns into Presidio would make custom-PII depend on the heavy optional
`[pii-spacy]` extra, which contradicts the design goal of ADR-0034.

**What the Presidio-integrated version would add**, and how:

1. Presidio supports request-time recognizers via
   `AnalyzerEngine.analyze(text, entities, ad_hoc_recognizers=[PatternRecognizer(...)])`.
   The `PIIHook` (`src/orchestration/detectors/pii_detector.py:238`) would build
   a `PatternRecognizer` per active tenant pattern (reusing the SAME
   `CustomPiiPatternLoader` cache from ADR-0034) and pass them as
   `ad_hoc_recognizers` at the `analyze()` call site.
2. Benefit over the current two-stage approach: custom entities would be scored
   and de-conflicted in the SAME pass as the built-in entities (one span set,
   consistent overlap handling), and could leverage Presidio context
   enhancement (surrounding-word confidence boosts) that a bare regex can't.
3. Constraint: this path only runs where `[pii-spacy]` is installed. The
   standalone regex engine (ADR-0034) MUST remain as the slim-image fallback —
   so this becomes an *optional enhancement layered on top*, not a replacement.
   The per-tenant loader, table, validator, and ReDoS controls are all reused
   unchanged; only the match/emit site differs.
4. A genuinely custom **ML** recognizer (a tenant-supplied model, not a regex)
   is a much larger, separate feature (model upload, sandboxed inference, supply-
   chain trust) and is explicitly NOT what this follow-up proposes — "ML hooks"
   here means Presidio's NLP-context machinery applied to tenant regexes.
