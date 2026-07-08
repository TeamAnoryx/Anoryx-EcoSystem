# ADR-0008 — Rendly Sentinel Safety: Real PII/Injection/Secret Inspection + Audit Log (R-008)

Status: Accepted
Date: 2026-07-07
Builds on: ADR-0001 D4 (the LOCKED fail-closed inspection contract + the RESERVED
``InspectionResult.detectors`` shape), ADR-0005 (the FORK D pipeline placement + the
``MessageInspector`` seam R-005 built and shipped as a no-op), R-001 (the locked wire contract).

## Context

``realtime/inspector.py`` and ``realtime/app.py`` already state R-008's job in one sentence:
"R-008 swaps in real PII / injection / secret detection... no pipeline change." The wire contract
(``contracts/messages.schema.json`` / ``contracts/openapi.yaml`` ``InspectionResult.detectors``)
already reserves the exact shape — up to 16 findings of ``{category: pii|injection|secret,
outcome: pass|block}``, "metadata only... never the offending content." R-008 is implementation
against an already-fully-specified surface, in the same posture R-007 was for its wire surface.

The roadmap's R-008 description additionally asks for "absolute data sovereignty" and "complete
administrative audit/oversight of all internal comms." The DATA SOVEREIGNTY half is a direct
consequence of Fork A below (self-hosted, in-process, no network call). The ADMINISTRATIVE
OVERSIGHT half needed its own scope decision — see Fork B.

## Decisions (one per resolved fork)

### Fork A — detection method: **A1 (self-hosted regex + Shannon-entropy heuristics, in-process, no ML, no network I/O)**
``realtime/detectors.py`` implements ``detect_pii`` / ``detect_injection`` / ``detect_secret`` as
pure functions: PII is email/phone/SSN regex + a Luhn-validated card-shaped digit run; injection
is a bounded instruction-override/jailbreak phrase list (mirrors Sentinel F-005's own
``InjectionRule`` regex posture); secret is a labeled-pattern list (AWS/Slack/GitHub/PEM headers)
plus a Shannon-entropy fallback for an unlabeled high-entropy token. ``realtime/sentinel_inspector.py``
wires all three into the ``MessageInspector`` seam, reducing them to the wire's ``pass``/``blocked``
shape (ANY category blocking blocks the WHOLE message — the contract's ``InspectionResult.status``
is a flat 3-value enum with no partial-redaction state, so there is no masking here, unlike some of
Sentinel's own hooks).

Rejected: A2 (call Sentinel's own detector code directly, ``Anoryx-Sentinel/src/orchestration/detectors/*``)
— those hooks are an ABC over Sentinel's own ``HookContext`` (per-agent event budgets,
``contracts/events.schema.json`` emission), not a dependency-free "inspect this string" function;
there is also no shared-library mechanism across product folders in this monorepo (root CLAUDE.md:
agents stay inside their assigned subproject) and no cross-product HTTP inspection endpoint exists
in ``Anoryx-Sentinel/contracts/openapi.yaml``. Building one would be a NEW cross-product contract,
well beyond this task. Rejected: A3 (Presidio, matching Sentinel's own PII backend) — a new heavy
dependency for a task with no shared-library seam to justify it; the regex approach is bounded,
disclosed, and testable without one. Rejected: A4 (call a third-party PII/DLP/classification API)
— directly contradicts "absolute data sovereignty": message content would leave the process (and
the company's infrastructure) for inspection.

**HONESTY BOUNDARY (verbatim, non-removable):** "high-coverage detection", not "100% detection"
(root CLAUDE.md). These are BOUNDED HEURISTIC detectors — a regex/entropy false negative on novel
phrasing or an unrecognized secret format is expected and NOT a claim of complete coverage. A
detector that raises or times out is still converted to a fail-closed BLOCK by the pipeline
(unchanged from R-005) — never a silent pass.

**DATA SOVEREIGNTY (verbatim, non-removable):** every detector is a pure in-process function —
no network call, no call-out to Sentinel, no third-party API. Message content never leaves this
process for inspection.

### Fork B — administrative oversight: **B1 (append-only ``inspection_audit_log`` data layer; a dedicated admin READ endpoint/scope is DEFERRED, not built)**
A passed message is already fully durable in ``messages`` (content + sender + channel + the R-008
``detectors`` findings) — the existing ``chat:read``-gated ``GET /channels/{id}/messages`` already
gives any channel member (and by extension anyone with DB/operational access) visibility into what
was inspected and passed. The gap is the OTHER half: a ``blocked`` or ``seam_unavailable`` send is
fail-closed and, by design (R-001 D4), NEVER persisted in ``messages`` — today that leaves
*zero trace anywhere* that a rejection happened at all, not even for an administrator. Migration
0003 adds ``inspection_audit_log`` (RLS, ``rendly_app`` SELECT+INSERT only — same append-only
posture as ``messages``) recording tenant/channel/sender/status/detectors/timestamps for every
non-``pass`` outcome; ``pipeline.py``'s ``_record_inspection_audit`` writes a row from the SAME
two rejection branches that already build a ``chat.ack blocked`` (the raising/unavailable branch
and the ``blocked`` branch). This closes the oversight gap at the DATA layer without touching the
wire contract or the scope enumeration.

Rejected: B2 (log every ``pass`` outcome too) — redundant with ``messages`` (which already carries
strictly more information — the actual content — for every passed send) and would roughly double
write volume on the hot path for no new coverage.

Rejected: B3 (add a new ``admin:audit_read`` scope + a ``GET /v1/admin/inspection-audit`` REST
endpoint now) — ``auth/store.py`` states the scope set is closed: "Subsets of the 8 LOCKED contract
scopes; never a new scope." A new scope is a real contract change (``contracts/openapi.yaml``'s
``security.oauth2.scopes`` enumeration) with no existing admin-identity concept to gate it
correctly (unlike Sentinel, which built a whole dedicated task — F-012 — for its admin principal
before F-013 built the read surface on top). Minting a scope + an ad-hoc admin surface in the same
PR that also ships the detectors would be exactly the kind of scope-widening this task should not
do unilaterally.

**HONESTY BOUNDARY (verbatim, non-removable):** "complete administrative audit/oversight" is
addressed at the DATA layer only — the log is real, append-only, RLS-scoped, and captures every
rejection with per-detector metadata (never content). It has NO REST/UI surface yet; querying it
today requires direct DB access (mirrors how R-005/R-007 left several read surfaces
DB-only/deferred — e.g. R-006's "OUT OF SCOPE (deferred): channel list/get/patch/archive +
member-list"). A follow-up task (not yet numbered) owns the admin scope decision + the read
endpoint/UI, exactly as Sentinel sequenced F-003 (log) before F-012/F-013 (admin principal +
dashboard).

This is ALSO, deliberately, NOT the R-009 hash chain: ``inspection_audit_log`` is a plain
append-only table, not a tamper-evident linked chain. R-009 still owns turning ``messages`` (and
now, if it chooses to, this log) into a hash-chained archive.

### Fork C — the reserved wire field: **C1 (populate ``detectors`` on every delivered message, not just on a block)**
``messages.detectors`` (migration 0003, JSONB) and ``Message.detectors`` (a new
``tuple[DetectorFinding, ...]`` field) are populated for every persisted (``pass``) message with
all three categories' findings (always all-``pass`` by construction — a single ``block`` would
have blocked the whole send before persist). ``frames.py`` surfaces this on both ``chat.message``
and the REST ``MessageRecord`` (``to_message_record`` — no change needed, it already delegates to
``build_chat_message``) and on a ``chat.ack blocked``/``inspection_unavailable`` (which findings
tripped, if any). This completes the contract's own "RESERVED (R-008)" annotation rather than
leaving it permanently empty.

## The three new modules + the two touched write paths

``realtime/detectors.py`` (pure, no imports outside stdlib) -> ``realtime/sentinel_inspector.py``
(``SentinelMessageInspector``, the new ``create_chat_app`` default, replacing
``NoOpMessageInspector`` there — ``NoOpMessageInspector`` remains for tests that want an explicit
pass-through, and the test harness (``tests/realtime/conftest.py``) now defaults to it explicitly
so every pre-existing test keeps its exact prior behavior). ``pipeline.py``'s ``handle_chat_send``
passes ``outcome.detectors`` into ``chat_repo.insert_message`` on PASS, and calls the new
``_record_inspection_audit`` helper (best-effort — an audit-WRITE failure never changes an
already-fail-closed ack) on every non-``pass`` branch.

## Consequences

- Every Rendly chat message is now inspected by a REAL, self-hosted, no-network detector before
  persist/fan-out — no comms bypass Sentinel-equivalent inspection (the fail-closed pipeline
  R-005 built already guaranteed this structurally; R-008 makes the inspection itself real).
- ``inspection_audit_log`` gives an operator with DB access a durable, RLS-scoped, content-free
  record of every rejected send — the gap that existed when only ``NoOpMessageInspector`` ran.
- A follow-up task inherits an EXACT, already-identified integration point for admin oversight:
  decide the scope (new locked scope vs. reusing ``channels:admin``) and add the REST read surface
  over ``chat_repo.load_inspection_audit_log`` (already written, already tested, just not wired to
  HTTP) — mirrored on Sentinel's own F-003 -> F-012/F-013 sequencing.
- R-009 (immutable archiving) gains a second table (``inspection_audit_log``) it MAY choose to
  extend with the hash chain alongside ``messages`` — not required by this task, not built here.
