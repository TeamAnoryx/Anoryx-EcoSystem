# ADR-0018 — Peer Feed: a Deterministic Multi-Signal Aggregation Seam (R-018)

Status: Accepted
Date: 2026-07-09
Builds on: ADR-0016 (R-016's `intent.IntentMatch`, the cross-tenant-allowed
reasoning this task inherits unchanged since it merges R-016's own output
rather than re-deciding tenancy), ADR-0017 (R-017's `career.TrajectoryMatch`
and its own precedent for scoping a 🏦 POST-INVESTMENT task down to a
pure-domain seam, which this ADR reproduces a third time).

## Context

The roadmap names R-018 "Hyper-personalized peer-networking interface 🏦
POST-INVESTMENT", the fourth task of Rendly's Phase 3 "B2C professional
networking (VISION)" tier (grouped `R-016 -> R-026`, "Depends on: R-004/R-005
+ the matching core", "~10-16h each"). As with R-017, the roadmap gives no
further detail beyond the title — this ADR resolves it the same way ADR-0016/
ADR-0017 did.

Two things bound this task before any design choice is made:

1. **"Hyper-personalized" cannot honestly mean ML personalization**, for the
   identical reason ADR-0012/ADR-0016/ADR-0017 already gave for "AI-powered"/
   "AI" language: no existing inference seam, no training data, no disclosed
   way to keep a learned-ranking model honestly bounded in one task. What
   CAN be built honestly is a deterministic combination of MORE THAN ONE
   already-shipped signal for the same subject — which is exactly what this
   codebase now has two of: R-016's intent-tag matching and R-017's
   career-trajectory matching. "Hyper" reads naturally as "more signals
   considered together", not "a smarter model".
2. **"Interface" cannot mean a UI or REST endpoint here**, for the same
   reason ADR-0016/ADR-0017 deferred REST/persistence: R-023 (Consumer
   onboarding) is unshipped, there is still no B2C identity to build a real
   user-facing surface for, and neither R-016 nor R-017 has a REST route yet
   for this task to sit behind. A feed-assembly function that a future
   endpoint calls is the honest scope; the endpoint itself is a named
   follow-up (see Consequences), exactly as R-016/R-017's own REST halves
   were deferred.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain merge of R-016 `IntentMatch` + R-017 `TrajectoryMatch` sequences into one ranked view; no REST endpoint, no persistence, no new matching logic, no ML)**

`src/rendly/peer_feed.py` adds `PeerSuggestion` (a per-candidate, immutable
combined-score record) and `build_peer_feed` (the merge function). Crucially,
this module does NOT compute any new match itself — it takes the OUTPUT of
`intent.rank_matches` / `career.rank_trajectory_matches` (or `suggest_match`/
`suggest_trajectory_match`) as input and combines it. There is no new opt-in
type, no new `Profile` read, no new migration, no new REST route.

Rejected: A2 (an ML/embedding-based unified ranking model over raw profile
data). Same rejection ADR-0012/ADR-0016/ADR-0017 already made for their own
A2 forks: no existing inference seam, no training data, no honestly-bounded
way to ship it in one task. Rejected: A3 (also fold in `culture.py`'s R-012
same-tenant department matching as a third signal). `culture.py` is a
DIFFERENT product surface — internal, cross-department, same-tenant
connection suggestions — with its own cross-tenant REFUSAL, the opposite
posture of R-016/R-017's cross-tenant-ALLOWED B2C matching (see ADR-0012 vs.
ADR-0016 Fork B). Merging a same-tenant-only signal into a definitionally
cross-tenant B2C feed would either silently drop culture signals for
cross-tenant candidates (inconsistent, undisclosed) or require inventing a
new tenant-scoping rule for this task alone — out of scope; a real "which
signals feed the B2C peer feed" product decision belongs to a future task
that can make it deliberately, not as a side effect of this merge utility.
Rejected: A4 (build the REST endpoint that calls `rank_matches` +
`rank_trajectory_matches` + `build_peer_feed` and wires it to a router in the
same PR). A second, independent unit of work (a wire-contract addition, a
FastAPI route, request/response shaping); bundling it here risks shipping
either half-finished, the same failure mode ADR-0016/ADR-0017 both avoided
identically. The merge function is fully useful and fully testable alone.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is a
DETERMINISTIC per-candidate score SUM over two already-deterministic,
already-shipped signal seams (R-016, R-017) — no model, no learned weighting,
no behavioral/click/engagement data, no third signal type. "Hyper-
personalized peer-networking interface" in the roadmap's task name is not
what ships; the merge utility this task's realistic scope allows is what
ships, and neither a UI nor a REST route accompanies it.

### Fork B — combination semantics: **B1 (union of candidates from both inputs; per-candidate scores summed; no de-duplication filtering, no signal weighting)**

A candidate appearing in only one input list still appears in the merged
feed (with the other signal's score at 0) — omitting them would silently
under-serve a subject who, say, has zero career-trajectory opt-ins but a rich
intent-tag profile. A candidate appearing in BOTH input lists is merged into
ONE row with both scores summed (`combined_score = intent_score +
trajectory_score`), not two separate rows — the point of "multi-signal" is a
single combined view per person, mirroring how a real UI would want to show
one card per candidate.

Rejected: B2 (weight one signal higher than the other, e.g. `2 * intent_score
+ trajectory_score`). An arbitrary weighting decision with no disclosed
product rationale — the same category of rejection ADR-0016/ADR-0017's own
D2 forks made for asymmetric weighting proposals. An unweighted sum is
simpler, equally orderable, and does not imply a prioritization this module
has no basis for. Rejected: B3 (require a candidate to appear in BOTH lists
to be included, i.e. intersection instead of union). Would silently drop
every candidate who only opted into one of the two signal types — the
opposite of "hyper-personalized" (more signals considered, not fewer
candidates surfaced).

### Fork C — provenance trust: **C1 (every match's `subject_user_id`/`subject_tenant_id` is checked against the caller-declared subject; mismatches raise, mirrors `intent.suggest_match`'s `_require_bound`)**

`build_peer_feed` takes `subject_user_id`/`subject_tenant_id` as explicit
arguments (not inferred from the first match) and validates every element of
BOTH input sequences against them before merging — a caller cannot
accidentally (or maliciously) mix in a match belonging to a different
subject and have it silently attributed to the wrong feed.

Rejected: C2 (trust the inputs without validation, since `IntentMatch`/
`TrajectoryMatch` are already-validated Pydantic models). Being individually
valid does not mean they belong to the SAME subject a caller claims to be
building a feed for — the same "trust but verify the pairing" discipline
`intent.py`/`career.py` themselves apply to `Profile`/opt-in pairs.

### Fork D — bounds + determinism: **D1 (`MAX_INPUT_MATCHES = 50` per input list — matches `intent.py`/`career.py`'s own `MAX_SUGGESTIONS`; `MAX_FEED_SUGGESTIONS = 50`/`DEFAULT_FEED_LIMIT = 10`; ties break on `candidate_user_id` ascending)**

A caller passing straight-through output from `rank_matches`/
`rank_trajectory_matches` (themselves already capped at `MAX_SUGGESTIONS =
50`) never trips this bound; a caller passing a hand-built, oversized list is
rejected outright. This is a smaller cap than `intent.py`/`career.py`'s own
`MAX_CANDIDATES = 500` deliberately — this module's inputs are expected to
already be RANKED, BOUNDED results, not raw candidate pools, so admitting up
to 500 pre-ranked matches per signal would be an inconsistent trust
boundary.

## What is deliberately NOT built here (named, not silently skipped)

- **No REST/wire surface.** Nothing in `contracts/openapi.yaml` changes. A
  follow-up task owns the endpoint that calls `intent.rank_matches` +
  `career.rank_trajectory_matches` and feeds their output into
  `build_peer_feed` — mirroring R-016/R-017's own deferred REST halves.
- **No UI ("interface").** The roadmap's "interface" language is not
  addressed by this task at all; a future frontend task is the natural
  owner, once a REST surface exists to call.
- **No third signal source.** `culture.py` (R-012) is deliberately excluded
  — see Fork A's rejection of A3.
- **No persistence.** `build_peer_feed` is a pure function; nothing is
  stored. A caller re-runs `rank_matches`/`rank_trajectory_matches` +
  `build_peer_feed` each time (or a future caching layer is a separate
  concern).
- **No weighting/tuning knobs.** See Fork B's rejection of B2 — the sum is
  unweighted and there is no configuration surface for a caller to bias it.

## Consequences

- A genuinely useful, genuinely tested feed-assembly utility exists for a
  future REST/UI task to build on, with the hard design question (how do two
  independently-shipped signal types combine into one ranked view without
  silently favoring one, dropping single-signal candidates, or trusting
  unverified input) already resolved and covered by
  `tests/domain/test_peer_feed.py`.
- No new attack surface is introduced: no new network endpoint, no new
  table, no new migration, no RLS change, no new opt-in type. The security
  review for this task is scoped accordingly — a pure computation over
  caller-supplied, already-validated match objects, with no I/O, mirroring
  ADR-0016/ADR-0017's own Consequences.
- The roadmap's R-018 checklist line is intentionally NOT marked "the full
  10-16h hyper-personalized peer-networking interface vision shipped" — it
  is marked shipped as THIS scoped aggregation seam, exactly as
  R-012/R-016/R-017 were, with the deferred REST/UI/third-signal halves
  named above as the obvious next slices.
