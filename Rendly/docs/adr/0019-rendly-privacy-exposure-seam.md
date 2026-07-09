# ADR-0019 — Privacy: a Deterministic, Fail-Closed, Per-Field Exposure-Grant Seam (R-019)

Status: Accepted
Date: 2026-07-09
Builds on: ADR-0016/ADR-0017/ADR-0018 (the established scope-down discipline
for this B2C tier: pure-domain, no ML, no persistence, no REST/UI, cross-
tenant allowed where the underlying signal already allows it), and Sentinel's
own F-017 JSON data-lock engine precedent (per-field conditional
withholding, fail-CLOSED) for the general shape of a field-level exposure
control — reproduced here as an independent Rendly seam, not a shared
dependency.

## Context

The roadmap names R-019 "Privacy-controlled DM portal (granular data
exposure) 🏦 POST-INVESTMENT", the fifth task of Rendly's Phase 3 "B2C
professional networking (VISION)" tier. As with R-017/R-018, the roadmap
gives no further detail beyond the title.

Two things bound this task before any design choice is made:

1. **"DM portal" cannot honestly mean a message transport or UI here.**
   Rendly already has real messaging (R-005's real-time chat, WebSocket-
   backed, with its own persistence in `rendly.persistence.chat_repo`) — a
   "DM portal" would mean either reusing that transport for 1:1 messages (a
   real, separate feature decision about scoping chat to DMs) or building a
   parallel one, and either way requires REST/UI work this tier has
   consistently deferred (R-016/R-017/R-018 all named their REST/UI halves
   as follow-ups). Building a portal UI now, with no backend REST surface
   for the *rest* of this tier to call yet, would ship an unconnected shell
   — the same half-finished-implementation failure mode banked rule 13 and
   this codebase's engineering standards explicitly forbid.
2. **"Granular data exposure" is the one part of this title that IS
   honestly buildable as a pure-domain seam**, and is a genuinely
   independent, valuable piece of work: deciding WHICH of a user's optional
   profile-adjacent fields (team, intent tags, career-trajectory stage) are
   visible to anyone at all, before any DM/portal/UI exists to display them.
   This is the literal parenthetical the roadmap's own task name supplies —
   not an invented reinterpretation.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain, fail-closed, per-field exposure-grant model + a deterministic redaction function; no DM portal, no message transport, no persistence, no REST/UI)**

`src/rendly/privacy.py` adds `PrivacyField` (a closed, five-value `StrEnum`:
`TEAM`, `INTENT_SEEKING`, `INTENT_OFFERING`, `CAREER_CURRENT_STAGE`,
`CAREER_TARGET_STAGE`), `PrivacySettings` (an opt-in-shaped grant record,
mirroring `intent.IntentProfile`'s construction idiom) + `bind_privacy_settings`,
and `reveal` (the redaction function producing an `ExposedProfileView`). There
is no new migration, no new table, no new REST route, no touch to R-005's
chat/messaging code at all.

Rejected: A2 (build the DM portal — a REST endpoint + a minimal UI for 1:1
messages). See Context point 1 — no backend REST surface exists yet for any
task in this tier to call, and Rendly has no frontend package to extend at
all (unlike Sentinel's `frontend/`), unlike the narrower "UI" gap R-018
described. Rejected: A3 (persist `PrivacySettings` in this task). A second,
independent unit of work (a migration, an RLS posture decision); mirrors
every prior ADR in this tier's identical A4-shaped rejection. The grant model
+ redaction function is fully useful and fully testable as a pure seam a
caller supplies data to each time, exactly as `IntentProfile`/`CareerGoal` do
before their own persistence follow-ups land.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is a
fail-closed, per-FIELD exposure grant and a pure redaction function — no
message transport, no portal, no UI, no per-viewer differentiation (see Fork
C). "Privacy-controlled DM portal" in the roadmap's task name is not what
ships; "(granular data exposure)" — read literally — is.

### Fork B — default posture: **B1 (fail-closed: absence of `PrivacySettings`, or an empty `granted_fields`, exposes nothing beyond identifiers)**

A privacy control whose default is "visible until configured otherwise"
is not honestly a privacy control — it is an opt-OUT mechanism wearing a
privacy label. `reveal(profile, settings=None, ...)` returns an
`ExposedProfileView` with every optional field `None`; the ONLY
unconditionally-exposed fields are `user_id`/`tenant_id`, which every other
match/view type in this codebase already exposes unconditionally
(`IntentMatch`, `TrajectoryMatch`, `PeerSuggestion`) and which are required
just to address the record.

Rejected: B2 (default-allow: an absent `PrivacySettings` exposes everything,
requiring an explicit grant to HIDE a field). The opposite posture — this is
exactly the "public by default" failure mode a privacy-labeled feature must
not have; a user who has never configured privacy settings must not be more
exposed than one who explicitly configured "hide everything."

### Fork C — differentiation: **C1 (no per-viewer/per-relationship differentiation — one grant list applies uniformly regardless of who is asking)**

A truly "granular" DM-portal privacy model would let a user show different
fields to different counterparties (e.g. reveal `CAREER_TARGET_STAGE` to a
mentor-match but not to a stranger). Building that requires a "who is this
viewer to the subject" relationship concept, which does not exist in
Rendly's pure-domain package — R-005's DM/chat relationships live in the
`realtime`/`persistence` layers (channels, memberships), not in
`rendly.profile`/`rendly.intent`/`rendly.career`, and inventing one here to
serve only this task would be exactly the kind of un-asked scope-widening
banked rule 13 warns against.

Rejected: C2 (build a minimal per-tenant or per-matched-candidate
differentiation, e.g. "expose to anyone I have a `TrajectoryMatch`/
`IntentMatch` with"). A real, disclosed-limitation-worthy idea for a
follow-up, but it would require this module to depend on `peer.py`'s
composition seam (or re-derive matches itself) just to decide visibility —
conflating "what matches were found" with "what is shown to whom" is a
different, larger design question than this task's realistic scope, and
premature before R-023 (Consumer onboarding) gives this tier a real
counterparty-relationship concept to key against.

**Disclosed limitation:** every consumer of `reveal` today can only ask
"what does this subject expose, period" — not "what does this subject expose
to ME." A future task that wants per-counterparty exposure owns modeling
that relationship first, then can either extend `PrivacySettings` with
scoped grants or layer a second, relationship-aware seam on top of this one.

### Fork D — field selection + independence: **D1 (the five fields are: `TEAM`, `INTENT_SEEKING`, `INTENT_OFFERING`, `CAREER_CURRENT_STAGE`, `CAREER_TARGET_STAGE`; each is granted/withheld independently)**

These are exactly the optional, non-identifying fields the B2C tier's own
prior seams (R-002's `Profile.team`, R-016's `IntentProfile`, R-017's
`CareerGoal`) already introduced — `reveal` covers the surface this tier has
actually built, not a speculative superset. Independence matters concretely:
a user job-hunting discreetly may want `CAREER_TARGET_STAGE` visible (so a
mentor-match can see what they're aiming for) while keeping
`CAREER_CURRENT_STAGE` hidden (so their current employer/level isn't
signaled) — a single "show my career info" toggle could not express this;
two independent grants can.

Rejected: D2 (a single coarse "show everything" / "show nothing" toggle
instead of five independent fields). Directly contradicts "granular" in the
roadmap's own task name — the whole point is per-field control.

## What is deliberately NOT built here (named, not silently skipped)

- **No DM portal, no message transport, no UI.** R-005 already owns
  messaging; this task does not touch it. A future task owns wiring a real
  "who can see what" check into an actual DM/portal surface.
- **No persistence.** `PrivacySettings` is not stored; a caller supplies it
  each time. A follow-up task owns a `rendly.privacy_settings` store +
  migration, naturally paired with R-016's/R-017's own deferred opt-in
  stores.
- **No REST/wire surface.** Nothing in `contracts/openapi.yaml` changes.
- **No per-viewer/per-relationship differentiation.** See Fork C's disclosed
  limitation.
- **No new field types beyond the five named.** See Fork D — this seam
  covers exactly the optional fields this tier has already shipped, not a
  speculative future superset.

## Consequences

- A genuinely useful, genuinely tested, fail-closed exposure-grant seam
  exists for a future persistence/REST/relationship-aware task to build on,
  with the hard design question (per-field vs. all-or-nothing, fail-open vs.
  fail-closed default, per-viewer vs. uniform) already resolved and covered
  by `tests/domain/test_privacy.py`.
- No new attack surface is introduced: no new network endpoint, no new
  table, no new migration, no RLS change. The security review for this task
  is scoped accordingly — pure computation over caller-supplied domain
  objects, with no I/O.
- The roadmap's R-019 checklist line is intentionally NOT marked "the full
  10-16h privacy-controlled DM portal vision shipped" — it is marked shipped
  as THIS scoped exposure-grant seam, exactly as R-012/R-016/R-017/R-018
  were, with the deferred portal/persistence/REST/per-viewer halves named
  above as the obvious next slices.
