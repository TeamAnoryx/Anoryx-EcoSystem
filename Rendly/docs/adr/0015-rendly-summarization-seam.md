# ADR-0015 — Comms Summarization: a Deterministic Extractive-Digest Seam (R-015)

Status: Accepted
Date: 2026-07-09
Builds on: ADR-0012 (R-012's precedent for scoping a 🏦 POST-INVESTMENT task down
to a pure-domain, no-persistence, no-REST seam), ADR-0013/ADR-0014 (the same
pattern applied to R-013/R-014), ADR-0008 (R-008's Fork A — the cross-product
"no shared-library mechanism... agents stay inside their assigned subproject"
rule this task's Alternatives section relies on), ADR-0009 (R-009's archiving
scope — huddle archiving is metadata-only, never media/transcript content;
this task does not touch or weaken that boundary), R-001 D4 (the LOCKED
"huddle media is P2P and NEVER relayed through or content-inspected by
Rendly" honesty boundary).

## Context

The roadmap names R-015 "Context-aware summarization of comms + meeting
transcripts 🏦 POST-INVESTMENT... AI summaries of executive comms/transcripts;
smart scheduling vs corporate calendars; automated outreach tracking. Depends
on: R-008, R-009 · 16-22h." Following the precedent set by
O-009/O-010/O-011/R-012/R-013/R-014, this is a 🏦 POST-INVESTMENT task pulled
into an active build: ship a deliberately scoped-down seam, not the full
named vision, in one task.

Three things bound this task before any design choice is made, and each
conflicts directly with a clause of the roadmap name:

1. **"AI summaries" implies a model; this codebase has none.** There is no
   LLM/AI-provider dependency anywhere in Rendly's `pyproject.toml` or source
   tree, and no cross-product inference seam to borrow one from — ADR-0008
   Fork A already rejected calling Sentinel's own detector code directly for
   exactly this reason ("no shared-library mechanism across product folders
   in this monorepo... agents stay inside their assigned subproject," root
   `CLAUDE.md`). Standing up a real LLM integration (provider selection, key
   vaulting, cost/latency budget, prompt-injection exposure on untrusted
   message content) is itself a multi-task unit of work with its own security
   review — not something to smuggle into a 16-22h scope-down. What IS
   buildable honestly, in the same spirit as `culture.py`'s "AI-powered"
   scope-down (ADR-0012), is a genuinely useful DETERMINISTIC, EXTRACTIVE
   digest: word-frequency keyword extraction + highest-scoring message
   selection, no generated text.
2. **"Meeting transcripts" do not exist in this codebase.** R-001 D4 (LOCKED)
   holds that huddle media is P2P and never relayed through or recorded by
   Rendly; R-009 (ADR-0009) accordingly persists only huddle session
   METADATA (`huddle_id`, `caller_id`/`callee_id`, `participant_ids`,
   `created_at`/`ended_at`) via `persistence.huddle_repo.archive_ended_huddle`
   — there is no transcript text field anywhere in the `huddles` table
   (migration `0004_immutable_archiving.py`) or elsewhere. A summarizer
   cannot honestly summarize content the product structurally never sees.
   What this task CAN honestly build for huddles is a metadata-only digest
   (who was on the call, when, for how long) — not a conversation summary.
3. **"Smart scheduling vs corporate calendars" and "automated outreach
   tracking" have no integration surface to build against.** No calendar
   integration (Google/Outlook/CalDAV or an internal equivalent) and no
   CRM/outreach-tracking integration exist anywhere in this codebase. Both
   are separate, unstarted integration efforts with their own external
   dependencies, credentials, and data-sovereignty questions (R-008's own
   "data never leaves" boundary would need to be re-litigated for any
   outbound calendar/CRM call) — out of this task's license entirely, not a
   trimmed-down version of either.

## Decision — resolved forks

### Fork A — scope: **A1 (a pure-domain, deterministic extractive-digest seam over already-loaded chat messages AND a metadata-only huddle digest; no abstractive/AI summarization, no meeting-transcript summarization, no calendar/outreach integration, no persistence, no wire surface)**

`src/rendly/summary.py` adds `DigestMessage` (a minimal, decoupled input
record — NOT `realtime.message.Message`, see Fork B), `CommsDigest`
(`message_count`, `participant_ids`, `period_start`/`period_end`,
`top_keywords`, `highlight_message_ids`), `summarize_messages` (tokenizes,
scores, and selects), `HuddleDigest` (`participant_ids`,
`started_at`/`ended_at`, `duration_seconds` — no content field, because none
exists to fill), and `summarize_huddle`. There is no new migration, no new
table, no new REST route, and no `contracts/openapi.yaml`/
`policy.schema.json` touch (out of scope for this product entirely, as for
every prior Rendly task).

Rejected: A2 (call out to an external or future in-repo LLM/AI provider for
real abstractive summarization). Directly contradicts Context point 1 — no
such seam exists, and standing one up is its own multi-task unit of work
with a dedicated security review (prompt injection via untrusted message
content into a model prompt is a real, unaddressed attack surface this task
is not licensed to wave through). Rejected: A3 (reconstruct or infer a
"transcript" from huddle metadata, e.g. synthesizing placeholder text from
participant names and duration). Would be actively dishonest — presenting
metadata as if it were conversational content — the opposite of this
ecosystem's mandatory honest-language discipline. Rejected: A4 (build a
calendar-integration or outreach-tracking stub/seam anyway, scoped down).
Unlike R-012/R-013/R-014's scope-downs (which kept the SAME domain, just
shrank capability), a calendar/CRM integration is a fundamentally different
external-system integration with no existing seam in this codebase to scope
down FROM — there is nothing here to shrink, only a new integration to
build from zero, which does not fit a single scope-down task any more than
"stand up an LLM integration" does.

**HONESTY BOUNDARY (verbatim, non-removable):** what ships here is a
DETERMINISTIC, EXTRACTIVE digest — word-frequency keyword extraction plus
highest-scoring message selection over already-loaded chat messages, and a
metadata-only digest (participants/timestamps/duration) for huddles. Nothing
here is "AI", nothing here summarizes a meeting transcript (none exists),
and nothing here schedules against a calendar or tracks outreach. "Context-
aware summarization... AI summaries... smart scheduling... automated
outreach tracking" is the vision name for a future, differently-scoped and
differently-integrated capability; this task does not claim to be it.

### Fork B — input type: **B1 (a new, decoupled `DigestMessage` record; not `realtime.message.Message`)**

The existing codebase's import direction is `realtime -> domain`
(`realtime/*.py` imports `..channel`, `..identifiers`, `..common`, `..profile`
transitively; nothing under the domain layer imports `realtime`).
`summary.py` lives beside `culture.py`/`event.py` in that same domain layer,
so importing `realtime.message.Message` here would invert that direction —
the same concern ADR-0013 Fork B named for `MAX_SESSION_CAPACITY`, applied
here to a type instead of a constant. `DigestMessage` carries only the
subset of fields the digest algorithm needs (`message_id`, `tenant_id`,
`channel_id`, `sender_user_id`, `content`, `seq`, `created_at`); a caller
loading real archived messages (e.g. via `persistence.chat_repo.
load_message_history`) maps each row's `Message` into a `DigestMessage`.

Rejected: B2 (import `realtime.message.Message` directly). Correct in the
short term but sets a precedent of the domain layer reaching into
`realtime`, which every other domain module has never done. Rejected: B3
(a bare `dict`/`tuple` instead of a pydantic model). Loses the frozen /
`extra="forbid"` / timezone-aware / non-negative-`seq` validation discipline
every other domain input type in this codebase enforces (`CultureOptIn`,
`EventSession`) — a digest input should be validated the same way a digest
output is.

### Fork C — keyword-frequency semantics: **C1 (message-frequency: each message contributes each of its distinct tokens once, not raw per-occurrence counts)**

`top_keywords` ranks tokens by how many DISTINCT messages contain them, not
by summed raw occurrence count. A single message repeating one word many
times (accidentally, or adversarially — e.g. a flood/spam message) cannot
alone dominate the digest; a term genuinely discussed across several
messages ranks above a term one message merely repeats. This mirrors
`event.agenda`'s and `culture.rank_connections`'s existing "resistant to a
single bad/degenerate input skewing the result" discipline, applied to text
frequency instead of scheduling/matching.

Rejected: C2 (raw per-occurrence term frequency, summed across all
messages). The more common "TF" baseline in extractive-summary literature,
but directly exposes the digest to single-message repetition dominating the
result — undesirable for a digest meant to reflect what a CHANNEL discussed,
not what one message contained.

### Fork D — digest bounds and determinism: **D1 (`MAX_MESSAGES = 1000`, `MAX_KEYWORDS = 10`, `MAX_HIGHLIGHTS = 5`; ties on keyword count break alphabetically, ties on highlight score break on earliest `seq`)**

Mirrors this codebase's existing bounded-list discipline (`culture.py`'s
`MAX_INTERESTS`/`MAX_CANDIDATES`, `event.py`'s `MAX_SESSIONS_PER_EVENT`): the
tokenize/count/select scan is bounded so an unbounded message history is
never silently accepted from a caller — a caller summarizing a longer
history must window/page it itself (exactly as `culture.rank_connections`
requires of its own `candidates`). Every ranking step has an explicit,
tested tie-break so the same input always produces the same output, matching
`event.agenda`'s and `culture.rank_connections`'s own determinism discipline.

Rejected: D2 (no cap on message count / keyword count / highlight count).
Same rationale as `MAX_CANDIDATES` in ADR-0012 Fork D — an unbounded input is
an unbounded-cost vector for a caller that forgets to window its own history.

### Fork E — huddle digest scope: **E1 (metadata-only: `participant_ids`, `started_at`, `ended_at`, `duration_seconds`; no content field of any kind)**

See Context point 2. `HuddleDigest` does not carry a `summary`, `transcript`,
`topics`, or any other content-shaped field — adding one, even nullable and
unpopulated today, would misleadingly suggest a future version might fill it
from real conversation content, when in fact R-001 D4 architecturally
prevents Rendly from ever seeing that content at all. If that lock is ever
revisited at the product level, huddle summarization would need a distinct,
separately-reviewed ADR of its own — not a field silently reserved here.

Rejected: E2 (a nullable `summary: str | None` field, always `None` for now).
Named and rejected above — an honesty risk, not a convenience.

## What is deliberately NOT built here (named, not silently skipped)

- **No AI/abstractive summarization.** See Context point 1 and Fork A. This
  is the single largest gap between the roadmap's "AI summaries" name and
  this delivery. Standing up a real LLM integration is a separate, future,
  dedicated-security-review task — not a silent extension of this one.
- **No meeting-transcript summarization.** See Context point 2 and Fork E.
  There is no transcript data source in this codebase; `summarize_huddle` is
  honestly scoped to session metadata only.
- **No calendar integration / "smart scheduling."** See Context point 3.
  No calendar integration exists anywhere in this codebase to build against.
- **No outreach tracking.** See Context point 3. No CRM/outreach integration
  exists anywhere in this codebase to build against.
- **No persistence.** Digests are computed on demand from caller-supplied
  records, exactly as R-012's `culture.py` and R-013's `event.py` shipped
  domain-only before any persistence follow-up. A follow-up task owns
  wiring `persistence.chat_repo.load_message_history` /
  `persistence.huddle_repo`'s archived rows into this module's inputs.
- **No REST/wire surface.** Nothing in `contracts/openapi.yaml` changes;
  there is no `GET /v1/channels/{channel_id}/digest` yet. A follow-up task
  owns the contract addition and the FastAPI router wiring it to this
  module's pure functions (mirroring how R-008 deferred its own admin-read
  surface, ADR-0008 Fork B).

## Consequences

- A genuinely useful, genuinely tested, honesty-bounded digest primitive
  exists for a future task to wire into a REST endpoint, persist a digest
  cache for, and (separately, and only after its own dedicated integration
  work) eventually pair with a real LLM summarizer, calendar seam, or
  outreach tracker — with the hard design questions (how keyword frequency
  resists single-message skew, how highlights are selected deterministically,
  what a huddle digest can honestly contain) already resolved and covered by
  `tests/domain/test_summary.py`.
- No new attack surface is introduced: no new network endpoint, no new
  table, no new migration, no RLS change, no outbound network call (no LLM
  API, no calendar API, no CRM API), no change to huddle signaling or media
  behavior. The security review for this task is scoped accordingly — pure
  computation over caller-supplied domain objects, with no I/O.
- The roadmap's R-015 checklist line is intentionally NOT marked "the full
  16-22h AI-summaries/smart-scheduling/outreach-tracking vision shipped" —
  it is marked shipped as THIS scoped extractive-digest seam, exactly as
  O-009/O-010/O-011/R-012/R-013/R-014 were, with the deferred AI-integration,
  calendar-integration, and outreach-tracking halves named above as
  requiring their own dedicated future tasks, not routine follow-ups.
