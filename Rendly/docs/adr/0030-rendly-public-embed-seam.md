# ADR-0030 — Public Embedding API + Developer Portal: a Permission-Gated Embed-Grant + Public-Safe Manifest Seam (R-030)

Status: Accepted
Date: 2026-07-11
Builds on: ADR-0013 (`event.py`'s deterministic, single-host agenda-scheduling
seam over `Event`/`EventSession`, R-013), ADR-0027 (`platform_rbac.py`'s fixed
`OrgRole` -> `PlatformPermission` matrix + its cross-tenant fail-loud guard,
R-027), ADR-0028/ADR-0029 (this tier's "reuse an EXISTING `PlatformPermission`
member, never widen the enum" discipline, R-028/R-029), the R-008 data-
sovereignty honesty boundary ("logs/transcripts/records never leave company
control"), and the whole post-investment tier's established "scoped seam,
ADR-disclosed limitation, honesty boundary" discipline (ADR-0012, ADR-0016
through ADR-0029).

## Context

The roadmap names R-030 "Public embedding API + developer portal
🏦 POST-INVESTMENT", the fourth and final task of Rendly's Phase 4
"Platform-as-a-Service (VISION)" tier — the first still-unchecked `R-` line in
`anoryx-ecosystem-roadmap-v3.md`'s checklist as of this run (R-001
through R-029 are all checked). Like every task in this tier, R-030 is not
given its own descriptive paragraph — it appears only as a name in the tier's
shared task list, with the shared estimate/dependency/risk line ("~12-22h
each · Depends on: R-005/R-007/R-008 + Delta · Risk: Medium-High"). This run
resolves that absence of detail the same way every prior unattended run in
this tier has: the most conservative, smallest honestly-buildable reading,
named explicitly, with no scope widening to fill in the blanks.

"Public embedding API + developer portal" as a full PaaS primitive is a large
product space (third-party app registration, a persisted/rotatable API-key
system, rate limiting, a self-serve developer-portal UI with docs, and a real
unauthenticated HTTP surface). This codebase already has a real piece this
task can compose against without inventing any of that: `event.py`'s `Event`/
`EventSession` (R-013) is a deterministic, single-host agenda — title and
time-boxed sessions — that is *already* public-facing metadata in shape (a
schedule, not a transcript), the natural thing a company would want to embed
on its own marketing site (e.g. "upcoming webinars"). `platform_rbac.py`
(R-027) already supplies a fixed, checkable tenant-level permission a caller
can be required to hold before authorizing that exposure.

## Decision — resolved forks

### Fork A — what can ever be embedded: **A1 (only `event.Event`/`EventSession` agenda metadata — NOT `channel.Channel` or any of its message/roster content)**

An `EmbedGrant` (below) can only ever be constructed by naming an `Event`; there
is no code path in this module that accepts a `Channel`. R-008 already
committed Rendly to a zero-trust promise: "logs/transcripts/records never
leave company control" — the whole reason Rendly exists instead of Slack/
Teams/Zoom. Embedding actual chat messages, channel rosters, or huddle content
on a third-party page would directly contradict that promise, no matter what
authorization gate surrounded it. An event's agenda (title + time window) is
scheduling metadata equivalent to a public calendar listing, not a
communications transcript, so it is the only object this module is willing to
expose.

Rejected: A2 (allow embedding `channel.Channel` messages/rosters, gated by
permission). Authorization is the wrong tool for a promise this codebase has
already made unconditional — R-008's data-sovereignty guarantee is not "never
leaves, unless an admin says otherwise." Out of this task's license
regardless of any gate.

### Fork B — the credential shape: **B1 (a NEW, minimal, non-persisted `EmbedGrant` capability object — event + validity window only — NOT a persisted, revocable API-key/developer-app system)**

`public_embed.py` ships `EmbedGrant` (a plain, caller-managed value: `grant_id`,
`tenant_id`, `event_id`, `issued_at`, `expires_at`) plus `issue_embed_grant`
(the permission-gated minting path) and `render_embed_manifest` (the public-safe
projection). The full "developer portal" vision needs third-party app
registration, key issuance/rotation/revocation, rate limiting, and a self-serve
UI — a large, separate, persistence-and-REST-heavy feature. What this task can
honestly ship now is the authorization-and-projection core such a system would
need underneath: who may authorize an embed, what expires, and what data a
manifest may honestly contain — exactly the same "prove the domain seam before
the infrastructure" move `workspace.py` (R-029) and `talent_routing.py` (R-028)
already made for their own tiers.

Rejected: B2 (build a real persisted API-key/developer-app table + FastAPI
router now). Same rejection every predecessor task in this tier already gives:
no product signal yet to justify the persistence/REST/UI investment ahead of
the MVP tracks + funding; this task instead proves the domain-authorization
seam a future task can wire into a real endpoint.

### Fork C — the unrevocable-credential risk: **C1 (`EmbedGrant.expires_at` MUST be within `MAX_EMBED_GRANT_LIFETIME` (90 days) of `issued_at` — enforced unconditionally by the model itself, `ValidationError` otherwise)**

Because Fork B deliberately ships no persistence, this module also has no
revocation mechanism — a `grant_id`, once handed to a caller, cannot later be
invalidated by this codebase. An unbounded expiry would leave a leaked
`grant_id` a permanently valid public read with no way to shut it off. Bounding
lifetime is a real, always-applicable security property this module can close
for free, not a deferred nice-to-have gated on the future key-store existing.

Rejected: C2 (unbounded/no expiry ceiling, leaving revocation entirely to a
future persisted key-store). Would leave every grant issued by this run's
callers permanently exploitable if leaked, for a mitigation ADR-0029/ADR-0027's
own "bounded-list" precedent already shows costs nothing to add now.

### Fork D — the authorization gate: **D1 (reuse R-027's EXISTING `PlatformPermission.MANAGE_TENANT_CHANNELS` — no new permission)**

Authorizing a piece of tenant content to be exposed *publicly*, to parties
entirely outside the tenant's own membership, is a content-administration
decision — the same shape `MANAGE_TENANT_CHANNELS`'s existing docstring already
claims ("administers how tenant content/membership is organized... channel
ADMINISTRATION actions"), just applied to an `Event` instead of a `Channel`.
Of `platform_rbac.py`'s three existing permissions it is the closest fit:
`VIEW_TENANT_AUDIT_LOG` is read-only oversight, not an authorize-to-expose
action, and `MANAGE_TENANT_MEMBERS` is roster administration, unrelated to
content exposure. Because the R-027 matrix is a two-tier ALL-or-NOTHING grant
(`ADMIN` holds every permission, `MEMBER`/`GUEST` hold none), this decision is
in practice "only a tenant admin may authorize a public embed" — the
conservative default this task should have regardless of which specific
existing member names it.

Rejected: D2 (add a new `PlatformPermission.AUTHORIZE_PUBLIC_EMBED` member).
Same rejection ADR-0028 Fork B / ADR-0029 Fork D already gave: would widen
R-027's closed enum and fixed matrix for a capability already expressible with
an existing member; a future task needing a finer-grained split (e.g.
distinguishing "may administer channels" from "may authorize public embeds")
can add that member then, against a real product requirement.

### Fork E — the cross-tenant/cross-event/expiry guard: **E1 (every function RAISES `ValueError`/`PermissionError` on ANY cross-tenant/cross-event mismatch or inactive grant — never a silent empty/None result)**

Mirrors the EXISTING precedent in `platform_rbac.resolve_platform_permissions`
(ADR-0027 Fork D), `talent_routing.py` (ADR-0028 Fork C), and `workspace.py`
(ADR-0029 Fork E): a caller passing a mismatched tenant/event/grant together,
or asking for a manifest outside a grant's validity window, is either a caller
bug or an authorization failure — never a security decision this module is
positioned to make quietly by returning an empty manifest that looks
indistinguishable from "this event legitimately has no sessions."

Rejected: E2 (silently return an empty/`None` manifest for an expired or
mismatched grant). Would hide an authorization failure behind ordinary-looking
"nothing to show" output — the same rejection ADR-0028 Fork C and ADR-0029
Fork E already gave for their own silent-drop alternatives.

## What is deliberately NOT built here (named, not silently skipped)

- **No developer portal.** No self-serve UI, no third-party app registration,
  no API-key issuance/rotation/rate-limiting, no usage dashboards, no docs
  site. See Fork B.
- **No public embedding API / REST surface.** `contracts/openapi.yaml` is
  unchanged; nothing unauthenticated (or authenticated) can reach this module
  from the network today. See Fork B.
- **No persisted, revocable credential system.** `EmbedGrant` is a pure,
  caller-managed value — no new table, no new migration, no key store, no
  revocation list (compensated for by the bounded lifetime in Fork C).
- **No embedding of `channel.Channel` content.** Only `event.Event`/
  `EventSession` may ever be named in a grant. See Fork A.
- **No new `PlatformPermission` member.** Reuses R-027's existing
  `MANAGE_TENANT_CHANNELS` — `platform_rbac.py`'s closed enum and matrix are
  unchanged. See Fork D.
- **No persistence.** This is a pure function of caller-supplied `Tenant`,
  `Profile`, `Event`, and `EventSession` objects — no new table, no new
  migration, no RLS change.

## Consequences

- Rendly gains its first public-egress-shaped authorization primitive: a
  time-bounded capability naming exactly one already-public-in-shape resource
  (an event's schedule), built to compose cleanly with a future REST endpoint
  without that endpoint needing to reinvent any of this module's guards.
- No new attack surface is introduced: no new network endpoint, no new table,
  no new migration, no RLS change, and no widened enum. The one genuinely new
  risk this module introduces — an unrevocable public capability — is closed
  by a mandatory, model-enforced lifetime ceiling rather than left to a future
  task or to caller discipline.
- The R-008 data-sovereignty commitment is reinforced, not weakened: this
  module structurally cannot construct a grant over channel/comms content,
  so a future REST/developer-portal layer built on top of this seam inherits
  that same restriction rather than having to reimplement it.
- The roadmap's R-030 checklist line — and with it, the entire "PaaS track"
  (R-027 through R-030) and Rendly's full 30-task roadmap — is intentionally
  NOT marked "the full real embedding API + developer portal shipped"; it is
  marked shipped as THIS scoped grant + manifest seam, exactly as R-012/R-016
  through R-029 were, with every deferred piece named above as the obvious
  next slice for a future, separately-dispatched (and, per the roadmap's own
  gating, funded) task.
