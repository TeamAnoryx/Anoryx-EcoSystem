# ADR-0002 — Rendly Internal Domain Model (R-002)

- **Status:** Proposed (awaiting Affu approval)
- **Date:** 2026-06-26
- **Task:** R-002 (second Rendly task)
- **Scope:** The canonical, storage-agnostic **internal domain model** — Pydantic v2 types,
  a hand-written JSON Schema, and the integrity invariants. **No server, no persistence, no
  DDL, no migration** (those are R-003 / R-004).
- **Depends on:** merged **R-001** (the LOCKED wire contract — `contracts/openapi.yaml`,
  `contracts/messages.schema.json`, `contracts/ids.md`) and its ADR-0001.
- **Numbering:** Rendly-scoped sequence (this is Rendly ADR **0002**, following 0001), matching
  how each product subtree keeps its own decision record (Sentinel `docs/adr/`, Delta
  `Delta/docs/adr/0001`). Rendly does not extend any global sequence.
- **Deciders:** api-architect (the only agent that edits `Rendly/contracts/**`),
  security-auditor (tenant-isolation focus), Affu (resolved the STEP-0 forks during planning:
  **A = A1**, **B = B1** with `OrgRole = {admin, member, guest}`, **C = R-001-resolved**,
  **D = D1**, **E = E1**).

---

## 1. Context

R-001 locked Rendly's **external wire contract** — what clients see on the wire. R-002 defines
the **internal domain model**: the canonical persistent entities (Tenant, User, Profile, Channel,
Membership), their relationships, and their invariants, **storage-agnostic**. It is the single
source of truth that R-001's wire serializes and that R-004 will persist.

The security-critical job: make **cross-tenant isolation a structural property of the domain
types**, not a runtime check. R-001 flagged (HIGH) that a cross-tenant membership must be
impossible; here that becomes a structural invariant. The model mirrors the proven Delta **D-001**
shape (Pydantic v2 + hand-written Draft 2020-12 JSON Schema + invariants-as-code + tests), and
mirrors Delta's `Transaction` integrity pattern for the cross-entity tenant check.

**The contract is the law.** Every domain entity that surfaces on the wire matches R-001's LOCKED
shapes byte-for-byte; this ADR never redefines them. Where the R-002 dispatch's working language
differed from R-001's committed contract, **R-001 wins** (see §3).

---

## 2. Decisions (the STEP-0 forks)

### FORK A = A1 — identity seam
`User` is **tenant-local**; `tenant_id` is the only ecosystem join key. The O-010 unified-identity
seam (`idp_subject`) stays where R-001 put it — a **token claim** (`AccessTokenClaims`, R-003's
concern), null in R-001 — and is deliberately **not** a field on the persistent `User`.
- *Rejected (A2):* reserve a principal-id field on the domain `User` now. Pre-builds a seam no
  consumer needs; R-001 already reserves it in the token, the correct layer.

### FORK B = B1 — org role: small fixed enum `{admin, member, guest}`
The **per-channel** RBAC role is R-001-locked (`Membership.role = {owner, admin, member, guest}`)
and reused verbatim. The **org-level** role is *not* locked (the token `roles` claim is an open
string array), so R-002 fixes it as a small enum `OrgRole = {admin, member, guest}`, carried as a
field on `Profile` and assigned per-tenant. No Role entity, no join table, no custom roles.
There is deliberately no org-level `owner` — org ownership is not an MVP concept.
- *Rejected (B2):* tenant-definable Role entity (id, name, permission set) + assignment — the
  post-investment RBAC tier (🏦). Heavier surface before any consumer needs it (YAGNI).

### FORK C = R-001-resolved — channel typing + the Delta seam
Mirror R-001's `Channel` verbatim: `type ∈ {public, private, dm}`; the Delta-team auto-mapping
seam is the `source ∈ {manual, delta_team}` discriminator + an opaque nullable `external_ref`
(≤ 64). A normally-constructed channel defaults to `source="manual"`, `external_ref=None`; the
`delta_team` value + `external_ref` are RESERVED for R-006 / D-016 and are never auto-populated.
A model invariant keeps the seam self-consistent: **`external_ref` is non-null IFF
`source == delta_team`**, so a `manual` channel can never carry a mapping pointer.
- *Note:* the dispatch's tentative `delta_team_id` field name and `{direct, role_mapped}` type
  values are **superseded** by R-001's committed `source`/`external_ref` + `{public, private, dm}`.

### FORK D = D1 — "intent" is literal: no Intent entity
In the MVP, "intent" reduces to the User's **org-role + team-affiliation fields ONLY**. There is
**NO Intent entity, NO preference vectors, and NO matching algorithm**. Intent-based matching is
the post-investment B2C tier (R-016 → R-026) and is explicitly deferred. The task name
("Intent + Matching") describes that future tier, not anything implemented here.
- *Rejected (D2):* a reserved Intent value object now. Would imply the MVP does more matching
  than it does — a dishonesty the boundary forbids.

### FORK E = E1 — affiliation fields live on an internal `Profile` superset
R-001's wire `User` exposes **no** role/team/department field, yet the honesty boundary requires
"intent = role + affiliation". The R-002 domain is therefore a strict **superset** of R-001's wire
projection: a separate internal `Profile` carries `org_role` + `team` affiliation that the MVP
wire (R-001 `User`) does **not** expose. These fields are **never serialized through R-001's
closed `User` shape**, so they are **NOT a contract change** to R-001 — R-001's `User` stays the
public projection and R-004 persists the richer `Profile`.
- *Rejected (E2):* domain == wire exactly → no affiliation fields → the honesty boundary collapses
  to "channel membership only".
- *Rejected (E3):* expose affiliation on the wire = a real contract change to merged/locked R-001.

### Tenant + Presence (no fork)
`Tenant` is a minimal root aggregate `{tenant_id, created_at}` — the isolation scoping root (R-001
exposes no tenant name → omitted, YAGNI). `Presence` is the LOCKED 4-value enum
`{online, away, busy, offline}` surfaced as `User.presence`; it is **not** a separately-persisted
entity (presence is realtime state owned by the R-005 runtime, not R-004).

---

## 3. Reconciliation with R-001 (the dispatch's working language vs the locked contract)

R-001 is merged and LOCKED; where it already fixed a representation, that is a constraint, not a
fork. The following dispatch phrasings are superseded by the committed contract and the model
conforms to R-001:

| Topic | Dispatch working language | R-001 LOCKED (used) |
|---|---|---|
| Presence | online/away/offline (3) | `{online, away, busy, offline}` (4) — `User.presence` + `presence_status` |
| Channel type | `{direct, role_mapped, …}` | `{public, private, dm}` |
| Delta seam | reserved `delta_team_id` field | `source ∈ {manual, delta_team}` + opaque `external_ref` |
| Channel role | (unspecified) | `{owner, admin, member, guest}` (`Membership.role`) |

No field that R-001 did not expose is added to any wire shape. The only fields beyond R-001's wire
(`Profile.org_role`, `Profile.team`) are internal-only (FORK E) and never serialize through a
locked shape.

---

## 4. The cross-tenant binding invariant (the security spine)

Every entity is frozen (`ConfigDict(extra="forbid", frozen=True)`) and tenant-scoped. The flat
`Membership` record holds only ids, so the **structural** tenant-equality invariant is enforced by
the canonical construction path `bind_membership(user, channel, role, added_at)`:

1. it requires `user.tenant_id == channel.tenant_id`, else REFUSES (`ValueError`) — nothing is
   constructed;
2. on a valid same-tenant pair it derives every id — including `tenant_id` — **from the validated
   parents**, so the membership's tenant agrees with both the user and the channel **by
   construction, not by a later check**.

The guarantee here is **construction-path** (factory) enforcement, which is weaker than a
model-level validator: Delta D-001's `Transaction` EMBEDS its entries, so a `@model_validator`
can reject a mismatched entry inside the type itself; Rendly's flat `Membership` holds only opaque
ids and cannot self-validate tenant agreement, so the equality is enforced by `bind_membership`,
the canonical construction path. Direct `Membership(...)` with hand-supplied ids is therefore an
**unguarded lower-level primitive** — not tenant-validated, reserved for R-004 rehydrating an
already-tenant-scoped row (where RLS is the boundary). All application code that mints a *new*
membership MUST use `bind_membership`; this is stated in the `Membership` docstring and proven by
`test_direct_membership_construction_is_an_unguarded_primitive`. `bind_profile(user, …)` applies
the same construction-path discipline: `Profile.tenant_id` is read from the `User`.
(`model_construct()` is Pydantic's documented validation-skipping escape hatch and is not a
supported construction path for any of these types.)

---

## 5. Honesty boundary (verbatim, non-removable)

> In the MVP, **"intent" reduces to the User's role + team-affiliation fields only.** There is NO
> matching algorithm, NO preference vectors, and NO Intent entity. Intent-based matching is the
> post-investment B2C tier (R-016 → R-026) and is explicitly deferred.

Additionally: the **Delta-team → channel auto-mapping is a SEAM ONLY** (`source`/`external_ref`
document it; R-006 / D-016 implement it; the domain always constructs `source="manual"` and never
auto-maps). The `Profile` affiliation fields are an **internal superset** over R-001's wire `User`
and are never serialized through the locked `User` shape. Framing is "risk reduction" through
structural integrity, never "blocks all attacks".

---

## 6. Threat model (tenant-isolation focus, with test paths)

| # | Vector | Defense | Test |
|---|---|---|---|
| 1 | **Cross-tenant membership** — a Membership joining a user and channel in different tenants | `bind_membership` rejects `user.tenant_id != channel.tenant_id`; ids derived from validated parents | `test_tenant_scope_invariants.py` |
| 2 | **Cross-tenant profile** — a Profile whose tenant disagrees with its user | `bind_profile` reads `tenant_id` from the `User` (cannot disagree by that path) | `test_tenant_scope_invariants.py` |
| 3 | **Scope-widening via a client tenant field** — a client-shaped `tenant_id` overrides server scope | inherits R-001's property: `tenant_id` is server-resolved; no construction path takes a client-widened tenant | (structural — `ids.md`) |
| 4 | **Mutation back to a bad state** — re-pointing a constructed entity to another tenant | every entity `frozen=True`; normal assignment raises. (A correctness aid on the sanctioned path, not a control against in-process `object.__setattr__`; the security boundary is `bind_membership` + RLS, not immutability.) | `test_tenant_scope_invariants.py` |
| 5 | **Schema permissiveness** — a missing `additionalProperties:false` or unbounded field opens a smuggling / DoS channel | every object closed + every field bounded; extra-key payload rejected | `test_json_schema_contracts.py` |
| 6 | **Parser-differential id** — a non-canonical UUID joins to a different string than the wire | pattern reproduces R-001's wire pattern **byte-for-byte** (rejects no-dash / braces / urn forms); case-folding + nil/`WILDCARD_UUID` semantics are deliberately deferred to the O-010 join per `ids.md` (tightening here would reject a wire-valid id) | `test_identifiers.py` |
| 7 | **Seam smuggling** — a `manual` channel carries a Delta mapping pointer, or the reserved pointer carries an injection payload | `external_ref` non-null IFF `source==delta_team` (model invariant) + `external_ref` charset-bounded `[A-Za-z0-9._:-]` (log-injection defense) | `test_channel.py` |
| 8 | **Implied matching** — the model implies an Intent / matching capability it does not have | no Intent entity / no matching; honesty boundary stated verbatim in spec + ADR | (this ADR §5, schema description) |

---

## 7. Consequences

- **Positive:** cross-tenant isolation is structural (R-001's HIGH finding closed in the model);
  every wire-surfacing type matches the LOCKED contract byte-for-byte; R-004 can map these types to
  storage with no further questions; the dialect + invariant pattern match Delta D-001 so reviewers
  and tooling carry over; honest scope (no matching) is baked into the types and the ADR.
- **Negative / accepted:** the domain is a superset of the wire, so `Profile.org_role`/`team` exist
  in the model but are not on R-001's `User` until a future wire change exposes them; the flat
  `Membership` relies on `bind_membership` (not a `@model_validator`) for the tenant-equality
  invariant because the record holds only ids — direct `Membership(...)` with hand-supplied ids is a
  lower-level primitive (used only for R-004 rehydration from an already-tenant-scoped row).
- **Out of scope (explicit):** server (R-003), persistence / DDL / migrations (R-004), the matching
  engine / Intent graph (R-016+, 🏦), tenant-definable roles (🏦), message domain shapes (owned by
  R-001's `messages.schema.json` + R-005).

---

## 8. CI

The existing `.github/workflows/rendly-ci.yml` lane (`rendly-contracts`, path filter `Rendly/**`,
Python 3.12) is extended: it installs the domain package (`pip install -e ".[dev]"` now pulls
`pydantic`) and runs `pytest --cov=rendly`, which executes **both** the R-001 contract suite and
the R-002 domain suite (invariants + JSON-Schema conformance + examples) and enforces the
`fail_under` coverage gate. The coverage gate makes a domain suite that did not actually run fail
(an uncovered `rendly` package), so the lane provably EXECUTES the domain tests, not skips them
(banked rule 4: CI is authoritative).

---

## 9. Rollback

R-002 is purely additive: a new `Rendly/src/rendly/` package, one new
`Rendly/contracts/rendly-domain.schema.json`, a new `Rendly/tests/domain/` suite, this ADR, a
`pyproject.toml` extension, and a `rendly-ci.yml` step extension. It adds no server, no DB, no
migration, and leaves R-001's `openapi.yaml` / `messages.schema.json` / `ids.md` byte-for-byte
unchanged. Rollback = revert the single squashed R-002 commit; nothing in the monorepo depends on
the package yet, so revert is clean and total.
