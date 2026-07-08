# ADR-0031 — Self-Serve Onboarding (F-025)

- Status: Accepted (implemented, scope-narrowed — see "Scoping decision" below)
- Date: 2026-07-08
- Builds on: ADR-0014 (F-012a admin console API — the tenant/key routes and
  session-splitting pattern this ADR's CLI reuses verbatim), ADR-0009 (F-008
  policy intake — the signed-record trust model this ADR's sample policy
  templates deliberately do NOT bypass), ADR-0005/F-003b (tenant isolation —
  `TeamRepository`/`ProjectRepository`, already complete at the data-access
  layer before this ADR).
- Scope: `src/onboarding/` (new — a CLI, not an HTTP surface),
  `deploy/onboarding/` sample content, `deploy/ONBOARDING.md`. **No
  `contracts/` change** — see the scoping decision.

## Context

Roadmap F-025: "Trial signup, guided wizard, sample policies/API calls vs
sandbox tenant." Before writing any code, a repo-wide read of the existing
tenant/auth model found two facts that change what "self-serve" can honestly
mean here:

1. **There is no self-service principal at all.** Every `/admin/*` route is
   gated by `require_admin` (`src/admin/auth.py`), which accepts exactly two
   credential kinds — a single deploy-injected `SENTINEL_ADMIN_TOKEN`
   break-glass token, or an enterprise-SSO **operator** session
   (`contracts/openapi.yaml` states outright: "v1 is single-operator"). A
   genuinely public, unauthenticated "sign up for a trial" endpoint would be
   an entirely new trust boundary on a product whose own CLAUDE.md opens
   with "it is ITSELF a security product... build accordingly" — not a
   narrow feature addition.
2. **Minting a working virtual API key requires a team + project row that
   already exists**, and there is no HTTP route to create either — only
   `TenantRepository`/`TeamRepository`/`ProjectRepository` at the data-access
   layer (all F-003b, all complete), never wired to `/admin/*`.

## Scoping decision

Given (1), this ADR does **not** build a public signup endpoint. The
guided-provisioning flow is **operator-run** (an `sentinel-onboarding` CLI,
same trust tier as `sentinel-cli`/`sentinel-dr` — someone with cluster/env
access, not an anonymous visitor), consistent with how ADR-0028 and
ADR-0030 both keep their own highest-blast-radius actions
(region-failover promotion; database restore) human-triggered rather than
automated. "Trial signup" is read here as "an operator can stand up a
tight, pre-capped sandbox tenant in one guided step" — not literal public
self-registration. This is the conservative reading recommended by the
pre-implementation research and is the single biggest scoping call in this
ADR; flagging it explicitly rather than silently narrowing the roadmap line.

Given (2), closing the team/project HTTP gap would have been the natural way
to build a fully browser-driven wizard. Doing so requires editing
`contracts/openapi.yaml`, which CLAUDE.md non-negotiable #1 restricts to the
`api-architect` role. An `api-architect` subagent was dispatched with a full
spec (see `docs/followups/f-025-team-project-admin-api.md`) and correctly
**refused** to make the edit: this session's `protect-paths-and-secrets.sh`
hook gates `contracts/**` on an `ANORYX_ACTIVE_AGENT` identity that the
`Agent`-tool subagent path here does not propagate — so no agent, including
one invoked specifically as api-architect, could satisfy the hook. The agent
did not attempt to route around this (no raw-Bash file write, no hook edit,
no identity spoofing), and neither did this implementation. The full
four-operation contract spec is preserved verbatim in the followup doc so it
applies mechanically once that access exists — this is a real, narrow,
low-risk gap-fill for a future session, not lost work.

**Given both constraints, F-025 ships as: an operator CLI that provisions a
sandbox tenant by calling the exact same repositories the (not-yet-existing)
HTTP routes would have called, plus a sample-policy template library that
uses F-008's existing signed-intake path unmodified, plus a runbook.**

## Decision

### 1. `sentinel-onboarding` CLI (`src/onboarding/`)

`sentinel-onboarding sandbox create --name <name> [--write-templates <dir>]`
(`src/onboarding/cli.py`) calls `provision_sandbox()`
(`src/onboarding/sandbox.py`), which:

- Creates a tenant on the privileged session (`TenantRepository.create`,
  exactly `admin/tenants.py::create_tenant`'s call), emitting the EXISTING
  `admin_tenant_created` audit event.
- Creates a team + project + mints a virtual API key on the new tenant's RLS
  session (`TeamRepository.create`, `ProjectRepository.create`,
  `VirtualApiKeyRepository.create` — exactly `admin/keys.py::mint_key`'s
  call), emitting the EXISTING `admin_key_minted` audit event.
- **No new audit event type is introduced.** Team/project creation is not
  audited by this CLI, because it is not audited anywhere else in the
  codebase either (there is no HTTP route to compare against) — this ADR
  does not invent an unreviewed event type to cover a gap that predates it.
  `docs/followups/f-025-team-project-admin-api.md` notes that the eventual
  HTTP version should decide whether to add one (a 4-site consistency change
  — migration, model constant, admin/audit.py, events.schema.json — the same
  pattern ADR-0023 §5.4 established).
- `actor_id` is always `None` (the same value break-glass admin actions
  already use when there is no SSO operator session) — an honest
  attribution, not a new one.

The plaintext key is printed to stdout exactly once (mirroring
`admin/keys.py::mint_key`'s "returned exactly once" contract) alongside a
ready-to-run sample `curl /v1/chat/completions` command using the sandbox's
real tenant/team/project/agent IDs.

### 2. Sample policy templates (`src/onboarding/templates.py`)

Two RAW (unsigned) F-008 policy records — a daily `budget_limit` token cap
and a small `model_allowlist` — generated with the new sandbox's real
`tenant_id`. **Deliberately not auto-signed or auto-pushed**: F-008's trust
model is that a policy is signed by whoever holds the private signing key
(normally Delta/Orchestrator, or an operator's own keypair via `sentinel-cli
policy keygen`); fabricating an unsigned push path inside the admin/
onboarding surface would undermine the exact boundary F-008 exists to
enforce (the "CRIT-2 cautionary tale" the roadmap already flags once —
this ADR does not create a second instance of it). `--write-templates
<dir>` writes the two JSON files to disk; the CLI prints the exact
`sentinel-cli policy push --file ... --key ...` commands to run next — the
existing, unmodified sign+push flow (ADR-0009 §11).

### 3. Runbook (`deploy/ONBOARDING.md`)

Mirrors `deploy/MULTI-REGION.md` / `deploy/DISASTER-RECOVERY.md`'s format:
architecture, prerequisites, the guided-create walkthrough, pushing the
sample policies, a sample API call, and an explicit "what this does and
does not claim" section.

## Honest limitations

- Not public self-serve signup — operator-run only (see "Scoping decision").
- The sample `/v1/chat/completions` call only succeeds if the deployment has
  a real upstream provider configured (`UPSTREAM_BASE_URL` / `ANTHROPIC_API_KEY`
  / `AWS_*`) — there is no mock/echo provider (none exists in the gateway
  today; building one was out of this ADR's scope). The CLI's printed
  summary says this plainly rather than implying a zero-config demo.
- Sample policies are templates, not automatically enforced — a sandbox
  tenant has NO budget/model cap until the operator signs and pushes them.
  `deploy/ONBOARDING.md` states this as step 1, not an afterthought.
- Team/project creation is unaudited (see §1) — a narrow, pre-existing gap,
  not introduced here, tracked in the followup doc.
- `provision_sandbox()` is not atomic across its two sessions (tenant-create,
  then team/project/key-create) — this is the SAME two-step shape
  `admin/tenants.py` + `admin/keys.py` already have as separate HTTP calls;
  a failure between them leaves a tenant with no team/project/key, visible
  via the existing `GET /admin/tenants`. `tenants.name` has no uniqueness
  constraint, so a retry with the same name creates a second, distinct
  tenant rather than erroring — cleaning up an orphaned partial tenant is an
  operator decision, not something this function detects automatically.
