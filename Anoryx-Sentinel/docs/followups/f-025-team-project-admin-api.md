# Follow-up: HTTP admin API for team/project creation (F-025)

**Status:** OPEN — blocked on environment access, not a design gap.
**Severity:** Low (no security issue — a capability gap, not a vulnerability).
**Owner:** api-architect (contracts/openapi.yaml is exclusively theirs to edit —
CLAUDE.md non-negotiable #1).

## The gap

The admin console has full HTTP CRUD-ish routes for **tenants**
(`src/admin/tenants.py`) and **virtual API keys** (`src/admin/keys.py`), but
**no HTTP route exists to create a team or a project.** `POST /admin/tenants/
{tenant_id}/keys` requires an existing `team_id`/`project_id` already present
in the `teams`/`projects` tables (`src/admin/keys.py::_assert_scope_in_tenant`)
— today those rows can only be created via direct repository access (the
compose demo seed, `deploy/seed/seed.py`, or F-025's new
`sentinel-onboarding` CLI, `src/onboarding/sandbox.py`), never over HTTP.

The data-access layer is already complete and tested (F-003b):
`src/persistence/repositories/team_repository.py` and
`.../project_repository.py` both have full `create`/`get_by_id`/
`list_for_*`/`deactivate` methods — this is purely a missing HTTP layer, not
a missing capability underneath.

## Why F-025 didn't close it

F-025 ("self-serve onboarding") needed exactly this gap closed to build a
fully HTTP-driven admin-console wizard. An `api-architect` subagent was
dispatched to add the four missing operations to `contracts/openapi.yaml`
(the only file that would need to change to unblock this — CLAUDE.md
non-negotiable #1 restricts that file to the api-architect role). The agent
correctly refused to edit the file: this environment's `protect-paths-and-
secrets.sh` hook gates `contracts/**` writes on an `ANORYX_ACTIVE_AGENT` env
var that the Claude Code `Agent` tool used in this session does not
propagate to subagents, so no agent — including one literally invoking
itself as api-architect — could satisfy the hook's identity check. The agent
declined to route around this (no Bash-based file write, no hook edits, no
identity spoofing) and instead fully specified the change below so it can be
applied mechanically once that access exists (e.g. a human runs api-architect
directly, or the harness is fixed to propagate `ANORYX_ACTIVE_AGENT`).

**Given this, F-025 shipped as an operator-run CLI
(`sentinel-onboarding`, ADR-0031) that reaches the SAME repositories
directly** — a fully working, tested sandbox-provisioning path today, with
the HTTP-endpoint version captured here for whenever contract access is
available. This is not a security gap: the CLI path uses the exact same
privileged/tenant-session split and the same repositories the HTTP routes
would have used.

## The exact contract change (ready to apply verbatim)

Four new operations in `contracts/openapi.yaml`, inserted between the
tenant `deactivate` block and the `keys` block; new params after
`AdminKeyId`; new schemas after `AdminTenantList`. All `security: [{
adminAuth: [] }]`, all with the `X-Request-Id` response header, all reusing
`#/components/responses/{BadRequest,AdminUnauthorized,NotFound,
TooManyRequests,InternalError}` (400/401/404/429/500) exactly as the
existing tenant/key endpoints do.

| operationId | method + path | request schema | success | list query params |
|---|---|---|---|---|
| `adminCreateTeam` | `POST /admin/tenants/{tenant_id}/teams` | `AdminCreateTeamRequest` | `201` → `AdminTeam` | — |
| `adminListTeams` | `GET /admin/tenants/{tenant_id}/teams` | — | `200` → `AdminTeamList` | `limit`, `offset` |
| `adminCreateProject` | `POST /admin/tenants/{tenant_id}/teams/{team_id}/projects` | `AdminCreateProjectRequest` | `201` → `AdminProject` | — |
| `adminListProjects` | `GET /admin/tenants/{tenant_id}/teams/{team_id}/projects` | — | `200` → `AdminProjectList` | `limit`, `offset` |

New reusable parameter components (mirroring `AdminTargetTenantId` /
`AdminKeyId`):
- `AdminTargetTeamId` — `name: team_id`, `in: path`, `required: true`,
  `schema: {type: string, format: uuid, maxLength: 64}`. A `team_id` not
  belonging to the target tenant returns the uniform `404` (never reveals
  another tenant's team).
- `AdminScopeListLimit` — `name: limit`, `in: query`,
  `schema: {type: integer, minimum: 1, maximum: 500, default: 100}`.
- `AdminScopeListOffset` — `name: offset`, `in: query`,
  `schema: {type: integer, minimum: 0, default: 0}`.
- Reuses the existing `AdminTargetTenantId` for `tenant_id`.

New schema components (field names are final — implement exactly these):

- `AdminCreateTeamRequest` — `additionalProperties: false`, `required: [name]`
  - `name`: `string`, `maxLength: 128`, `pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"`
  - `display_name`: `type: [string, "null"]`, `maxLength: 256` (optional)
- `AdminTeam` — `additionalProperties: false`,
  `required: [team_id, tenant_id, name, display_name, is_active, created_at]`
  - `team_id` str≤64, `tenant_id` str≤64, `name` str≤128,
    `display_name` `[string,"null"]`≤256, `is_active` bool, `created_at` date-time ≤64
- `AdminTeamList` — `required: [teams, count]`; `teams`: array of `AdminTeam`;
  `count`: integer ≥0
- `AdminCreateProjectRequest` — `additionalProperties: false`, `required: [name]`
  - `name`: `string`, `maxLength: 128`, `pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"`
  - `display_name`: `type: [string, "null"]`, `maxLength: 256` (optional)
- `AdminProject` — `additionalProperties: false`,
  `required: [project_id, tenant_id, team_id, name, display_name, is_active, created_at]`
  - `project_id` str≤64, `tenant_id` str≤64, `team_id` str≤64, `name` str≤128,
    `display_name` `[string,"null"]`≤256, `is_active` bool, `created_at` date-time ≤64
- `AdminProjectList` — `required: [projects, count]`; `projects`: array of
  `AdminProject`; `count`: integer ≥0

Two deliberate choices flagged by api-architect, worth revisiting when this
lands:
1. `display_name` in the two create-request bodies is `type: [string,
   "null"]` — a minor divergence from `AdminCreateTenantRequest`, whose
   `display_name` is plain `string`. Confirm whether to align with the
   tenant precedent instead.
2. `AdminTeam` / `AdminProject` omit `updated_at` (unlike `AdminTenant`)
   because the repositories return `created_at` only today.

## Implementation once the contract lands

`src/admin/teams.py` + `src/admin/projects.py`, mirroring
`src/admin/tenants.py` / `src/admin/keys.py` exactly: RLS tenant session
(`get_tenant_session`), `TeamRepository`/`ProjectRepository` (already
exist), mounted onto `admin_router` in `src/admin/router.py`. A new ADR
(`docs/adr/0032-*.md` or the next available number) should accompany it,
and — per the existing 4-site consistency pattern (ADR-0023 §5.4) — if these
actions should be audited, that ALSO needs: a new Alembic migration
widening `ck_eal_event_type`, `VALID_EVENT_TYPES`/`ACTION_TAKEN_BY_EVENT_TYPE`
in `src/persistence/models/events_audit_log.py`, `ADMIN_EVENT_TYPES` in
`src/admin/audit.py`, and the corresponding event `$def`s in
`contracts/events.schema.json` (also api-architect-owned).
