# Anoryx EcoSystem — Engineering Standards (Monorepo Root)

## Ecosystem structure

| Folder                  | Product                             | Status      |
|-------------------------|-------------------------------------|-------------|
| Anoryx-Sentinel/        | Zero-trust AI gateway (BUILD FIRST) | Active MVP  |
| Anoryx-AI-Orchestrator/ | Central AI orchestration layer      | Hooks only  |
| Delta/                  | FinOps / ERP / budget policy        | Placeholder |
| Rendly/                 | TBD                                 | Placeholder |

Build Sentinel first. Every other product integrates with it.

## Cross-project rules (hooks enforce these — not suggestions)

- Never write application code at the monorepo root. Root = config + CI only.
- Agents stay inside their assigned subproject. The protect-paths hook blocks
  unauthorized cross-project writes.
- Secrets live in GitHub Secrets / Vault / root .env (gitignored, hook-protected).
  Never inside any subproject folder. Never in git.
- .claude/ at root serves ALL four products. Changes to it affect the entire ecosystem.

## The contract is the law

Anoryx-Sentinel/contracts/openapi.yaml is the single source of truth for Sentinel's API.
Only the api-architect agent edits it. All builders conform to it.
When Delta and Anoryx-AI-Orchestrator consume Sentinel events, they conform to
Anoryx-Sentinel/contracts/events.schema.json. That file is the integration contract.

## Honest language (mandatory everywhere across the ecosystem)

"audit-ready" not "compliant"  |  "risk reduction" not "blocks all attacks"
"high-coverage detection" not "100% detection"  |  "likely defect" not "bug-free"
"client-side cost estimate" when referencing total_cost_usd

## Ecosystem data flow

Sentinel → (events) → Anoryx-AI-Orchestrator → (cost/risk data) → Delta
Delta → (budget policies) → Anoryx-AI-Orchestrator → (enforcement) → Sentinel
The killer feature: financial policy enforced in the security path.
