---
name: new-feature
description: Start a Sentinel feature task. Runs: Cartographer → builder → oversight loop.
---
Given task: $ARGUMENTS

1. Use cartographer to get a context pack (paths are in Anoryx-Sentinel/).
2. Identify the builder agent (gateway feature → gateway-core, PII → data-protection, etc.)
3. Tell the builder: "Implement: $ARGUMENTS
   Context pack: [paste cartographer output]
   Work in Anoryx-Sentinel/src/. Conform to Anoryx-Sentinel/contracts/openapi.yaml.
   Write tests in Anoryx-Sentinel/tests/. Do not stop until tests pass."
4. Invoke code-reviewer on the diff (git diff main...HEAD).
5. Invoke security-auditor on the diff. If Critical → stop, print ⛔ HUMAN ESCALATION.
6. Invoke test-engineer to verify tests exist and pass.
7. Invoke pr-gate for the final verdict.
