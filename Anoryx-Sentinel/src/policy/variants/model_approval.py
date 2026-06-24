"""ModelApprovalPolicy typed view (ADR-0022 §5.1).

F-019 default-deny model governance. UNLIKE the F-008 model_allowlist (opt-in —
absence of a matching allow-list means *not constrained*), the *presence* of an
active model_approval policy for a request's scope flips that tenant to
**default-deny**: a model is usable only if its row in the per-tenant
`model_inventory` is in state 'approved'. pending / denied / unknown → DENY
(resolved in src/policy/enforcement.py, STEP 5).

This policy is the per-tenant SWITCH, not the per-model state. It carries the four
scope IDs (matched wildcard-aware, exactly like the model_allowlist/denylist views)
and an explicit `enforcement_mode` marker; the pending/approved/denied state lives
in the inventory table, never here. Minimal by design (D2): no per-model fields, no
multi-approver metadata.

Like the other variant views this uses ConfigDict(extra="ignore"): it is built from
the FULL stored record (policies.policy_payload), which carries common fields
(signature, effective_from, etc.) the view does not model. The closed intake schema
(additionalProperties:false) already rejected unknown fields before storage.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class ModelApprovalPolicy(BaseModel):
    """Typed view of a validated model_approval policy payload (the default-deny switch)."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    policy_id: str
    tenant_id: str
    team_id: str
    project_id: str
    agent_id: str
    policy_version: int
    # Explicit, validated marker. Const "default_deny" in v1 — the only mode this
    # policy expresses. Stored in the payload so the intent is auditable and the
    # enforcement branch can assert it rather than inferring meaning from presence.
    enforcement_mode: str = "default_deny"
    # NO effective_until: a default-deny SWITCH has no meaningful time-bound expiry,
    # and reusing the allow-list's expiry parser here would be FAIL-OPEN — a malformed
    # stored date would silently disable the gate (a security-critical regression).
    # The policy is active whenever it matches the scope; removal turns the gate off
    # explicitly. (code-review MED fix — ADR-0022 R3 fail-closed.)
