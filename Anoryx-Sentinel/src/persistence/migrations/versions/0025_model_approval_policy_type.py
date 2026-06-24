"""Widen ck_policies_policy_type and ck_pv_policy_type to include 'model_approval'.

Revision ID: 0025
Revises: 0024
Create Date: 2026-06-24

F-019 (ADR-0022 §5.1) adds the default-deny model-approval layer. Its per-tenant
switch is a new policy_type 'model_approval' written via
PolicyRepository.create_version. Both ck_policies_policy_type and ck_pv_policy_type
currently allow only ('budget_limit', 'model_allowlist', 'model_denylist',
'code_scan', 'data_lock'), so every model_approval policy write would be a hard DB
rejection — making the entire enforcement feature a permanent production no-op (the
F-016 CRIT-2 failure this migration exists to prevent). This is the FIRST F-019
migration; no enforcement code is wired until the non-stubbed persist->load test
(vector 9) is green against it.

Widens BOTH constraints via DROP+ADD (the established pattern from 0008 onward,
last used by 0022 for 'data_lock'). No data change required — no pre-existing row
uses 'model_approval', so upgrade is loss-free and downgrade is also loss-free
provided no model_approval rows were written after upgrade.

Fully reversible: downgrade() restores the exact prior constraint strings (the
five-type set 0022 created).

Round-trip: upgrade head -> downgrade 0024 -> upgrade head (verified at STEP 9).
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0025"
down_revision: Union[str, None] = "0024"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Constraint names (set in 0004, never renamed).
_CK_POLICIES = "ck_policies_policy_type"
_CK_PV = "ck_pv_policy_type"

# Prior constraint values (the five-type set 0022 created; no migration between
# 0022 and 0025 touched these two constraints).
_OLD_CHECK = (
    "policy_type IN ("
    "'budget_limit', 'model_allowlist', 'model_denylist', 'code_scan', 'data_lock')"
)

# Widened constraint values: add 'model_approval'.
_NEW_CHECK = (
    "policy_type IN ("
    "'budget_limit', 'model_allowlist', 'model_denylist', 'code_scan', "
    "'data_lock', 'model_approval')"
)


def upgrade() -> None:
    # Widen ck_policies_policy_type on the policies table.
    op.drop_constraint(_CK_POLICIES, "policies", type_="check")
    op.create_check_constraint(_CK_POLICIES, "policies", _NEW_CHECK)

    # Widen ck_pv_policy_type on the policy_versions table.
    op.drop_constraint(_CK_PV, "policy_versions", type_="check")
    op.create_check_constraint(_CK_PV, "policy_versions", _NEW_CHECK)


def downgrade() -> None:
    # Restore ck_policies_policy_type to the pre-F-019 five-type set.
    op.drop_constraint(_CK_POLICIES, "policies", type_="check")
    op.create_check_constraint(_CK_POLICIES, "policies", _OLD_CHECK)

    # Restore ck_pv_policy_type to the pre-F-019 five-type set.
    op.drop_constraint(_CK_PV, "policy_versions", type_="check")
    op.create_check_constraint(_CK_PV, "policy_versions", _OLD_CHECK)
