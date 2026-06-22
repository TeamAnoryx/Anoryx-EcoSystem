"""Widen ck_policies_policy_type and ck_pv_policy_type to include 'code_scan'.

Revision ID: 0021
Revises: 0020
Create Date: 2026-06-22

F-016 CRIT-2 fix: the code-scan detector (src/code_scan/) calls
PolicyRepository.upsert_policy with policy_type='code_scan', but both
ck_policies_policy_type and ck_pv_policy_type only allowed the original
three types ('budget_limit', 'model_allowlist', 'model_denylist'), making
every code_scan policy write a hard DB rejection. The detector was a permanent
production no-op as a result.

This migration widens BOTH constraints via DROP+ADD (the established pattern
from 0008 onward for constraint widening). No data change required — no
pre-existing row uses 'code_scan', so upgrade is loss-free and downgrade is
also loss-free provided no code_scan rows were written after upgrade.

Fully reversible: downgrade() restores the exact prior constraint strings
(the three-type set that 0004 created and no later migration changed).

Round-trip: upgrade head -> downgrade 0020 -> upgrade head.
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0021"
down_revision: Union[str, None] = "0020"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Constraint names (set in 0004, never renamed).
_CK_POLICIES = "ck_policies_policy_type"
_CK_PV = "ck_pv_policy_type"

# Prior constraint values (0004 original; no migration between 0004 and 0021
# touched these two constraints — verified by reading 0005-0020).
_OLD_POLICIES_CHECK = "policy_type IN ('budget_limit', 'model_allowlist', 'model_denylist')"
_OLD_PV_CHECK = "policy_type IN ('budget_limit', 'model_allowlist', 'model_denylist')"

# Widened constraint values: add 'code_scan'.
_NEW_POLICIES_CHECK = (
    "policy_type IN ('budget_limit', 'model_allowlist', 'model_denylist', 'code_scan')"
)
_NEW_PV_CHECK = "policy_type IN ('budget_limit', 'model_allowlist', 'model_denylist', 'code_scan')"


def upgrade() -> None:
    # Widen ck_policies_policy_type on the policies table.
    op.drop_constraint(_CK_POLICIES, "policies", type_="check")
    op.create_check_constraint(_CK_POLICIES, "policies", _NEW_POLICIES_CHECK)

    # Widen ck_pv_policy_type on the policy_versions table.
    op.drop_constraint(_CK_PV, "policy_versions", type_="check")
    op.create_check_constraint(_CK_PV, "policy_versions", _NEW_PV_CHECK)


def downgrade() -> None:
    # Restore ck_policies_policy_type to the pre-F-016 three-type set.
    op.drop_constraint(_CK_POLICIES, "policies", type_="check")
    op.create_check_constraint(_CK_POLICIES, "policies", _OLD_POLICIES_CHECK)

    # Restore ck_pv_policy_type to the pre-F-016 three-type set.
    op.drop_constraint(_CK_PV, "policy_versions", type_="check")
    op.create_check_constraint(_CK_PV, "policy_versions", _OLD_PV_CHECK)
