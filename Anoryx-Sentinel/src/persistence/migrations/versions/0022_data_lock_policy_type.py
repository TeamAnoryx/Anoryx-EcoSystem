"""Widen ck_policies_policy_type and ck_pv_policy_type to include 'data_lock'.

Revision ID: 0022
Revises: 0021
Create Date: 2026-06-23

F-017 (ADR-0020 §6) adds the data-lock detector (src/data_lock/), which calls
PolicyRepository.upsert_policy with policy_type='data_lock'. Both
ck_policies_policy_type and ck_pv_policy_type currently allow only
('budget_limit', 'model_allowlist', 'model_denylist', 'code_scan'), so every
data_lock policy write would be a hard DB rejection and the detector would be a
permanent production no-op — exactly the F-016 CRIT-2 failure this migration
exists to prevent.

This migration widens BOTH constraints via DROP+ADD (the established pattern
from 0008 onward, last used by 0021 for 'code_scan'). No data change required —
no pre-existing row uses 'data_lock', so upgrade is loss-free and downgrade is
also loss-free provided no data_lock rows were written after upgrade.

Fully reversible: downgrade() restores the exact prior constraint strings
(the four-type set that 0021 created).

Round-trip: upgrade head -> downgrade 0021 -> upgrade head (verified at STEP 10).
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0022"
down_revision: Union[str, None] = "0021"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Constraint names (set in 0004, never renamed).
_CK_POLICIES = "ck_policies_policy_type"
_CK_PV = "ck_pv_policy_type"

# Prior constraint values (the four-type set 0021 created; no migration between
# 0021 and 0022 touched these two constraints).
_OLD_CHECK = "policy_type IN ('budget_limit', 'model_allowlist', 'model_denylist', 'code_scan')"

# Widened constraint values: add 'data_lock'.
_NEW_CHECK = (
    "policy_type IN ("
    "'budget_limit', 'model_allowlist', 'model_denylist', 'code_scan', 'data_lock')"
)


def upgrade() -> None:
    # Widen ck_policies_policy_type on the policies table.
    op.drop_constraint(_CK_POLICIES, "policies", type_="check")
    op.create_check_constraint(_CK_POLICIES, "policies", _NEW_CHECK)

    # Widen ck_pv_policy_type on the policy_versions table.
    op.drop_constraint(_CK_PV, "policy_versions", type_="check")
    op.create_check_constraint(_CK_PV, "policy_versions", _NEW_CHECK)


def downgrade() -> None:
    # Restore ck_policies_policy_type to the pre-F-017 four-type set.
    op.drop_constraint(_CK_POLICIES, "policies", type_="check")
    op.create_check_constraint(_CK_POLICIES, "policies", _OLD_CHECK)

    # Restore ck_pv_policy_type to the pre-F-017 four-type set.
    op.drop_constraint(_CK_PV, "policy_versions", type_="check")
    op.create_check_constraint(_CK_PV, "policy_versions", _OLD_CHECK)
