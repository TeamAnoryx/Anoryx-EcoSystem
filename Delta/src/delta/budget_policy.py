"""Budget *policy* document — the Delta-side layer above D-001's ``BudgetConcept``
(D-002, ADR-0002).

A :class:`BudgetPolicy` bundles a hard cap (the D-001 :class:`delta.budget.
BudgetConcept`, the ONLY part that serializes) with advisory soft-warning /
escalation tiers and the policy envelope (``policy_id``, ``policy_version``,
``effective_from``). Its emit path :meth:`BudgetPolicy.to_policy_payload`
serializes the hard cap, byte-valid, into Sentinel's LOCKED ``BudgetLimitPolicy``
variant by reusing D-001's :func:`delta.attribution.
budget_concept_to_policy_payload`.

HONESTY BOUNDARY (Fork 1 = (b), ADR-0002): soft-warning thresholds and
escalation tiers are **Delta-advisory only**. They live in Delta types, they are
**never serialized** into the signed policy, and **Sentinel never sees or
enforces them**. Nothing acts on a warning tier until D-005 (the budget engine)
wires it to the orchestrator/notify path; here a tier is a declared *intent*, not
an enforced behavior. The locked variant is ``additionalProperties:false``, so an
accidental leak of a warning key would also *fail* validation — but the emit path
drops warnings by construction, not by luck.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from .attribution import budget_concept_to_policy_payload
from .budget import BudgetConcept
from .identifiers import UuidStr
from .money import (
    MAX_BUDGET_COST_CENTS,
    bounded_count,
    reject_non_integer,
    require_aware_utc,
)

# Locked-schema envelope bound (mirrors policy.schema.json policy_version: 2**53-1,
# JS Number.MAX_SAFE_INTEGER). The emit builder re-validates this; held here too so
# an invalid BudgetPolicy cannot be constructed.
MAX_POLICY_VERSION = 9007199254740991

# Warning-threshold percent bounds. 100% IS the hard cap, not a warning, so the
# upper bound is 99 (a warning must trip strictly before the cap).
_MIN_WARNING_PERCENT = 1
_MAX_WARNING_PERCENT = 99


class WarningAction(StrEnum):
    """Advisory escalation label carried on a warning tier.

    DELTA-ADVISORY ONLY: Sentinel never receives this value and nothing enforces
    it. It records the operator's *intent* at a threshold; the wiring that turns
    it into a real notification/throttle is D-005.
    """

    NOTIFY = "notify"
    ALERT = "alert"
    PAGE = "page"


class BudgetWarningTier(BaseModel):
    """One soft-warning tier: a threshold (percent XOR absolute cents) + an action.

    Exactly one of ``threshold_percent`` / ``threshold_cost_cents`` is set. The
    tier is advisory — it does not enter the signed policy.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    threshold_percent: int | None = None
    threshold_cost_cents: int | None = None
    action: WarningAction

    @field_validator("threshold_percent", mode="before")
    @classmethod
    def _percent(cls, value: object) -> object:
        if value is None:
            return None
        value = reject_non_integer(value, "threshold_percent")
        if not _MIN_WARNING_PERCENT <= value <= _MAX_WARNING_PERCENT:
            raise ValueError(
                "threshold_percent must be in [1, 99] (100% is the cap, not a warning)"
            )
        return value

    @field_validator("threshold_cost_cents", mode="before")
    @classmethod
    def _absolute(cls, value: object) -> object:
        if value is None:
            return None
        value = bounded_count(value, "threshold_cost_cents", MAX_BUDGET_COST_CENTS)
        if value < 1:
            raise ValueError("threshold_cost_cents must be >= 1")
        return value

    @model_validator(mode="after")
    def _exactly_one_basis(self) -> "BudgetWarningTier":
        has_percent = self.threshold_percent is not None
        has_absolute = self.threshold_cost_cents is not None
        if has_percent == has_absolute:
            raise ValueError(
                "a warning tier must set exactly one of threshold_percent or threshold_cost_cents"
            )
        return self

    @property
    def basis(self) -> str:
        """``"percent"`` or ``"absolute"`` — the threshold's denomination."""
        return "percent" if self.threshold_percent is not None else "absolute"

    @property
    def order_value(self) -> int:
        """The basis-native magnitude used to order tiers within a policy."""
        # _exactly_one_basis guarantees exactly one threshold is set, so the
        # absolute branch never returns None at runtime.
        if self.threshold_percent is not None:
            return self.threshold_percent
        return self.threshold_cost_cents  # type: ignore[return-value]


class BudgetPolicy(BaseModel):
    """A Delta budget-policy document: a hard cap + advisory warnings + envelope.

    Only ``cap`` serializes (see :meth:`to_policy_payload`). ``warnings`` are
    Delta-advisory and never reach Sentinel. ``signature`` is NOT held here — it
    is produced by the signer (Delta/Orchestrator) and supplied at emit time.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    cap: BudgetConcept
    policy_id: UuidStr
    policy_version: int
    effective_from: datetime
    # tuple, not list: a frozen model does not deep-freeze a mutable list (D-001 H-1).
    warnings: tuple[BudgetWarningTier, ...] = ()

    @field_validator("policy_version", mode="before")
    @classmethod
    def _version(cls, value: object) -> int:
        value = reject_non_integer(value, "policy_version")
        if not 1 <= value <= MAX_POLICY_VERSION:
            raise ValueError("policy_version must be in [1, 2**53-1] (locked schema bound)")
        return value

    @field_validator("effective_from")
    @classmethod
    def _effective_from_aware(cls, value: datetime) -> datetime:
        return require_aware_utc(value, "effective_from")

    @model_validator(mode="after")
    def _warnings_sound(self) -> "BudgetPolicy":
        """Enforce the Fork-1 warning soundness rules (ADR-0002).

        These are cross-field invariants not expressible in JSON Schema alone:
        a homogeneous basis (so a total order exists), strictly ascending tiers
        with no duplicates, and — for an absolute basis — a cost cap that every
        threshold trips strictly below.
        """
        if not self.warnings:
            return self

        bases = {w.basis for w in self.warnings}
        if len(bases) != 1:
            raise ValueError(
                "all warning tiers must share one basis (percent or absolute); "
                "mixed bases have no sound total order"
            )
        basis = bases.pop()

        if basis == "absolute" and self.cap.limit_cost_cents is None:
            raise ValueError("absolute warning tiers require the cap to set limit_cost_cents")

        values = [w.order_value for w in self.warnings]
        if any(later <= earlier for earlier, later in zip(values, values[1:], strict=False)):
            raise ValueError(
                "warning tiers must be strictly ascending by threshold (no duplicates)"
            )

        if basis == "absolute" and values[-1] >= self.cap.limit_cost_cents:
            # A warning at or above the cap is over-permissive / meaningless.
            raise ValueError("every absolute warning threshold must be < cap.limit_cost_cents")

        return self

    def to_policy_payload(self, *, signature: str) -> dict[str, Any]:
        """Emit the LOCKED ``budget_limit`` record from this policy's hard cap.

        Serializes ``self.cap`` ONLY, via D-001's
        :func:`delta.attribution.budget_concept_to_policy_payload`. Warnings and
        the ``WarningAction`` are dropped by construction — they are advisory and
        must never enter the signed policy. ``signature`` is supplied by the
        caller (the signer); D-002 does not sign.
        """
        return budget_concept_to_policy_payload(
            self.cap,
            policy_id=self.policy_id,
            policy_version=self.policy_version,
            effective_from=self.effective_from,
            signature=signature,
        )
