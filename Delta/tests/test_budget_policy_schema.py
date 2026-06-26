"""Delta-side wrapper-schema conformance for delta-budget-policy.schema.json
(D-002, vectors: JSON Schema permissiveness + bounds).

Proves: (a) the schema is valid Draft 2020-12 and every object is closed
(additionalProperties:false, incl. each BudgetWarningTier oneOf branch),
(b) a canonical Pydantic-serialized BudgetPolicy validates, and (c) malformed
docs are rejected. This validates the WRAPPER document; the SERIALIZED hard cap
is proven against the untouched locked schema in ``test_budget_policy_emit.py``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator

from delta.budget import BudgetConcept, BudgetPeriod, BudgetScope
from delta.budget_policy import BudgetPolicy, BudgetWarningTier, WarningAction

_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "contracts" / "delta-budget-policy.schema.json"
_SCHEMA = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))

_T = "12121212-1212-4212-8212-121212121212"
_TEAM = "13131313-1313-4313-8313-131313131313"
_PROJ = "14141414-1414-4414-8414-141414141414"
_POLICY = "1a1a1a1a-1a1a-4a1a-8a1a-1a1a1a1a1a1a"
_EFF = datetime(2026, 6, 26, 0, 0, 0, tzinfo=timezone.utc)


def _validator(defname: str) -> Draft202012Validator:
    root = {"$ref": f"#/$defs/{defname}", "$defs": _SCHEMA["$defs"]}
    return Draft202012Validator(root, format_checker=Draft202012Validator.FORMAT_CHECKER)


def _cap(**over) -> BudgetConcept:
    base = dict(
        tenant_id=_T,
        team_id=_TEAM,
        project_id=_PROJ,
        agent_id="gateway-core",
        scope=BudgetScope.TEAM,
        period=BudgetPeriod.MONTHLY,
        limit_cost_cents=500_000,
    )
    base.update(over)
    return BudgetConcept(**base)


def _policy_doc(warnings=()) -> dict:
    p = BudgetPolicy(
        cap=_cap(), policy_id=_POLICY, policy_version=1, effective_from=_EFF, warnings=warnings
    )
    # Wire form omits unset optionals (null != absent) so the oneOf branches match.
    return p.model_dump(mode="json", exclude_none=True)


# --- (a) schema validity + closedness ------------------------------------------
def test_schema_is_valid_draft202012():
    Draft202012Validator.check_schema(_SCHEMA)


def test_every_object_def_forbids_additional_properties():
    # Cover both plain object defs and oneOf-branch objects (e.g. BudgetWarningTier
    # is a bare oneOf with no top-level type), so no def is silently skipped.
    for name, definition in _SCHEMA["$defs"].items():
        if definition.get("type") == "object":
            assert definition.get("additionalProperties") is False, f"{name} not closed"
        for i, branch in enumerate(definition.get("oneOf", [])):
            if branch.get("type") == "object":
                assert branch.get("additionalProperties") is False, f"{name}.oneOf[{i}] not closed"


def test_warning_tier_oneof_branches_are_closed():
    # BudgetWarningTier is a oneOf (no top-level type); assert each branch closes.
    for branch in _SCHEMA["$defs"]["BudgetWarningTier"]["oneOf"]:
        assert branch["additionalProperties"] is False


# --- (b) canonical payloads validate -------------------------------------------
def test_canonical_policy_no_warnings_valid():
    errors = list(_validator("BudgetPolicy").iter_errors(_policy_doc()))
    assert errors == [], errors


def test_canonical_policy_percent_warnings_valid():
    doc = _policy_doc(
        warnings=(
            BudgetWarningTier(threshold_percent=50, action=WarningAction.NOTIFY),
            BudgetWarningTier(threshold_percent=90, action=WarningAction.PAGE),
        )
    )
    errors = list(_validator("BudgetPolicy").iter_errors(doc))
    assert errors == [], errors


def test_canonical_policy_absolute_warnings_valid():
    doc = _policy_doc(
        warnings=(BudgetWarningTier(threshold_cost_cents=400_000, action=WarningAction.ALERT),)
    )
    assert _validator("BudgetPolicy").is_valid(doc)


# --- (c) malformed payloads rejected -------------------------------------------
def test_extra_key_on_doc_rejected():
    doc = _policy_doc()
    doc["smuggled"] = "x"
    assert not _validator("BudgetPolicy").is_valid(doc)


def test_warning_tier_with_both_bases_rejected():
    # Both threshold fields present -> matches NEITHER oneOf branch (each is closed).
    doc = _policy_doc()
    doc["warnings"] = [{"threshold_percent": 50, "threshold_cost_cents": 100, "action": "notify"}]
    assert not _validator("BudgetPolicy").is_valid(doc)


def test_warning_percent_100_rejected():
    doc = _policy_doc()
    doc["warnings"] = [{"threshold_percent": 100, "action": "notify"}]
    assert not _validator("BudgetPolicy").is_valid(doc)


def test_warning_percent_0_rejected():
    doc = _policy_doc()
    doc["warnings"] = [{"threshold_percent": 0, "action": "notify"}]
    assert not _validator("BudgetPolicy").is_valid(doc)


def test_unknown_action_rejected():
    doc = _policy_doc()
    doc["warnings"] = [{"threshold_percent": 50, "action": "shutdown"}]
    assert not _validator("BudgetPolicy").is_valid(doc)


def test_bad_agent_slug_in_cap_rejected():
    doc = _policy_doc()
    doc["cap"]["agent_id"] = "Gateway_Core"  # uppercase + underscore: not the slug
    assert not _validator("BudgetPolicy").is_valid(doc)


def test_cap_without_a_limit_rejected():
    doc = _policy_doc()
    doc["cap"].pop("limit_cost_cents", None)
    doc["cap"].pop("limit_tokens", None)
    assert not _validator("BudgetPolicy").is_valid(doc)


def test_missing_envelope_field_rejected():
    doc = _policy_doc()
    del doc["policy_id"]
    assert not _validator("BudgetPolicy").is_valid(doc)


def test_too_many_warning_tiers_rejected():
    # warnings maxItems is 64; 65 tiers must be rejected by the wrapper schema.
    doc = _policy_doc()
    doc["warnings"] = [{"threshold_percent": 50, "action": "notify"}] * 65
    assert not _validator("BudgetPolicy").is_valid(doc)


def test_all_expected_defs_present():
    for name in ("BudgetPolicy", "BudgetWarningTier", "BudgetConcept", "WarningAction"):
        assert name in _SCHEMA["$defs"]
