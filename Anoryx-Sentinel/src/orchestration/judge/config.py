"""Classifier configuration + B2C inheritance resolver (F-007, ADR-0010 §6).

`ClassifierConfig` is the resolved per-request classifier config: which judge
preset to use (or None = unconfigured) and the audit mode.

`resolve_inherited_config` is the PURE inheritance contract: given candidate
configs at several scope specificities (e.g. tenant / team / project / agent),
the most-specific non-NULL `model_id` wins, and the most-specific non-NULL
`audit_mode` wins independently.  This proves the B2C contract (child overrides
parent; child inherits when unset; all-NULL → unconfigured) regardless of how many
scope rows the persistence layer actually stores.  The repository (STEP 5) feeds it
the candidate rows; today `tenant_routing_policy` is one row per tenant, so the
candidate list is tenant-scoped — but the resolver is future-proof for per-scope
rows.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ClassifierConfig:
    """Resolved classifier config for a request scope.

    model_id:   the judge preset ("anthropic:claude-haiku-4-5" / "openai:gpt-4o-mini")
                or None when unconfigured.
    audit_mode: "full" | "redacted" (R10).  Defaults to "full".
    """

    model_id: str | None
    audit_mode: str = "full"


# Sentinel for "no classifier configured anywhere in the scope chain".
UNCONFIGURED = ClassifierConfig(model_id=None, audit_mode="full")


@dataclass(frozen=True)
class ScopeConfig:
    """A candidate classifier config at a given scope specificity.

    specificity: higher = more specific (e.g. agent=3, project=2, team=1, tenant=0).
    model_id / audit_mode: the stored values at that scope (None = not set there).
    """

    specificity: int
    model_id: str | None
    audit_mode: str | None


def resolve_inherited_config(candidates: list[ScopeConfig]) -> ClassifierConfig:
    """Resolve the effective config by most-specific-non-NULL inheritance.

    model_id and audit_mode are resolved INDEPENDENTLY: each takes the value from
    the most-specific scope that sets it.  An empty / all-NULL chain yields
    UNCONFIGURED (model_id=None, audit_mode="full").
    """
    ordered = sorted(candidates, key=lambda c: c.specificity, reverse=True)
    model_id = next((c.model_id for c in ordered if c.model_id is not None), None)
    audit_mode = next((c.audit_mode for c in ordered if c.audit_mode is not None), "full")
    return ClassifierConfig(model_id=model_id, audit_mode=audit_mode)
