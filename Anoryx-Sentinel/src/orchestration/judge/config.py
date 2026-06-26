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

# ADR-0025: code defaults for two of the per-tenant judge thresholds. When a
# tenant leaves the column NULL the DETECTOR applies these (the resolver itself is
# pure pass-through). confidence matches the historical hardcoded `0.5`; floor is
# the new obvious-clean skip (0.0 = today, no clean-skip). The SKIP default is NOT
# a constant here — it defers to the existing `judge_skip_score` SETTING so a
# deployment that customized that setting is preserved (the detector applies it).
DEFAULT_CONFIDENCE_THRESHOLD = 0.5
DEFAULT_FLOOR_THRESHOLD = 0.0


@dataclass(frozen=True)
class ClassifierConfig:
    """Resolved classifier config for a request scope.

    model_id:   the judge preset ("anthropic:claude-haiku-4-5" / "openai:gpt-4o-mini")
                or None when unconfigured.
    audit_mode: "full" | "redacted" (R10).  Defaults to "full".

    ADR-0025 per-tenant thresholds — a resolved per-tenant override, or None when
    the tenant left it unset (the DETECTOR then applies the code/setting default).
    These gate WHETHER the judge runs / WHETHER its verdict is counted; they never
    enter the max(regex, judge) blend, so no value can lower the final below regex:
      confidence_threshold: judge verdict ignored when confidence < this.
      skip_threshold:       judge skipped (obvious attack)  when regex_score >= this.
      floor_threshold:      judge skipped (obvious clean)   when regex_score < this.
    """

    model_id: str | None
    audit_mode: str = "full"
    confidence_threshold: float | None = None
    skip_threshold: float | None = None
    floor_threshold: float | None = None


# Sentinel for "no classifier configured anywhere in the scope chain".
UNCONFIGURED = ClassifierConfig(model_id=None, audit_mode="full")


@dataclass(frozen=True)
class ScopeConfig:
    """A candidate classifier config at a given scope specificity.

    specificity: higher = more specific (e.g. agent=3, project=2, team=1, tenant=0).
    The stored values at that scope (None = not set there, inherit from a parent).
    """

    specificity: int
    model_id: str | None
    audit_mode: str | None
    confidence_threshold: float | None = None
    skip_threshold: float | None = None
    floor_threshold: float | None = None


def resolve_inherited_config(candidates: list[ScopeConfig]) -> ClassifierConfig:
    """Resolve the effective config by most-specific-non-NULL inheritance.

    Every field is resolved INDEPENDENTLY: each takes the value from the
    most-specific scope that sets it.  An empty / all-NULL chain yields model_id=None
    (unconfigured) and threshold=None (the detector applies the default). The
    thresholds are pure pass-through here — defaulting lives in the detector so the
    skip default can defer to the existing `judge_skip_score` setting.
    """
    ordered = sorted(candidates, key=lambda c: c.specificity, reverse=True)

    def _first(attr: str, default):
        return next(
            (v for c in ordered if (v := getattr(c, attr)) is not None),
            default,
        )

    return ClassifierConfig(
        model_id=_first("model_id", None),
        audit_mode=_first("audit_mode", "full"),
        confidence_threshold=_first("confidence_threshold", None),
        skip_threshold=_first("skip_threshold", None),
        floor_threshold=_first("floor_threshold", None),
    )
