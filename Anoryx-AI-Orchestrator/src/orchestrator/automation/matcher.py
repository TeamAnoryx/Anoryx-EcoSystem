"""Pure automation-rule matcher (O-011, ADR-0011).

NO I/O. NO eval, NO regex, NO code execution of any kind — this function's simplicity IS
the security property that closes the "condition-language injection / RCE" threat named
in the ADR's threat model. Do not add extensibility hooks (a template language, an
operator DSL, a callback) to this module; that is explicitly out of scope for v1.
"""

from __future__ import annotations

from typing import Any

# JSON scalar types a trigger_conditions value (or a matched payload field) may be. A
# dict/list value NEVER matches (checked explicitly below) — bool is intentionally
# included since it is a valid JSON scalar and Python's bool is a subclass of int, so no
# separate branch is needed for it.
_SCALAR_TYPES = (str, int, float, bool)


def _is_scalar(value: Any) -> bool:
    """True iff *value* is a JSON scalar (str/int/float/bool), never a dict/list/None."""
    return isinstance(value, _SCALAR_TYPES)


def rule_matches(rule: dict, *, event_type: str, source_product: str, payload: dict) -> bool:
    """Return True iff *rule* matches this event. Never raises.

    Matching, in order (ALL must hold):
      1. event_type == rule["trigger_event_type"].
      2. rule["trigger_source_product"] is None, OR it equals source_product.
      3. every key in rule["trigger_conditions"] exists in payload with an EXACTLY EQUAL
         scalar value (`==` on JSON-decoded values). A condition value or the
         corresponding payload value that is a dict/list NEVER matches (treated as
         non-matching, never raises) — this is a hard security invariant, not merely a
         convenience: it prevents a condition language from ever comparing structured
         data, which is the only shape an injection/operator-smuggling attempt could take
         here.

    Empty trigger_conditions (the default, `{}`) always matches within the same
    event_type/source_product — there is nothing to check.
    """
    if rule.get("trigger_event_type") != event_type:
        return False

    trigger_source_product = rule.get("trigger_source_product")
    if trigger_source_product is not None and trigger_source_product != source_product:
        return False

    conditions = rule.get("trigger_conditions") or {}
    if not isinstance(conditions, dict):
        return False
    for key, expected in conditions.items():
        if not _is_scalar(expected):
            return False
        if not isinstance(payload, dict) or key not in payload:
            return False
        actual = payload[key]
        if not _is_scalar(actual):
            return False
        if actual != expected:
            return False

    return True
