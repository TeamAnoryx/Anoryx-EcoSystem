"""JSON Schema Draft 2020-12 validation against contracts/policy.schema.json (R6).

We use jsonschema's explicit Draft202012Validator — NOT Pydantic — because the
contract mandates that Sentinel, Orchestrator, and Delta all validate with the
SAME Draft 2020-12 dialect so no parser-differential exists (a differential is a
security bug per the contract). The format checker is attached so `uuid` /
`date-time` formats are asserted when the optional format libraries are present
(jsonschema[format], a runtime dependency); the load-bearing security gates are
structural (additionalProperties:false, required, maxLength/maxItems, the
signature `pattern`, and `oneOf` variant dispatch) and hold regardless.
"""

from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Any

from jsonschema import Draft202012Validator

_SCHEMA_PATH_ENV = "POLICY_SCHEMA_PATH"


def _default_schema_path() -> str:
    """contracts/policy.schema.json resolved relative to this module (src/policy/)."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(here, "..", "..", "contracts", "policy.schema.json"))


@lru_cache(maxsize=1)
def _load_schema() -> dict[str, Any]:
    path = os.environ.get(_SCHEMA_PATH_ENV) or _default_schema_path()
    with open(path, "rb") as handle:
        return json.load(handle)


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    schema = _load_schema()
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


def validate_policy_record(record: Any) -> list[str]:
    """Return a list of human-readable validation errors; empty list means valid.

    A non-dict input is itself a validation failure (the contract's variants are
    all objects).
    """
    if not isinstance(record, dict):
        return ["<root>: policy record must be a JSON object"]
    validator = _validator()
    errors = sorted(validator.iter_errors(record), key=lambda e: list(e.path))
    out: list[str] = []
    for err in errors:
        location = "/".join(str(p) for p in err.path) or "<root>"
        out.append(f"{location}: {err.message}")
    return out


def is_valid_policy_record(record: Any) -> bool:
    return isinstance(record, dict) and _validator().is_valid(record)
