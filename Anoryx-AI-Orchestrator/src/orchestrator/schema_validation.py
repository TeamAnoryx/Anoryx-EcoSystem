"""JSON Schema validation for the ingest seam (O-003, ADR-0003).

Two-stage (ADR-0002 Fork C):
  * STRUCTURAL envelope validation — validates the envelope's own fields against a
    SHALLOW copy of event-envelope.schema.json whose `payload` is relaxed to a generic
    object. A structurally malformed envelope is a synchronous 422 at the boundary. The
    payload is NOT deep-validated here, so a well-formed-but-rejected envelope (unknown
    schema_version, payload-schema failure, invariant mismatch) reaches the DLQ rather
    than 422'ing.
  * PAYLOAD validation — validates the payload against the LOCKED events.schema.json
    UNMODIFIED, in the pipeline stage. A failure → reject-to-DLQ (payload_schema_invalid).

Both use a JSON Schema Draft 2020-12 validator with the format checker enabled — the same
library + dialect Sentinel and the Orchestrator contract tests use, so there is no
parser-differential between products.
"""

from __future__ import annotations

import copy
import functools
import json
import pathlib

from jsonschema import Draft202012Validator
from jsonschema.validators import Draft202012Validator as _D

# Layout: this file is Anoryx-AI-Orchestrator/src/orchestrator/schema_validation.py
_HERE = pathlib.Path(__file__).resolve()
_ORCH_ROOT = _HERE.parents[2]  # .../Anoryx-AI-Orchestrator
_REPO_ROOT = _HERE.parents[3]  # repo root
_ENVELOPE_SCHEMA_PATH = _ORCH_ROOT / "contracts" / "event-envelope.schema.json"
_EVENTS_SCHEMA_PATH = _REPO_ROOT / "Anoryx-Sentinel" / "contracts" / "events.schema.json"


def _load_json(path: pathlib.Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@functools.lru_cache(maxsize=1)
def _events_validator() -> Draft202012Validator:
    schema = _load_json(_EVENTS_SCHEMA_PATH)
    return Draft202012Validator(schema, format_checker=_D.FORMAT_CHECKER)


@functools.lru_cache(maxsize=1)
def _shallow_envelope_validator() -> Draft202012Validator:
    """Validator for the envelope's OWN fields, with payload relaxed to a generic object.

    This deliberately does NOT resolve the payload $ref into events.schema.json, so the
    structural boundary check does not deep-validate the payload (that is the pipeline's
    job, routed to the DLQ on failure).
    """
    schema = copy.deepcopy(_load_json(_ENVELOPE_SCHEMA_PATH))
    schema.get("properties", {})["payload"] = {"type": "object"}
    return Draft202012Validator(schema, format_checker=_D.FORMAT_CHECKER)


def envelope_structure_errors(envelope: object) -> list[str]:
    """Return structural errors for *envelope* (empty list = structurally valid).

    Validates envelope fields (required, types, patterns, bounds) but treats payload as a
    generic object. A non-empty result → the receiver returns 422.
    """
    return [e.message for e in _shallow_envelope_validator().iter_errors(envelope)]


def payload_errors(payload: object) -> list[str]:
    """Return validation errors for *payload* vs the locked events.schema.json.

    Empty list = valid. A non-empty result → reject-to-DLQ (payload_schema_invalid).
    """
    return [e.message for e in _events_validator().iter_errors(payload)]
