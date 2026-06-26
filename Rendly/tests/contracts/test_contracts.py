"""Contract-validation suite for the Rendly R-001 contract lock.

This is the executable authority behind the CI lane (`.github/workflows/rendly-ci.yml`).
It proves three things on a clean tree:

  1. `contracts/openapi.yaml` is a structurally valid OpenAPI 3.1 document.
  2. `contracts/messages.schema.json` is a valid JSON Schema Draft 2020-12 document.
  3. EVERY example in both specs validates against its declared schema — every REST
     endpoint request/response example, every component-schema example, and every
     WebSocket message-catalog example (which must also dispatch to exactly one
     `oneOf` variant).

There is no application code in R-001 (servers are R-003+), so these tests ARE the
contract guarantee a downstream builder relies on.
"""

from __future__ import annotations

import json
import pathlib

import pytest
import yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

try:  # openapi-spec-validator >=0.7 exposes `validate`
    from openapi_spec_validator import validate as validate_openapi
except ImportError:  # pragma: no cover - older API fallback
    from openapi_spec_validator import validate_spec as validate_openapi

CONTRACTS = pathlib.Path(__file__).resolve().parents[2] / "contracts"
OPENAPI_PATH = CONTRACTS / "openapi.yaml"
MESSAGES_PATH = CONTRACTS / "messages.schema.json"

# A concrete https base URI (not a bare urn:) so `referencing` splits the JSON-pointer
# fragment correctly when resolving `#/components/...` against the registered document.
_OPENAPI_URI = "https://rendly.anoryx.io/contracts/openapi.json"


# --------------------------------------------------------------------------- loaders
def _load_openapi() -> dict:
    with OPENAPI_PATH.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _load_messages() -> dict:
    with MESSAGES_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


def _openapi_registry(doc: dict) -> Registry:
    """A referencing registry holding the whole OpenAPI doc so `#/components/...`
    pointers inside any schema fragment resolve."""
    resource = Resource(contents=doc, specification=DRAFT202012)
    return Registry().with_resource(uri=_OPENAPI_URI, resource=resource)


def _validator_for_pointer(doc: dict, pointer: str) -> Draft202012Validator:
    registry = _openapi_registry(doc)
    return Draft202012Validator({"$ref": f"{_OPENAPI_URI}#{pointer}"}, registry=registry)


# --------------------------------------------------------------------------- spec validity
def test_openapi_is_valid_openapi_31():
    validate_openapi(_load_openapi())


def test_messages_catalog_is_valid_draft_2020_12():
    Draft202012Validator.check_schema(_load_messages())


# ------------------------------------------------------------- message-catalog examples
def _message_example_cases():
    catalog = _load_messages()
    cases = []
    for name, subschema in catalog["$defs"].items():
        for idx, example in enumerate(subschema.get("examples", [])):
            cases.append(pytest.param(example, id=f"{name}[{idx}]"))
    return cases


def test_message_catalog_has_examples():
    # Guard: every dispatchable variant in the oneOf must ship at least one example.
    catalog = _load_messages()
    variant_names = [ref["$ref"].split("/")[-1] for ref in catalog["oneOf"]]
    missing = [n for n in variant_names if not catalog["$defs"][n].get("examples")]
    assert not missing, f"message variants without a validating example: {missing}"


@pytest.mark.parametrize("example", _message_example_cases())
def test_message_example_validates_and_dispatches(example):
    catalog = _load_messages()
    validator = Draft202012Validator(catalog)
    # Validates against the whole catalog (the root oneOf), so it must both be
    # structurally valid AND match exactly one variant.
    validator.validate(example)


# ----------------------------------------------------------- component-schema examples
def _component_schema_example_cases():
    doc = _load_openapi()
    cases = []
    for name, schema in doc.get("components", {}).get("schemas", {}).items():
        if "example" in schema:
            cases.append(pytest.param(name, schema["example"], id=name))
    return cases


@pytest.mark.parametrize("name,example", _component_schema_example_cases())
def test_component_schema_example_validates(name, example):
    doc = _load_openapi()
    validator = _validator_for_pointer(doc, f"/components/schemas/{name}")
    validator.validate(example)


# ----------------------------------------------------- endpoint (media-type) examples
def _iter_media_objects(doc: dict):
    """Yield (label, media_object) for every request/response media object that
    carries a `schema` plus an `example` or `examples`."""

    def walk(node, path):
        if isinstance(node, dict):
            if "schema" in node and ("example" in node or "examples" in node):
                yield (path, node)
            for key, value in node.items():
                yield from walk(value, f"{path}/{key}")
        elif isinstance(node, list):
            for i, value in enumerate(node):
                yield from walk(value, f"{path}[{i}]")

    yield from walk(doc.get("paths", {}), "paths")
    yield from walk(doc.get("components", {}).get("responses", {}), "components/responses")


def _media_example_cases():
    doc = _load_openapi()
    cases = []
    for label, media in _iter_media_objects(doc):
        schema = media["schema"]
        examples = []
        if "example" in media:
            examples.append(("example", media["example"]))
        if "examples" in media:
            for ex_name, ex_obj in media["examples"].items():
                examples.append((ex_name, ex_obj["value"]))
        for ex_name, value in examples:
            cases.append(pytest.param(schema, value, id=f"{label}::{ex_name}"))
    return cases


@pytest.mark.parametrize("schema,example", _media_example_cases())
def test_endpoint_example_validates(schema, example):
    doc = _load_openapi()
    registry = _openapi_registry(doc)
    if set(schema.keys()) == {"$ref"} and schema["$ref"].startswith("#"):
        # "#/components/schemas/X" -> "<base>#/components/schemas/X" (keep the fragment).
        resolved = {"$ref": f"{_OPENAPI_URI}#{schema['$ref'][1:]}"}
    else:
        resolved = schema
    Draft202012Validator(resolved, registry=registry).validate(example)


def test_endpoint_examples_were_discovered():
    # Guard against a silently-empty walk (would make the lane pass vacuously).
    assert _media_example_cases(), "no endpoint examples discovered in openapi.yaml"


# --------------------------------------------------------- error envelope maintainability
# Canonical 1:1 REST error_code -> fixed message pairing (positional in the schema enums).
# This dict is the source of truth: a reorder or mis-pairing in the spec must fail a test.
_REST_ERROR_PAIRS = {
    "invalid_request": "The request body is invalid or violates a field constraint.",
    "request_too_large": "The request body exceeds the maximum allowed size.",
    "invalid_token": "The access token is missing, expired, or invalid.",
    "tenant_context_mismatch": "The addressed tenant does not match the access token's authorized tenant.",
    "forbidden": "The caller is not permitted to perform this action.",
    "message_blocked": "Content was blocked by the safety inspection seam.",
    "rate_limit_exceeded": "Rate limit exceeded. Retry after the window resets.",
    "not_found": "The requested resource was not found.",
    "conflict": "The request conflicts with the current state of the resource.",
    "internal_error": "An internal error occurred. The request was not processed.",
}


def test_rest_error_enums_are_the_canonical_pairing():
    error = _load_openapi()["components"]["schemas"]["Error"]
    codes = error["properties"]["error_code"]["enum"]
    messages = error["properties"]["message"]["enum"]
    assert len(codes) == len(messages)
    assert (
        dict(zip(codes, messages, strict=True)) == _REST_ERROR_PAIRS
    ), "Error.error_code/Error.message enums drifted from the canonical 1:1 pairing"


def test_rest_error_examples_use_the_canonical_pairing():
    # Every Error-envelope example in the spec must pair the right message with its code,
    # so a downstream builder copying an example cannot inherit a mis-paired code/message.
    doc = _load_openapi()
    seen = 0
    for _label, media in _iter_media_objects(doc):
        values = []
        if "example" in media:
            values.append(media["example"])
        if "examples" in media:
            values.extend(e["value"] for e in media["examples"].values())
        for v in values:
            if isinstance(v, dict) and "error_code" in v and "message" in v:
                assert (
                    _REST_ERROR_PAIRS.get(v["error_code"]) == v["message"]
                ), f"error example pairs '{v['error_code']}' with a non-canonical message"
                seen += 1
    assert seen, "no Error-envelope examples found to check pairing"


def test_ws_error_frame_enums_parity():
    err = _load_messages()["$defs"]["ErrorFrame"]["properties"]
    codes = err["error_code"]["enum"]
    messages = err["message"]["enum"]
    assert len(codes) == len(messages), (
        f"ErrorFrame error_code/message enums must stay 1:1 "
        f"(codes={len(codes)}, messages={len(messages)})"
    )


def test_archival_and_inspection_shapes_match_across_specs():
    # Drift guard: ArchivalMeta + InspectionResult are defined in BOTH the OpenAPI schemas
    # and the WS message catalog; their shapes must not diverge silently.
    oa = _load_openapi()["components"]["schemas"]
    ws = _load_messages()["$defs"]
    for name in ("ArchivalMeta", "InspectionResult"):
        assert set(oa[name].get("properties", {})) == set(
            ws[name].get("properties", {})
        ), f"{name} property set drifted between openapi.yaml and messages.schema.json"
        assert set(oa[name].get("required", [])) == set(
            ws[name].get("required", [])
        ), f"{name} required set drifted between openapi.yaml and messages.schema.json"
