"""O-001 contract-validation tests.

Mirrors the existing Sentinel contract-test pattern
(Anoryx-Sentinel/tests/policy/test_event_contract.py and tests/gateway/test_audit.py):
load the schema file by path and validate with a JSON Schema Draft 2020-12 validator.

These tests assert, design-level (no runtime exists yet):
  - the OpenAPI document is a valid 3.1 spec;
  - every external $ref into the locked Sentinel F-002 schemas resolves to a real file;
  - every example payload in the spec validates against the LOCKED
    events.schema.json / policy.schema.json UNMODIFIED;
  - the mutualTLS scheme is declared and applied to every operation;
  - the locked schema $ids are unchanged (guard against accidental widen/copy);
  - a types/client generator can consume the spec (codegen smoke, DoD #4).
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import jsonschema
import pytest
import yaml
from jsonschema import Draft202012Validator

# Layout: this file is Anoryx-AI-Orchestrator/tests/test_contract.py
HERE = pathlib.Path(__file__).resolve().parent
ORCH_CONTRACTS = HERE.parent / "contracts"
SPEC_PATH = ORCH_CONTRACTS / "openapi.yaml"
REPO_ROOT = HERE.parent.parent  # Anoryx-AI-Orchestrator/ -> repo root
SENTINEL_CONTRACTS = REPO_ROOT / "Anoryx-Sentinel" / "contracts"
EVENTS_SCHEMA = SENTINEL_CONTRACTS / "events.schema.json"
POLICY_SCHEMA = SENTINEL_CONTRACTS / "policy.schema.json"

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head", "trace"}


def _load_spec() -> dict:
    with open(SPEC_PATH, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _load_json(path: pathlib.Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _iter_refs(node):
    """Yield every $ref string value anywhere in the spec tree."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "$ref" and isinstance(value, str):
                yield value
            else:
                yield from _iter_refs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _iter_refs(item)


# --------------------------------------------------------------------------- #
# Spec validity
# --------------------------------------------------------------------------- #


def test_spec_declares_openapi_31():
    assert _load_spec()["openapi"] == "3.1.0"


def test_spec_is_valid_openapi_31():
    """The document validates structurally as an OpenAPI 3.1 spec."""
    try:
        from openapi_spec_validator import validate as _validate
    except ImportError:  # older API name
        from openapi_spec_validator import validate_spec as _validate

    spec = _load_spec()
    # Pass the spec's own file URI as base so any external $ref the validator chooses
    # to resolve (../../Anoryx-Sentinel/contracts/*.json) is locatable.
    _validate(spec, base_uri=SPEC_PATH.as_uri())


# --------------------------------------------------------------------------- #
# External $refs into the locked F-002 schemas resolve
# --------------------------------------------------------------------------- #


def test_external_refs_resolve_to_real_files():
    spec = _load_spec()
    external = [ref for ref in _iter_refs(spec) if ref.startswith(("../", "./"))]
    assert external, "expected external $refs into the Sentinel F-002 schemas"
    for ref in external:
        file_part = ref.split("#", 1)[0]
        target = (ORCH_CONTRACTS / file_part).resolve()
        assert target.is_file(), f"unresolved external $ref: {ref} -> {target}"
        _load_json(target)  # must parse as JSON


def test_refs_point_only_at_locked_sentinel_schemas():
    """Reuse by reference, never by copy: external refs must target the Sentinel files."""
    spec = _load_spec()
    external = [r for r in _iter_refs(spec) if r.startswith(("../", "./"))]
    for ref in external:
        target = (ORCH_CONTRACTS / ref.split("#", 1)[0]).resolve()
        assert target in {
            EVENTS_SCHEMA.resolve(),
            POLICY_SCHEMA.resolve(),
        }, f"external $ref points outside the locked Sentinel schemas: {ref}"


# --------------------------------------------------------------------------- #
# Locked schemas are themselves valid + their $ids are unchanged
# --------------------------------------------------------------------------- #


def test_events_schema_is_valid_draft202012():
    Draft202012Validator.check_schema(_load_json(EVENTS_SCHEMA))


def test_policy_schema_is_valid_draft202012():
    Draft202012Validator.check_schema(_load_json(POLICY_SCHEMA))


def test_locked_events_schema_id_unchanged():
    assert _load_json(EVENTS_SCHEMA)["$id"] == "sentinel:events:v1"


def test_locked_policy_schema_id_unchanged():
    # Guards against accidental widen/copy: the policy schema is LOCKED at F-008 a9e2344.
    assert _load_json(POLICY_SCHEMA)["$id"] == "sentinel:policy:v1"


# --------------------------------------------------------------------------- #
# Every example validates against the locked schemas UNMODIFIED
# --------------------------------------------------------------------------- #


def test_ingest_example_validates_against_events_schema():
    spec = _load_spec()
    example = spec["paths"]["/v1/ingest/events"]["post"]["requestBody"]["content"][
        "application/json"
    ]["examples"]["policyDecisionDeny"]["value"]
    schema = _load_json(EVENTS_SCHEMA)
    # Pin the 2020-12 dialect explicitly (do not rely on $schema autodetection) so the
    # validator dialect can never drift between Sentinel/Orchestrator/Delta.
    try:
        Draft202012Validator(schema).validate(example)
    except jsonschema.ValidationError as exc:
        pytest.fail(
            f"ingest example failed events.schema.json validation: {exc.message}"
        )


def test_distribution_policy_example_validates_against_policy_schema():
    spec = _load_spec()
    body = spec["paths"]["/v1/policies/distributions"]["post"]["requestBody"][
        "content"
    ]["application/json"]["examples"]["budgetLimitDistribution"]["value"]
    policy = body["policy"]
    schema = _load_json(POLICY_SCHEMA)
    try:
        Draft202012Validator(schema).validate(policy)
    except jsonschema.ValidationError as exc:
        pytest.fail(
            f"distribution policy example failed policy.schema.json validation: {exc.message}"
        )


# --------------------------------------------------------------------------- #
# mTLS declared + applied to all operations
# --------------------------------------------------------------------------- #


def test_mutualtls_scheme_declared():
    schemes = _load_spec()["components"]["securitySchemes"]
    assert schemes["mutualTLS"]["type"] == "mutualTLS"
    # The two second factors are present too.
    assert schemes["hmacIngest"]["type"] == "apiKey"
    assert schemes["serviceToken"]["scheme"] == "bearer"


_SECOND_FACTORS = {"hmacIngest", "serviceToken"}


def test_mutualtls_applied_to_every_operation():
    spec = _load_spec()
    global_security = spec.get("security", [])
    operations = 0
    for path, item in spec["paths"].items():
        for method, operation in item.items():
            if method not in _HTTP_METHODS:
                continue
            operations += 1
            security = operation.get("security", global_security)
            assert security, f"{method.upper()} {path} has no security requirement"
            for requirement in security:
                assert (
                    "mutualTLS" in requirement
                ), f"{method.upper()} {path} security requirement is missing mutualTLS: {requirement}"
                # mTLS provisioning is deferred (boundary a), so an mTLS-only operation
                # is effectively unauthenticated until O-008. Require a second factor
                # (HMAC or service token) on EVERY operation so a future op that forgets
                # its op-level override (and silently inherits the mTLS-only global
                # default) fails this gate instead of shipping inert auth.
                assert _SECOND_FACTORS & set(requirement), (
                    f"{method.upper()} {path} requirement has no second factor "
                    f"(hmacIngest/serviceToken): {requirement}"
                )
    assert operations >= 4, "expected at least the four O-001 operations"


# --------------------------------------------------------------------------- #
# Codegen smoke (DoD #4)
# --------------------------------------------------------------------------- #


def test_codegen_consumes_spec(tmp_path):
    """A types generator (datamodel-code-generator) must consume the spec without error.

    The spec references the locked Sentinel schemas via cross-file $ref, so the
    generator emits a modular package — output must be a DIRECTORY, and the external
    local-file refs are allowed explicitly with --allow-remote-refs.
    """
    output_dir = tmp_path / "models"
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "datamodel_code_generator",
            "--input",
            str(SPEC_PATH),
            "--input-file-type",
            "openapi",
            "--allow-remote-refs",
            "--output",
            str(output_dir),
        ],
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, (
        "datamodel-code-generator failed to consume the spec:\n"
        f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    generated = list(output_dir.rglob("*.py"))
    assert generated, "codegen produced no Python modules"
    # Guard against a false green where the generator exits 0 but silently skips the
    # spec's own schemas: at least one Orchestrator-defined model must appear in the
    # generated output (a class name derived from components.schemas).
    all_code = "\n".join(p.read_text(encoding="utf-8") for p in generated)
    assert "Distribution" in all_code, (
        "codegen exited 0 but produced no Distribution model — the spec's own schemas "
        "did not generate (possible silent $ref skip)"
    )
