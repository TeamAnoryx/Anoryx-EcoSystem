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
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

# Layout: this file is Anoryx-AI-Orchestrator/tests/test_contract.py
HERE = pathlib.Path(__file__).resolve().parent
ORCH_CONTRACTS = HERE.parent / "contracts"
SPEC_PATH = ORCH_CONTRACTS / "openapi.yaml"
REPO_ROOT = HERE.parent.parent  # Anoryx-AI-Orchestrator/ -> repo root
SENTINEL_CONTRACTS = REPO_ROOT / "Anoryx-Sentinel" / "contracts"
EVENTS_SCHEMA = SENTINEL_CONTRACTS / "events.schema.json"
POLICY_SCHEMA = SENTINEL_CONTRACTS / "policy.schema.json"
# O-002: the standalone event envelope, a sibling of openapi.yaml in the same dir.
EVENT_ENVELOPE_SCHEMA = ORCH_CONTRACTS / "event-envelope.schema.json"

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
    """Reuse by reference, never by copy. O-002 (ADR-0002, Fork D) widens the allow-set:
    openapi.yaml now also $refs the sibling event-envelope.schema.json. The envelope file
    itself $refs ONLY the locked events.schema.json, so reuse-by-reference is preserved
    transitively (no Sentinel schema is copied or widened anywhere). Any OTHER external
    target is still rejected. This is the second of the two O-001 tests deliberately
    updated, recorded in ADR-0002.
    """
    spec = _load_spec()
    external = [r for r in _iter_refs(spec) if r.startswith(("../", "./"))]
    allowed = {
        EVENTS_SCHEMA.resolve(),
        POLICY_SCHEMA.resolve(),
        EVENT_ENVELOPE_SCHEMA.resolve(),
    }
    for ref in external:
        target = (ORCH_CONTRACTS / ref.split("#", 1)[0]).resolve()
        assert (
            target in allowed
        ), f"external $ref points outside the locked schemas + the envelope: {ref}"


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
    """O-002 reconciliation (ADR-0002, Fork D): the ingest body is now the envelope, so
    the example is an envelope. Its `payload` member must still validate against the
    locked events.schema.json UNMODIFIED — the original O-001 intent, one indirection
    deeper. This is one of the two O-001 tests deliberately updated, recorded in ADR-0002.
    """
    spec = _load_spec()
    example = spec["paths"]["/v1/ingest/events"]["post"]["requestBody"]["content"][
        "application/json"
    ]["examples"]["policyDecisionDenyEnvelope"]["value"]
    payload = example["payload"]
    schema = _load_json(EVENTS_SCHEMA)
    # Pin the 2020-12 dialect explicitly (do not rely on $schema autodetection) so the
    # validator dialect can never drift between Sentinel/Orchestrator/Delta.
    try:
        Draft202012Validator(schema).validate(payload)
    except jsonschema.ValidationError as exc:
        pytest.fail(f"wrapped ingest payload failed events.schema.json validation: {exc.message}")


def test_distribution_policy_example_validates_against_policy_schema():
    spec = _load_spec()
    body = spec["paths"]["/v1/policies/distributions"]["post"]["requestBody"]["content"][
        "application/json"
    ]["examples"]["budgetLimitDistribution"]["value"]
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
    # The app-layer second factors are present too.
    assert schemes["hmacIngest"]["type"] == "apiKey"
    assert schemes["serviceToken"]["scheme"] == "bearer"
    # O-005 adds a dedicated OPERATOR bearer (ORCH_ADMIN_TOKEN), distinct from the peer
    # serviceToken, gating the registry + coordinate seams.
    assert schemes["operatorBearer"]["scheme"] == "bearer"
    # O-009 adds a dedicated RELAY SOURCE bearer (ORCH_RELAY_SOURCE_TOKENS), distinct from
    # every other credential, gating the governed-relay dispatch seam.
    assert schemes["relaySourceBearer"]["scheme"] == "bearer"
    # O-010 adds a dedicated IDENTITY SOURCE bearer (ORCH_IDENTITY_SOURCE_TOKENS), distinct
    # from every other credential, gating the identity-event ingest seam.
    assert schemes["identitySourceBearer"]["scheme"] == "bearer"


# Recognised app-layer second factors paired with mutualTLS: hmacIngest (O-003 ingest),
# serviceToken (O-004 peer distribution), operatorBearer (O-005 operator registry/coordinate),
# relaySourceBearer (O-009 governed relay dispatch), identitySourceBearer (O-010 identity
# event ingest), externalApiKey (O-013 third-party external-gateway read), safetySourceBearer
# (X-004 cross-product safety-event ingest).
_SECOND_FACTORS = {
    "hmacIngest",
    "serviceToken",
    "operatorBearer",
    "relaySourceBearer",
    "identitySourceBearer",
    "externalApiKey",
    "safetySourceBearer",
}


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
                assert "mutualTLS" in requirement, (
                    f"{method.upper()} {path} security requirement is missing "
                    f"mutualTLS: {requirement}"
                )
                # mTLS provisioning is deferred (boundary a), so an mTLS-only operation
                # is effectively unauthenticated until O-008. Require a second factor
                # (HMAC or service token) on EVERY operation so a future op that forgets
                # its op-level override (and silently inherits the mTLS-only global
                # default) fails this gate instead of shipping inert auth.
                assert _SECOND_FACTORS & set(requirement), (
                    f"{method.upper()} {path} requirement has no second factor "
                    f"(hmacIngest/serviceToken/operatorBearer): {requirement}"
                )
    assert operations >= 7, "expected at least seven operations: four O-001 + three O-002 bus seams"


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


# --------------------------------------------------------------------------- #
# O-002 event bus: envelope, DLQ, replay, version negotiation
# --------------------------------------------------------------------------- #


def _bus_registry(spec):
    """Mount the spec + the two cross-referenced schema files by their exact file URIs so
    every $ref resolves: openapi.yaml's `./event-envelope.schema.json` -> the envelope
    file, and the envelope's `../../Anoryx-Sentinel/contracts/events.schema.json` -> the
    locked events file. Internal `#/components/...` refs resolve within the spec resource.
    """
    return Registry().with_resources(
        [
            (
                SPEC_PATH.as_uri(),
                Resource.from_contents(spec, default_specification=DRAFT202012),
            ),
            (
                EVENT_ENVELOPE_SCHEMA.as_uri(),
                Resource.from_contents(
                    _load_json(EVENT_ENVELOPE_SCHEMA),
                    default_specification=DRAFT202012,
                ),
            ),
            (
                EVENTS_SCHEMA.as_uri(),
                Resource.from_contents(
                    _load_json(EVENTS_SCHEMA), default_specification=DRAFT202012
                ),
            ),
        ]
    )


def _component_validator(spec, name):
    """A validator for components.schemas.<name>, with all cross-file refs resolvable."""
    return Draft202012Validator(
        {"$ref": f"{SPEC_PATH.as_uri()}#/components/schemas/{name}"},
        registry=_bus_registry(spec),
    )


def _envelope_validator(spec):
    """A validator for the standalone envelope schema (its payload $ref resolved)."""
    return Draft202012Validator(
        {"$ref": EVENT_ENVELOPE_SCHEMA.as_uri()}, registry=_bus_registry(spec)
    )


def _ingest_envelope_example(spec):
    return spec["paths"]["/v1/ingest/events"]["post"]["requestBody"]["content"]["application/json"][
        "examples"
    ]["policyDecisionDenyEnvelope"]["value"]


def test_envelope_schema_is_valid_draft202012():
    Draft202012Validator.check_schema(_load_json(EVENT_ENVELOPE_SCHEMA))


def test_envelope_schema_id_unchanged():
    # Guards against accidental rename of the cross-product envelope contract id.
    assert _load_json(EVENT_ENVELOPE_SCHEMA)["$id"] == "anoryx:event-envelope:v1"


def test_envelope_is_closed_and_requires_core_fields():
    schema = _load_json(EVENT_ENVELOPE_SCHEMA)
    assert schema["additionalProperties"] is False
    required = set(schema["required"])
    core = {
        "schema_version",
        "envelope_id",
        "event_type",
        "source_product",
        "occurred_at",
        "idempotency_key",
        "sequence",
        "correlation_id",
        "payload",
    }
    assert core <= required, f"envelope missing required core fields: {core - required}"


def test_envelope_payload_ref_targets_locked_events_schema():
    schema = _load_json(EVENT_ENVELOPE_SCHEMA)
    ref = schema["properties"]["payload"]["$ref"]
    assert ref == "../../Anoryx-Sentinel/contracts/events.schema.json"
    target = (EVENT_ENVELOPE_SCHEMA.parent / ref).resolve()
    assert (
        target == EVENTS_SCHEMA.resolve()
    ), f"payload $ref does not target the locked events schema: {target}"
    assert _load_json(target)["$id"] == "sentinel:events:v1"


def test_ingest_envelope_example_validates_against_envelope_schema():
    spec = _load_spec()
    example = _ingest_envelope_example(spec)
    try:
        _envelope_validator(spec).validate(example)
    except jsonschema.ValidationError as exc:
        pytest.fail(f"ingest envelope example failed envelope-schema validation: {exc.message}")


def test_ingest_envelope_invariants_hold_in_example():
    # The three consumer-enforced invariants (ADR-0002) are demonstrated by the example:
    # event_type == payload.event_type, idempotency_key == payload.event_id (the F-002 bus
    # dedup key), correlation_id == payload.request_id, source_product == the mTLS peer.
    example = _ingest_envelope_example(_load_spec())
    payload = example["payload"]
    assert example["event_type"] == payload["event_type"]
    assert example["idempotency_key"] == payload["event_id"]
    assert example["correlation_id"] == payload["request_id"]
    assert example["source_product"] == "sentinel"


def test_dead_letter_envelope_preserves_a_valid_original_envelope():
    # The DLQ failure-envelope wraps the original (a full envelope). Build one from the
    # ingest example and validate the whole DeadLetterEnvelope (original_envelope ->
    # envelope -> events all resolve through the registry).
    spec = _load_spec()
    dlq = {
        "dlq_id": "9f8e7d6c-5b4a-4039-8281-706f5e4d3c2b",
        "original_envelope": _ingest_envelope_example(spec),
        "reason": "unknown_schema_version",
        "attempt_count": 3,
        "first_failed_at": "2026-06-26T12:00:10Z",
    }
    try:
        _component_validator(spec, "DeadLetterEnvelope").validate(dlq)
    except jsonschema.ValidationError as exc:
        pytest.fail(f"DeadLetterEnvelope example failed validation: {exc.message}")


def test_dead_letter_reason_enum_is_closed():
    reasons = _load_spec()["components"]["schemas"]["DeadLetterReason"]["enum"]
    assert set(reasons) == {
        "unknown_schema_version",
        "payload_schema_invalid",
        "source_identity_mismatch",
        "idempotency_conflict",
        "max_attempts_exceeded",
    }


def test_dlq_metadata_page_example_validates():
    spec = _load_spec()
    example = spec["paths"]["/v1/bus/dlq"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["examples"]["page"]["value"]
    try:
        _component_validator(spec, "DeadLetterMetadataPage").validate(example)
    except jsonschema.ValidationError as exc:
        pytest.fail(f"DLQ metadata page example failed validation: {exc.message}")


def test_replay_request_examples_validate_and_limit_is_bounded():
    spec = _load_spec()
    examples = spec["paths"]["/v1/bus/replays"]["post"]["requestBody"]["content"][
        "application/json"
    ]["examples"]
    validator = _component_validator(spec, "ReplayRequest")
    for name, ex in examples.items():
        try:
            validator.validate(ex["value"])
        except jsonschema.ValidationError as exc:
            pytest.fail(f"replay example '{name}' failed ReplayRequest validation: {exc.message}")
    # Bounded limit (replay-amplification defense).
    limit = spec["components"]["schemas"]["ReplayLimit"]
    assert limit["minimum"] == 1
    assert limit["maximum"] == 1000


def test_replay_request_rejects_two_selectors():
    # The oneOf must reject a request supplying more than one selector — all three
    # violating pairs, not just one.
    spec = _load_spec()
    validator = _component_validator(spec, "ReplayRequest")
    dlq_id = "9f8e7d6c-5b4a-4039-8281-706f5e4d3c2b"
    two_selector_cases = [
        {"source_product": "sentinel", "from_sequence": 1, "dlq_id": dlq_id},
        {
            "source_product": "sentinel",
            "from_sequence": 1,
            "from_timestamp": "2026-06-26T12:00:00Z",
        },
        {
            "source_product": "sentinel",
            "from_timestamp": "2026-06-26T12:00:00Z",
            "dlq_id": dlq_id,
        },
    ]
    for bad in two_selector_cases:
        with pytest.raises(jsonschema.ValidationError):
            validator.validate(bad)


def test_schema_versions_example_validates_and_pins_v1():
    spec = _load_spec()
    example = spec["paths"]["/v1/bus/schema-versions"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["examples"]["v1"]["value"]
    try:
        _component_validator(spec, "SchemaVersions").validate(example)
    except jsonschema.ValidationError as exc:
        pytest.fail(f"schema-versions example failed validation: {exc.message}")
    assert 1 in example["supported"]
    sv = spec["components"]["schemas"]["SchemaVersions"]
    assert sv["properties"]["envelope_schema_id"]["const"] == "anoryx:event-envelope:v1"


def test_o002_honesty_boundaries_present_verbatim():
    # Boundaries (a)-(c) must appear verbatim in the binding contract (rule 5).
    desc = _load_spec()["info"]["description"]
    assert "Replay and DLQ are SPECIFIED, not implemented — O-003 builds the machinery." in desc
    assert "Delivery is at-least-once; consumers MUST dedupe on idempotency_key." in desc
    assert "Unknown-version handling is reject-to-DLQ." in desc


def test_bus_operations_carry_mtls_plus_service_token():
    # Every new bus op must pair mTLS with a second factor (the same posture O-001's
    # test_mutualtls_applied_to_every_operation enforces globally).
    spec = _load_spec()
    bus_ops = [
        ("/v1/bus/replays", "post"),
        ("/v1/bus/dlq", "get"),
        ("/v1/bus/schema-versions", "get"),
    ]
    for path, method in bus_ops:
        security = spec["paths"][path][method]["security"]
        assert security, f"{method.upper()} {path} has no security requirement"
        for requirement in security:
            assert "mutualTLS" in requirement
            assert "serviceToken" in requirement
