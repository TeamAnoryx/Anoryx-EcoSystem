"""Gateway compliance endpoint tests (F-011, ADR-0013 §10 vectors 9, 13).

Covers:
  - vector 13: unauthenticated requests → 401 on both endpoints.
  - vector 9:  cross-tenant structural impossibility + extra 'tenant_id' field
               in export body → 422; generate_evidence always called with
               server-resolved tenant_id (never client-supplied); compliance_*
               audit event emitted for tenant A.
  - happy-path: valid tenant-A key → 200 evidence summary with readiness_score
               + disclaimer; POST export → 200 application/zip with PK magic
               and verifiable JWS.
  - edge cases: bad framework → 400; reversed window → 400; missing signing
               keys → 500 with no key-path leakage; emit failure → still 200.

Gateway tests mock the compliance layer (generate_evidence, read_chain_segment,
analyze_gaps) at the route boundary — DB-backed compliance correctness is
covered by tests/compliance/.  Auth and tenant resolution are exercised through
the real middleware stack with a mocked VirtualApiKeyRepository.

Auth mechanism: the existing gateway virtual-key Bearer path is reused exactly
as /v1/chat/completions uses it.  No admin-scope concept exists (D1, ADR-0013).
Endpoints are NOT in _AUTH_EXEMPT_PATHS.

Honest framing: "audit-ready" throughout; never "compliant".
"""

from __future__ import annotations

import hashlib
import json
import types
import uuid
import zipfile
from contextlib import ExitStack, asynccontextmanager
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

# ---------------------------------------------------------------------------
# Test IDs — must be valid UUID v4 to pass TenantContextMiddleware validation.
# ---------------------------------------------------------------------------

_TENANT_A_ID = str(uuid.uuid4())
_TENANT_B_ID = str(uuid.uuid4())
_TEAM_ID = str(uuid.uuid4())
_PROJECT_ID = str(uuid.uuid4())
_AGENT_ID = "compliance-engine"
_VIRTUAL_KEY_A = "sk-sentinel-compliance-test-a"

_T0 = "2025-01-01T00:00:00Z"
_T1 = "2027-01-01T00:00:00Z"
_FRAMEWORK = "SOC2"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def truncate_audit_log_after():
    """No-op fixture matching the compliance conftest TRUNCATE fixture interface.

    Gateway compliance tests use fully mocked compliance layers — no real rows
    are committed to events_audit_log.  The fixture is requested on
    test_cross_tenant_pack_request_denied per the AFFU hybrid plan (scoped, not
    autouse) so that the call site is consistent across all three cross-tenant
    tests, but no actual truncation is needed here.
    """
    yield


@pytest.fixture()
def signing_keys(tmp_path: Path, monkeypatch):
    """Generate P-256 keypair, write PEMs, set env vars."""
    from policy.crypto import generate_keypair, private_key_to_pem, public_key_to_pem

    priv, pub = generate_keypair()
    priv_path = tmp_path / "compliance_signing.pem"
    pub_path = tmp_path / "compliance_pubkey.pem"
    priv_path.write_bytes(private_key_to_pem(priv))
    pub_path.write_bytes(public_key_to_pem(pub))
    monkeypatch.setenv("COMPLIANCE_PACK_SIGNING_KEY_PATH", str(priv_path))
    monkeypatch.setenv("COMPLIANCE_PACK_PUBKEY_PATH", str(pub_path))
    return priv, pub, priv_path, pub_path


# ---------------------------------------------------------------------------
# Fake compliance layer — used to isolate gateway routing from real DB
# ---------------------------------------------------------------------------


def _make_fake_projection(framework: str = "SOC2", fw_version: str = "2017-TSC-rev2022"):
    """Return a minimal EvidenceProjection with one 'passed' injection control."""
    from compliance.evidence import ChainTip, EvidenceProjection

    return EvidenceProjection(
        framework=framework,
        framework_version=fw_version,
        t0=datetime(2025, 1, 1, tzinfo=timezone.utc),
        t1=datetime(2027, 1, 1, tzinfo=timezone.utc),
        event_counts=types.MappingProxyType({"injection_detected": 3}),
        total_events_in_window=3,
        chain_tip=ChainTip(
            sequence_number=42,
            row_hash="a" * 64,
        ),
    )


def _make_fake_gap_report(framework: str = "SOC2", fw_version: str = "2017-TSC-rev2022"):
    """Return a minimal GapReport with one passed control."""
    from compliance.constants import DISCLAIMER
    from compliance.gap_analysis import ControlResult, GapReport

    result = ControlResult(
        control_id="CC7.2",
        title="System monitoring for anomalies",
        status="passed",
        evidence_event_types=("injection_detected",),
        evidence_count=3,
        rationale="Test control.",
    )
    return GapReport(
        framework=framework,
        framework_version=fw_version,
        t0=datetime(2025, 1, 1, tzinfo=timezone.utc),
        t1=datetime(2027, 1, 1, tzinfo=timezone.utc),
        results=(result,),
        total=1,
        passed=1,
        gap=0,
        not_applicable=0,
        not_covered=0,
        applicable=1,
        readiness=1.0,
        disclaimer=DISCLAIMER,
    )


def _make_fake_chain_links():
    """Return an empty chain-links tuple (no real DB needed)."""
    return ()


# ---------------------------------------------------------------------------
# App factory helpers — patches returned as list so callers keep them active.
# ---------------------------------------------------------------------------


def _make_key_row(
    tenant_id: str = _TENANT_A_ID,
    team_id: str = _TEAM_ID,
    project_id: str = _PROJECT_ID,
    agent_id: str = _AGENT_ID,
    key_id: str | None = None,
) -> MagicMock:
    row = MagicMock()
    row.tenant_id = tenant_id
    row.team_id = team_id
    row.project_id = project_id
    row.agent_id = agent_id
    row.key_id = key_id or str(uuid.uuid4())
    row.is_active = True
    return row


def _build_compliance_patches(
    key_row: MagicMock | None = None,
    audit_append_fn=None,
    mock_generate_evidence=True,
    mock_read_chain=True,
    mock_analyze_gaps=True,
    captured_tenant_ids: list | None = None,
):
    """Return (patches_list, audit_repo_mock, fake_gen_fn).

    Caller keeps all patches active during the entire request lifecycle via
    ExitStack (mirrors test_auth.py/_build_app_patches pattern).

    mock_generate_evidence: when True, replaces generate_evidence with a spy
    that returns a minimal fake projection (no live DB required).
    captured_tenant_ids: if provided, the spy appends each tenant_id call to
    the list (for vector 9 assertions).
    """
    from gateway.config import _reset_settings

    _reset_settings()

    if key_row is None:
        key_row = _make_key_row()

    audit_append_fn = audit_append_fn or AsyncMock(return_value=MagicMock())

    audit_repo = MagicMock()
    audit_repo.append = audit_append_fn

    auth_repo = MagicMock()
    auth_repo.lookup_by_plaintext = AsyncMock(return_value=key_row)

    @asynccontextmanager
    async def _privileged_cm():
        session = MagicMock()

        @asynccontextmanager
        async def _begin():
            yield MagicMock()

        session.begin = _begin
        yield session

    import gateway.upstream.openai_proxy as proxy_mod

    proxy_mod._http_client = None

    patches = [
        patch("gateway.middleware.auth.get_privileged_session", _privileged_cm),
        patch("gateway.middleware.auth.VirtualApiKeyRepository", return_value=auth_repo),
        patch("gateway.routes.compliance.get_privileged_session", _privileged_cm),
        patch("gateway.routes.compliance.AuditLogRepository", return_value=audit_repo),
        patch("gateway.middleware.audit.get_privileged_session", _privileged_cm),
        patch("gateway.middleware.audit.AuditLogRepository", return_value=audit_repo),
    ]

    if mock_generate_evidence:

        async def _fake_generate_evidence(framework_map, t0, t1, *, tenant_id):
            if captured_tenant_ids is not None:
                captured_tenant_ids.append(tenant_id)
            return _make_fake_projection(
                framework=framework_map.framework,
                fw_version=framework_map.framework_version,
            )

        patches.append(
            patch("gateway.routes.compliance.generate_evidence", _fake_generate_evidence)
        )

    if mock_read_chain:

        async def _fake_read_chain(t0, t1, *, tenant_id):
            return _make_fake_chain_links()

        patches.append(patch("gateway.routes.compliance.read_chain_segment", _fake_read_chain))

    if mock_analyze_gaps:

        def _fake_analyze_gaps(framework_map, projection):
            return _make_fake_gap_report(
                framework=framework_map.framework,
                fw_version=framework_map.framework_version,
            )

        patches.append(patch("gateway.routes.compliance.analyze_gaps", _fake_analyze_gaps))

    return patches, audit_repo  # noqa: RET504


def _valid_headers(
    tenant_id: str = _TENANT_A_ID,
    team_id: str = _TEAM_ID,
    project_id: str = _PROJECT_ID,
    agent_id: str = _AGENT_ID,
    bearer: str = _VIRTUAL_KEY_A,
) -> dict:
    return {
        "X-Anoryx-Tenant-Id": tenant_id,
        "X-Anoryx-Team-Id": team_id,
        "X-Anoryx-Project-Id": project_id,
        "X-Anoryx-Agent-Id": agent_id,
        "Authorization": f"Bearer {bearer}",
        "Content-Type": "application/json",
    }


# ===========================================================================
# Vector 13 — Unauthenticated requests → 401 on both endpoints
# ===========================================================================


@pytest.mark.asyncio
async def test_compliance_endpoints_require_auth():
    """Vector 13: GET /v1/compliance/evidence and POST /v1/compliance/export
    WITHOUT a valid tenant Bearer key → 401 (both endpoints).

    No admin-scope concept exists in v1 (D1, ADR-0013 §2).
    These endpoints are NOT in _AUTH_EXEMPT_PATHS — auth is enforced by the
    same AuthMiddleware that guards /v1/chat/completions.
    Auth fails → 401 invalid_api_key (same error code as every other route).
    """
    patches, _ = _build_compliance_patches()

    evidence_params = {"framework": _FRAMEWORK, "t0": _T0, "t1": _T1}
    export_body = {"framework": _FRAMEWORK, "t0": _T0, "t1": _T1}

    # All four routing headers present, but NO Authorization header.
    headers_no_auth = {
        "X-Anoryx-Tenant-Id": _TENANT_A_ID,
        "X-Anoryx-Team-Id": _TEAM_ID,
        "X-Anoryx-Project-Id": _PROJECT_ID,
        "X-Anoryx-Agent-Id": _AGENT_ID,
        "Content-Type": "application/json",
    }

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # GET evidence — no auth.
            resp = await client.get(
                "/v1/compliance/evidence",
                params=evidence_params,
                headers=headers_no_auth,
            )
            assert resp.status_code == 401, (
                f"Expected 401 for unauthenticated GET /v1/compliance/evidence, "
                f"got {resp.status_code}: {resp.text}"
            )
            assert resp.json()["error_code"] == "invalid_api_key"

            # POST export — no auth.
            resp = await client.post(
                "/v1/compliance/export",
                json=export_body,
                headers=headers_no_auth,
            )
            assert resp.status_code == 401, (
                f"Expected 401 for unauthenticated POST /v1/compliance/export, "
                f"got {resp.status_code}: {resp.text}"
            )
            assert resp.json()["error_code"] == "invalid_api_key"

    # Also test: completely absent Authorization.
    patches2, _ = _build_compliance_patches()
    headers_bare = {
        "X-Anoryx-Tenant-Id": _TENANT_A_ID,
        "X-Anoryx-Team-Id": _TEAM_ID,
        "X-Anoryx-Project-Id": _PROJECT_ID,
        "X-Anoryx-Agent-Id": _AGENT_ID,
    }
    with ExitStack() as stack:
        for p in patches2:
            stack.enter_context(p)

        from gateway.main import create_app

        app2 = create_app()

        async with AsyncClient(transport=ASGITransport(app=app2), base_url="http://test") as client:
            resp = await client.get(
                "/v1/compliance/evidence",
                params=evidence_params,
                headers=headers_bare,
            )
            assert resp.status_code == 401

            resp = await client.post(
                "/v1/compliance/export",
                json=export_body,
                headers=headers_bare,
            )
            assert resp.status_code == 401


# ===========================================================================
# Vector 9 — Cross-tenant structural impossibility
# ===========================================================================


@pytest.mark.asyncio
async def test_cross_tenant_pack_request_denied(
    truncate_audit_log_after,  # noqa: ANN001 — fixture; no-op for gateway tests
):
    """Vector 9: cross-tenant override is STRUCTURALLY IMPOSSIBLE.

    ADR-0013 §10 vector 9: "Client-supplied tenant override — server-resolved
    tenant, no param → no override honored."

    (a) An injected 'tenant_id' field in POST /v1/compliance/export body →
        422 (Pydantic extra='forbid' closes the schema before generation runs).

    (b) generate_evidence is ALWAYS called with the server-resolved tenant_id
        from the Bearer key — never a client-supplied value. Verified by spy.

    (c) A compliance_* audit event is emitted and attributed to tenant A
        (real four IDs, agent_id='compliance-engine').

    Honest deviation from ADR-0013 §10 vector 9 wording ("403 + audited"):
    The ADR was written when a tenant_id param was hypothetically possible.
    With the CLOSED schema (extra='forbid'), the response is 422 (Pydantic
    Unprocessable Entity) — which is MORE restrictive than 403 because the
    field is structurally absent from the API surface. There is no attack
    surface to authorize/deny; the field is simply rejected. The audit
    (compliance_evidence_generated) is emitted only on successful requests;
    an invalid-schema request never reaches the generation path.
    """
    key_row_a = _make_key_row(tenant_id=_TENANT_A_ID)
    emitted_events: list[dict] = []

    async def _capture_append(event_data):
        emitted_events.append(dict(event_data))
        return MagicMock()

    captured_tenant_ids: list[str] = []
    patches, _ = _build_compliance_patches(
        key_row=key_row_a,
        audit_append_fn=_capture_append,
        captured_tenant_ids=captured_tenant_ids,
    )
    headers_a = _valid_headers(tenant_id=_TENANT_A_ID)

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # (a) Injected 'tenant_id' field → 422 (closed schema, extra='forbid').
            body_with_extra_tenant = {
                "framework": _FRAMEWORK,
                "t0": _T0,
                "t1": _T1,
                "tenant_id": _TENANT_B_ID,  # cross-tenant override attempt
            }
            resp = await client.post(
                "/v1/compliance/export",
                json=body_with_extra_tenant,
                headers=headers_a,
            )
            assert (
                resp.status_code == 422
            ), f"Expected 422 for extra 'tenant_id' field, got {resp.status_code}: {resp.text}"

            # (b) GET evidence for tenant A — spy verifies server-resolved tenant_id.
            resp = await client.get(
                "/v1/compliance/evidence",
                params={"framework": _FRAMEWORK, "t0": _T0, "t1": _T1},
                headers=headers_a,
            )
            assert (
                resp.status_code == 200
            ), f"Expected 200 for tenant A evidence, got {resp.status_code}: {resp.text}"

    # Assert generate_evidence was called with tenant A's server-resolved ID only.
    assert len(captured_tenant_ids) >= 1, "generate_evidence was not called"
    for tid in captured_tenant_ids:
        assert tid == _TENANT_A_ID, (
            f"generate_evidence called with tenant_id={tid!r}; "
            f"expected {_TENANT_A_ID!r} (server-resolved from Bearer key)"
        )

    # (c) Assert compliance_* event emitted and attributed to tenant A.
    compliance_events = [
        e for e in emitted_events if e.get("event_type", "").startswith("compliance_")
    ]
    assert (
        len(compliance_events) >= 1
    ), f"Expected at least one compliance_* audit event; emitted: {emitted_events}"
    for ev in compliance_events:
        assert ev["tenant_id"] == _TENANT_A_ID, (
            f"Compliance event attributed to {ev['tenant_id']!r}; " f"expected {_TENANT_A_ID!r}"
        )
        assert ev["agent_id"] == "compliance-engine"
        assert ev["action_taken"] == "logged"
        assert "framework" in ev


# ===========================================================================
# Happy-path tests
# ===========================================================================


@pytest.mark.asyncio
async def test_get_compliance_evidence_happy_path():
    """GET /v1/compliance/evidence → 200 with readiness_score + disclaimer.

    Mocks generate_evidence + analyze_gaps to return known-good data, then
    asserts the response conforms to ComplianceEvidenceSummary (openapi schema).
    """
    key_row_a = _make_key_row(tenant_id=_TENANT_A_ID)
    patches, _ = _build_compliance_patches(key_row=key_row_a)

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        headers_a = _valid_headers(tenant_id=_TENANT_A_ID)

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/v1/compliance/evidence",
                params={"framework": _FRAMEWORK, "t0": _T0, "t1": _T1},
                headers=headers_a,
            )

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    body = resp.json()

    # Required fields from ComplianceEvidenceSummary (openapi schema).
    assert body["framework"] == _FRAMEWORK
    assert "framework_version" in body
    assert "window" in body
    assert body["window"]["t0"] == _T0
    assert body["window"]["t1"] == _T1
    assert "controls" in body
    assert isinstance(body["controls"], list)
    assert len(body["controls"]) > 0
    assert "gaps" in body
    assert isinstance(body["gaps"], list)
    assert "readiness_score" in body
    score = body["readiness_score"]
    assert isinstance(score, (int, float)), f"readiness_score not numeric: {score!r}"
    assert 0.0 <= score <= 1.0, f"readiness_score {score!r} not in [0, 1]"
    assert "disclaimer" in body
    assert "Certification requires an accredited auditor" in body["disclaimer"]

    # Each control entry must have required fields and valid status.
    for ctrl in body["controls"]:
        assert "control_id" in ctrl
        assert "status" in ctrl
        assert ctrl["status"] in (
            "passed",
            "gap",
            "not_applicable",
            "not_covered",
        ), f"Unexpected control status: {ctrl['status']!r}"


@pytest.mark.asyncio
async def test_post_compliance_export_happy_path(signing_keys, tmp_path: Path):
    """POST /v1/compliance/export → 200 application/zip with PK magic + valid JWS.

    Mocks evidence/chain/gap layers to produce a deterministic pack, then:
    - Verifies response is 200 application/zip.
    - Verifies bytes start with PK (ZIP magic).
    - Verifies ZIP contains evidence.json, evidence.json.jws, pubkey.pem, manifest.json.
    - Verifies JWS with the test public key (Layer B signature).
    - Verifies manifest.json content_hash matches sha256 of evidence.json bytes.
    """
    priv, pub, priv_path, pub_path = signing_keys

    key_row_a = _make_key_row(tenant_id=_TENANT_A_ID)
    patches, _ = _build_compliance_patches(key_row=key_row_a)

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        headers_a = _valid_headers(tenant_id=_TENANT_A_ID)
        export_body = {"framework": _FRAMEWORK, "t0": _T0, "t1": _T1}

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/compliance/export",
                json=export_body,
                headers=headers_a,
            )

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    content_type = resp.headers.get("content-type", "")
    assert "zip" in content_type, f"Expected application/zip content-type, got {content_type!r}"

    zip_bytes = resp.content

    # ZIP magic bytes: PK (0x50 0x4B).
    assert (
        zip_bytes[:2] == b"PK"
    ), f"Response bytes don't start with ZIP magic PK; got {zip_bytes[:4]!r}"

    # Unpack and verify ZIP contents.
    with zipfile.ZipFile(BytesIO(zip_bytes)) as zf:
        names = set(zf.namelist())
        assert "evidence.json" in names, f"Missing evidence.json; ZIP contains: {names}"
        assert "evidence.json.jws" in names
        assert "pubkey.pem" in names
        assert "manifest.json" in names

        evidence_bytes = zf.read("evidence.json")
        jws_str = zf.read("evidence.json.jws").decode("ascii").strip()
        manifest_bytes = zf.read("manifest.json")

    # Parse evidence.json.
    evidence_dict = json.loads(evidence_bytes)
    assert evidence_dict.get("framework") == _FRAMEWORK
    assert "disclaimer" in evidence_dict
    assert "Certification requires an accredited auditor" in evidence_dict["disclaimer"]

    # Verify Layer B JWS with the test public key (will raise on tamper/bad sig).
    from policy.crypto import verify_compact_jws

    claims = verify_compact_jws(jws_str, pub)
    assert claims.get("framework") == _FRAMEWORK

    # Manifest content_hash must match sha256 of canonical evidence bytes.
    manifest_dict = json.loads(manifest_bytes)
    assert "content_hash" in manifest_dict
    assert len(manifest_dict["content_hash"]) == 64, "content_hash must be 64-char sha256 hex"
    assert (
        manifest_dict["content_hash"] == hashlib.sha256(evidence_bytes).hexdigest()
    ), "manifest.json content_hash does not match sha256 of evidence.json bytes"


# ===========================================================================
# Additional edge-case / regression tests
# ===========================================================================


@pytest.mark.asyncio
async def test_evidence_bad_framework_returns_400():
    """GET /v1/compliance/evidence with unsupported framework → 400 invalid_request."""
    patches, _ = _build_compliance_patches()
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/v1/compliance/evidence",
                params={"framework": "HIPAA", "t0": _T0, "t1": _T1},
                headers=_valid_headers(),
            )
    assert resp.status_code == 400, f"Expected 400, got {resp.status_code}: {resp.text}"
    assert resp.json()["error_code"] == "invalid_request"


@pytest.mark.asyncio
async def test_evidence_reversed_window_returns_400():
    """GET /v1/compliance/evidence with t0 >= t1 → 400 invalid_request."""
    patches, _ = _build_compliance_patches()
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/v1/compliance/evidence",
                # Reversed: t0 after t1.
                params={"framework": "SOC2", "t0": _T1, "t1": _T0},
                headers=_valid_headers(),
            )
    assert resp.status_code == 400, f"Expected 400, got {resp.status_code}: {resp.text}"
    assert resp.json()["error_code"] == "invalid_request"


@pytest.mark.asyncio
async def test_export_missing_signing_keys_returns_500(monkeypatch):
    """POST /v1/compliance/export with no signing key env vars → 500 internal_error.

    PackSigningKeyError maps to 500 with a generic message.
    Key paths MUST NOT appear in the error response (CLAUDE.md non-neg #4).
    """
    monkeypatch.delenv("COMPLIANCE_PACK_SIGNING_KEY_PATH", raising=False)
    monkeypatch.delenv("COMPLIANCE_PACK_PUBKEY_PATH", raising=False)

    # Mock evidence layers (no DB needed); signing key load will fail.
    patches, _ = _build_compliance_patches()
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/compliance/export",
                json={"framework": "SOC2", "t0": _T0, "t1": _T1},
                headers=_valid_headers(),
            )
    assert resp.status_code == 500, f"Expected 500, got {resp.status_code}: {resp.text}"
    body = resp.json()
    assert body["error_code"] == "internal_error"
    # Key paths must NOT appear in the response body.
    resp_text = json.dumps(body)
    assert "COMPLIANCE_PACK_SIGNING_KEY_PATH" not in resp_text
    assert "COMPLIANCE_PACK_PUBKEY_PATH" not in resp_text


@pytest.mark.asyncio
async def test_compliance_emit_is_best_effort():
    """Compliance meta-audit emit failure must NOT fail the evidence request.

    If _emit_compliance_event raises (e.g. DB error), the 200 evidence response
    is still returned. Best-effort: swallow + log at ERROR (mirrors
    emit_routing_decision behaviour — ADR-0013 §8 D7).
    """

    async def _failing_append(event_data):
        raise RuntimeError("simulated audit DB failure")

    patches, _ = _build_compliance_patches(audit_append_fn=_failing_append)
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/v1/compliance/evidence",
                params={"framework": "SOC2", "t0": _T0, "t1": _T1},
                headers=_valid_headers(),
            )

    # Response must be 200 even though the audit emit failed.
    assert (
        resp.status_code == 200
    ), f"Expected 200 despite audit failure, got {resp.status_code}: {resp.text}"
    body = resp.json()
    assert "disclaimer" in body
    assert "Certification requires an accredited auditor" in body["disclaimer"]


@pytest.mark.asyncio
async def test_export_body_closed_schema_rejects_unknown_fields():
    """POST /v1/compliance/export with an additional unknown field → 422.

    The ExportCompliancePackRequest schema has extra='forbid'. Any extra field
    (including a 'tenant_id' injection attempt) is rejected at the FastAPI
    validation layer before any evidence generation runs.
    """
    patches, _ = _build_compliance_patches()
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/compliance/export",
                json={
                    "framework": "SOC2",
                    "t0": _T0,
                    "t1": _T1,
                    "extra_field": "injected",
                },
                headers=_valid_headers(),
            )
    assert (
        resp.status_code == 422
    ), f"Expected 422 for extra field in export body, got {resp.status_code}: {resp.text}"


@pytest.mark.asyncio
async def test_evidence_response_contains_mandatory_disclaimer():
    """GET evidence response MUST contain the exact mandatory disclaimer text.

    Every compliance artifact carries "Automated evidence for audit preparation.
    Certification requires an accredited auditor." — the mandatory honest framing.
    """
    patches, _ = _build_compliance_patches()
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/v1/compliance/evidence",
                params={"framework": "SOC2", "t0": _T0, "t1": _T1},
                headers=_valid_headers(),
            )

    assert resp.status_code == 200
    body = resp.json()
    disclaimer = body.get("disclaimer", "")
    assert "Automated evidence for audit preparation" in disclaimer, (
        f"Mandatory disclaimer missing 'Automated evidence for audit preparation'; "
        f"got: {disclaimer!r}"
    )
    assert "Certification requires an accredited auditor" in disclaimer, (
        f"Mandatory disclaimer missing 'Certification requires an accredited auditor'; "
        f"got: {disclaimer!r}"
    )


# ===========================================================================
# Targeted branch coverage — GET evidence error paths
# ===========================================================================


@pytest.mark.asyncio
async def test_evidence_t0_malformed_datetime_returns_400():
    """GET evidence with an unparseable t0 string hits the GatewayError path → 400.

    Drives lines 111-119 in _parse_datetime (all strptime variants fail and
    fromisoformat also fails → raise GatewayError).
    """
    patches, _ = _build_compliance_patches()
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/v1/compliance/evidence",
                params={"framework": "SOC2", "t0": "not-a-date", "t1": _T1},
                headers=_valid_headers(),
            )
    assert resp.status_code == 400
    assert resp.json()["error_code"] == "invalid_request"


@pytest.mark.asyncio
async def test_evidence_t0_fromisoformat_fallback_path():
    """GET evidence with a datetime that falls through strptime but succeeds via fromisoformat.

    Drives lines 108-110 / 113-117 (the fallback fromisoformat branch that
    returns successfully after all strptime formats fail).
    A date-only string like '2025-01-01' is rejected by all three strptime
    patterns but accepted by fromisoformat; the tzinfo=None branch applies UTC.
    """
    patches, _ = _build_compliance_patches()
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Date-only ISO strings bypass all three strptime patterns but succeed
            # via fromisoformat; tzinfo is None so the UTC-replace branch fires.
            resp = await client.get(
                "/v1/compliance/evidence",
                params={"framework": "SOC2", "t0": "2025-01-01", "t1": "2025-02-01"},
                headers=_valid_headers(),
            )
    # Window is valid and evidence is mocked → should succeed
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_evidence_generate_evidence_raises_window_error_returns_400():
    """GET evidence where generate_evidence itself raises EvidenceWindowError → 400.

    Drives lines 264-265 (the EvidenceWindowError except branch inside the
    generate_evidence try/except block of the GET handler).
    """
    from compliance.errors import EvidenceWindowError

    async def _raise_window_error(framework_map, t0, t1, *, tenant_id):
        raise EvidenceWindowError("window became invalid during generation")

    patches, _ = _build_compliance_patches(mock_generate_evidence=False, mock_read_chain=False)
    patches.append(patch("gateway.routes.compliance.generate_evidence", _raise_window_error))

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/v1/compliance/evidence",
                params={"framework": "SOC2", "t0": _T0, "t1": _T1},
                headers=_valid_headers(),
            )

    assert resp.status_code == 400
    assert resp.json()["error_code"] == "invalid_request"


@pytest.mark.asyncio
async def test_evidence_generate_evidence_generic_exception_returns_500():
    """GET evidence where generate_evidence raises a generic Exception → 500.

    Drives lines 266-268 (the bare except-Exception branch after EvidenceWindowError
    in the GET handler's generate_evidence try block).
    """

    async def _raise_generic(framework_map, t0, t1, *, tenant_id):
        raise RuntimeError("unexpected DB failure")

    patches, _ = _build_compliance_patches(mock_generate_evidence=False, mock_read_chain=False)
    patches.append(patch("gateway.routes.compliance.generate_evidence", _raise_generic))

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/v1/compliance/evidence",
                params={"framework": "SOC2", "t0": _T0, "t1": _T1},
                headers=_valid_headers(),
            )

    assert resp.status_code == 500
    body = resp.json()
    assert body["error_code"] == "internal_error"
    # No internal exception detail must leak
    assert "RuntimeError" not in json.dumps(body)
    assert "unexpected DB failure" not in json.dumps(body)


@pytest.mark.asyncio
async def test_evidence_analyze_gaps_exception_returns_500():
    """GET evidence where analyze_gaps raises a generic Exception → 500.

    Drives lines 273-275 (the except-Exception branch in the analyze_gaps
    try block of the GET handler).
    """

    def _raise_gap_error(framework_map, projection):
        raise RuntimeError("gap analysis exploded")

    patches, _ = _build_compliance_patches(mock_analyze_gaps=False)
    patches.append(patch("gateway.routes.compliance.analyze_gaps", _raise_gap_error))

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/v1/compliance/evidence",
                params={"framework": "SOC2", "t0": _T0, "t1": _T1},
                headers=_valid_headers(),
            )

    assert resp.status_code == 500
    assert resp.json()["error_code"] == "internal_error"


@pytest.mark.asyncio
async def test_evidence_load_framework_exception_returns_500():
    """GET evidence where load_framework raises → 500 internal_error.

    Drives lines 257-259 (the except-Exception in the load_framework try block
    of the GET handler).
    """
    patches, _ = _build_compliance_patches(
        mock_generate_evidence=False,
        mock_read_chain=False,
        mock_analyze_gaps=False,
    )
    patches.append(
        patch(
            "gateway.routes.compliance.load_framework",
            side_effect=RuntimeError("YAML corrupt"),
        )
    )

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get(
                "/v1/compliance/evidence",
                params={"framework": "SOC2", "t0": _T0, "t1": _T1},
                headers=_valid_headers(),
            )

    assert resp.status_code == 500
    assert resp.json()["error_code"] == "internal_error"


# ===========================================================================
# Targeted branch coverage — POST export error paths
# ===========================================================================


@pytest.mark.asyncio
async def test_export_reversed_window_returns_400(signing_keys):
    """POST export with reversed window (t0 >= t1) → 400 invalid_request.

    Drives lines 353-354 (EvidenceWindowError branch in export validate_window).
    """
    priv, pub, priv_path, pub_path = signing_keys
    patches, _ = _build_compliance_patches()
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/compliance/export",
                json={"framework": "SOC2", "t0": _T1, "t1": _T0},
                headers=_valid_headers(),
            )

    assert resp.status_code == 400
    assert resp.json()["error_code"] == "invalid_request"


@pytest.mark.asyncio
async def test_export_load_framework_exception_returns_500(signing_keys):
    """POST export where load_framework raises → 500 internal_error.

    Drives lines 367-369 (except-Exception in the load_framework try block
    of the POST export handler).
    """
    priv, pub, priv_path, pub_path = signing_keys
    patches, _ = _build_compliance_patches(
        mock_generate_evidence=False,
        mock_read_chain=False,
        mock_analyze_gaps=False,
    )
    patches.append(
        patch(
            "gateway.routes.compliance.load_framework",
            side_effect=RuntimeError("YAML corrupt in export"),
        )
    )

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/compliance/export",
                json={"framework": "SOC2", "t0": _T0, "t1": _T1},
                headers=_valid_headers(),
            )

    assert resp.status_code == 500
    assert resp.json()["error_code"] == "internal_error"


@pytest.mark.asyncio
async def test_export_generate_evidence_window_error_returns_400(signing_keys):
    """POST export where generate_evidence raises EvidenceWindowError → 400.

    Drives lines 375-376 (EvidenceWindowError except branch inside the export
    handler's generate_evidence try block).
    """
    from compliance.errors import EvidenceWindowError

    priv, pub, priv_path, pub_path = signing_keys

    async def _raise_window_error(framework_map, t0, t1, *, tenant_id):
        raise EvidenceWindowError("window edge case")

    patches, _ = _build_compliance_patches(mock_generate_evidence=False, mock_read_chain=False)
    patches.append(patch("gateway.routes.compliance.generate_evidence", _raise_window_error))

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/compliance/export",
                json={"framework": "SOC2", "t0": _T0, "t1": _T1},
                headers=_valid_headers(),
            )

    assert resp.status_code == 400
    assert resp.json()["error_code"] == "invalid_request"


@pytest.mark.asyncio
async def test_export_generate_evidence_generic_exception_returns_500(signing_keys):
    """POST export where generate_evidence raises generic Exception → 500.

    Drives lines 377-379 (bare except-Exception after EvidenceWindowError in
    the export handler's generate_evidence try block).
    """
    priv, pub, priv_path, pub_path = signing_keys

    async def _raise_generic(framework_map, t0, t1, *, tenant_id):
        raise RuntimeError("DB down during export")

    patches, _ = _build_compliance_patches(mock_generate_evidence=False, mock_read_chain=False)
    patches.append(patch("gateway.routes.compliance.generate_evidence", _raise_generic))

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/compliance/export",
                json={"framework": "SOC2", "t0": _T0, "t1": _T1},
                headers=_valid_headers(),
            )

    assert resp.status_code == 500
    body = resp.json()
    assert body["error_code"] == "internal_error"
    assert "DB down" not in json.dumps(body)


@pytest.mark.asyncio
async def test_export_analyze_gaps_exception_returns_500(signing_keys):
    """POST export where analyze_gaps raises generic Exception → 500.

    Drives lines 384-386 (except-Exception in the gap-analysis try block of
    the POST export handler).
    """
    priv, pub, priv_path, pub_path = signing_keys

    def _raise_gap_error(framework_map, projection):
        raise RuntimeError("gap analysis failed in export")

    patches, _ = _build_compliance_patches(mock_analyze_gaps=False)
    patches.append(patch("gateway.routes.compliance.analyze_gaps", _raise_gap_error))

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/compliance/export",
                json={"framework": "SOC2", "t0": _T0, "t1": _T1},
                headers=_valid_headers(),
            )

    assert resp.status_code == 500
    assert resp.json()["error_code"] == "internal_error"


@pytest.mark.asyncio
async def test_export_pack_build_exception_returns_500(signing_keys):
    """POST export where pack build/sign raises generic Exception → 500.

    Drives lines 415-422 (except-Exception in the pack-record/sign/export try
    block at the end of the POST export handler, re-raise path for non-GatewayError).
    """
    priv, pub, priv_path, pub_path = signing_keys
    patches, _ = _build_compliance_patches()
    patches.append(
        patch(
            "gateway.routes.compliance.build_pack_record",
            side_effect=RuntimeError("pack record build failed"),
        )
    )

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/compliance/export",
                json={"framework": "SOC2", "t0": _T0, "t1": _T1},
                headers=_valid_headers(),
            )

    assert resp.status_code == 500
    body = resp.json()
    assert body["error_code"] == "internal_error"
    assert "pack record build failed" not in json.dumps(body)


@pytest.mark.asyncio
async def test_export_emit_best_effort_on_export_path(signing_keys):
    """POST export: audit emit failure on export path still returns 200.

    Drives lines 424-436 (the best-effort _emit_compliance_event call after
    successful pack export) and confirms that a failing emit is swallowed —
    the 200 response with the ZIP is still returned.
    """
    priv, pub, priv_path, pub_path = signing_keys

    async def _failing_append(event_data):
        raise RuntimeError("simulated audit DB failure during export emit")

    patches, _ = _build_compliance_patches(audit_append_fn=_failing_append)

    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/compliance/export",
                json={"framework": "SOC2", "t0": _T0, "t1": _T1},
                headers=_valid_headers(),
            )

    assert (
        resp.status_code == 200
    ), f"Expected 200 despite export emit failure, got {resp.status_code}: {resp.text}"
    assert resp.content[:2] == b"PK", "Response is not a valid ZIP"


@pytest.mark.asyncio
async def test_export_invalid_framework_value_returns_422():
    """POST export with an invalid framework value in the body → 422.

    Drives line 94 (raise ValueError inside ExportRequest._validate_framework),
    then the RequestValidationError re-raise at line 343, which FastAPI maps to 422.
    """
    patches, _ = _build_compliance_patches()
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/compliance/export",
                json={"framework": "HIPAA", "t0": _T0, "t1": _T1},
                headers=_valid_headers(),
            )

    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_evidence_t0_with_offset_timezone_parses_correctly():
    """GET evidence with a +HH:MM offset datetime is parsed via strptime %z path.

    Drives branch 108->110 in _parse_datetime: strptime with %Y-%m-%dT%H:%M:%S%z
    returns a tz-aware datetime so the 'if dt.tzinfo is None' branch is False
    (i.e., skip the replace), then return dt directly (line 110).
    """
    patches, _ = _build_compliance_patches()
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # +00:00 suffix matches %Y-%m-%dT%H:%M:%S%z and returns tz-aware datetime.
            resp = await client.get(
                "/v1/compliance/evidence",
                params={
                    "framework": "SOC2",
                    "t0": "2025-01-01T00:00:00+00:00",
                    "t1": "2025-06-01T00:00:00+00:00",
                },
                headers=_valid_headers(),
            )

    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_export_invalid_json_body_returns_400():
    """POST export with an unparseable body (not JSON) → 400 invalid_request.

    Drives lines 332-333 (the except-Exception branch in the JSON parse try block
    of the POST export handler, where _json.loads raises on non-JSON bytes).
    """
    patches, _ = _build_compliance_patches()
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)

        from gateway.main import create_app

        app = create_app()
        headers = _valid_headers()
        # Remove application/json so httpx sends raw bytes as-is.
        headers["Content-Type"] = "text/plain"
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.post(
                "/v1/compliance/export",
                content=b"this is not json {{{{",
                headers=headers,
            )

    assert resp.status_code == 400
    assert resp.json()["error_code"] == "invalid_request"
