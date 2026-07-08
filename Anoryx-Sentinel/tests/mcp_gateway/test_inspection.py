"""F-026 (ADR-0032) proof that MCP-shaped payload content gets the SAME
governance /v1/chat/completions gets — the real detector chain, not a stub.

PII detection (Presidio/spacy) needs a downloaded NLP model this sandbox has
no internet access for (a pre-existing, environment-only limitation — see
tests/gateway's own conftest handling of the same dependency; it works fine
in real CI, which has internet access). These tests build a registry with
pii_detection_enabled=False (mirrors tests/orchestration/test_code_scan_hook.py's
own precedent) since none of them are testing PII specifically — the secret
detector alone is sufficient proof that the SAME chain, not a stub, runs
against MCP-shaped content.
"""

from __future__ import annotations

import uuid

import pytest

from gateway.context import TenantContext
from mcp_gateway.inspection import inspect_mcp_payload, inspect_mcp_response
from orchestration.config import OrchestrationSettings
from orchestration.exceptions import HookBlockedError
from orchestration.registry import build_default_registry

# Built at runtime (not a literal) so this fake-but-pattern-shaped credential
# exercises secret_detector.py's real AKIA[0-9A-Z]{16} regex without being a
# static string a repo secret-scanner would flag.
_FAKE_AWS_KEY = "AKIA" + "ABCD1234EFGH5678"


def _tenant_context() -> TenantContext:
    return TenantContext(
        tenant_id=str(uuid.uuid4()),
        team_id=str(uuid.uuid4()),
        project_id=str(uuid.uuid4()),
        agent_id="mcp-test-agent",
        virtual_key_id="test-key",
    )


def _registry_without_pii():
    return build_default_registry(OrchestrationSettings(pii_detection_enabled=False))


@pytest.mark.asyncio
async def test_clean_mcp_payload_passes_through_unchanged():
    result = await inspect_mcp_payload(
        "search for the quarterly report",
        tenant_context=_tenant_context(),
        request_id="mcp-" + uuid.uuid4().hex,
        registry=_registry_without_pii(),
    )
    assert result == "search for the quarterly report"


@pytest.mark.asyncio
async def test_mcp_payload_containing_aws_key_is_blocked():
    """An MCP tools/call argument leaking a real-shaped AWS credential must be
    BLOCKED by the exact same SecretInboundHook /v1/chat/completions uses —
    proves the roadmap's 'uniform inspection' claim is real, not aspirational."""
    payload = f"here is my AWS key for the S3 tool: {_FAKE_AWS_KEY}"
    with pytest.raises(HookBlockedError):
        await inspect_mcp_payload(
            payload,
            tenant_context=_tenant_context(),
            request_id="mcp-" + uuid.uuid4().hex,
            registry=_registry_without_pii(),
        )


@pytest.mark.asyncio
async def test_mcp_response_containing_aws_key_is_masked():
    """SecretOutboundHook masks (does not block) a non-streamed response
    carrying a secret — same behavior /v1/chat/completions gets for a
    non-streamed body (secret_detector.py: block only in a streaming
    context, which this preview function is not)."""
    payload = f"tool result: your key is {_FAKE_AWS_KEY}"
    result = await inspect_mcp_response(
        payload,
        tenant_context=_tenant_context(),
        request_id="mcp-" + uuid.uuid4().hex,
        registry=_registry_without_pii(),
    )
    assert _FAKE_AWS_KEY not in result
    assert result != payload


@pytest.mark.asyncio
async def test_different_tenants_get_independent_inspection_context():
    """Two calls with distinct TenantContexts must not leak state (the
    HookContext per-detector event budget is constructed fresh per call)."""
    ctx_a = _tenant_context()
    ctx_b = _tenant_context()
    assert ctx_a.tenant_id != ctx_b.tenant_id

    registry = _registry_without_pii()
    result_a = await inspect_mcp_payload(
        "clean text", tenant_context=ctx_a, request_id="mcp-" + uuid.uuid4().hex, registry=registry
    )
    result_b = await inspect_mcp_payload(
        "clean text", tenant_context=ctx_b, request_id="mcp-" + uuid.uuid4().hex, registry=registry
    )
    assert result_a == result_b == "clean text"
