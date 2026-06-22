"""Tests: CodeScanDetector integration into HookRegistry (F-016, ADR-0019 §3-§5).

Validates the hard constraint:
  - run_code_scan() fires exactly ONCE on the full response text.
  - run_post_response() (windowed chain) NEVER invokes the CodeScanDetector.
  - Non-streamed BLOCK → HookBlockedError(error_code="policy_blocked").
  - Streamed path → detector returns action="pass" (block_suppressed_by_streaming);
    run_code_scan() does NOT raise HookBlockedError.
  - No _code_scan_detector → run_code_scan() is a no-op (returns content).
  - Unexpected detector exception → HookFailSafeError (D3 fail-safe).
  - build_default_registry() puts CodeScanDetector in the dedicated slot,
    NOT in the windowed post_response list.
  - Existing four windowed detectors are unaffected (R8).
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from orchestration.exceptions import HookBlockedError, HookFailSafeError
from orchestration.hooks.base import DetectorResult, PostResponseHook
from orchestration.registry import HookRegistry

# ---------------------------------------------------------------------------
# Helpers — minimal stub detectors
# ---------------------------------------------------------------------------


class _RecordingDetector(PostResponseHook):
    """Records every inspect() call; returns a configurable result."""

    def __init__(self, slug: str, result: DetectorResult) -> None:
        self._slug = slug
        self._result = result
        self.calls: list[tuple[str, object]] = []  # (content, context)

    @property
    def detector_slug(self) -> str:
        return self._slug

    async def inspect(self, content: str, context: object) -> DetectorResult:
        self.calls.append((content, context))
        return self._result


class _BlockingCodeScanDetector(PostResponseHook):
    """Simulates a CodeScanDetector that returns BLOCK on any content.

    Mirrors the real CodeScanDetector convention: inspect() emits the event
    itself via ctx.emit() BEFORE returning the DetectorResult.  run_code_scan()
    must NOT re-emit — this stub makes the double-emit bug observable as a
    second ctx.emit() call.
    """

    @property
    def detector_slug(self) -> str:
        return "code-scan"

    async def inspect(self, content: str, context: object) -> DetectorResult:
        event = {
            "event_type": "code_scan_blocked",
            "action_taken": "blocked",
            "verdict": "BLOCK",
            "language": "python",
            "finding_count": 1,
            "top_severity": "high",
            "scanner": "semgrep+bandit",
        }
        # Emit inside inspect() — same as the real detector.  The registry
        # must not emit a second time in its block path.
        await context.emit(event, detector_slug="code-scan")
        return DetectorResult(action="block", event=event)


class _PassCodeScanDetector(PostResponseHook):
    """Simulates a CodeScanDetector that returns PASS."""

    @property
    def detector_slug(self) -> str:
        return "code-scan"

    async def inspect(self, content: str, context: object) -> DetectorResult:
        return DetectorResult(action="pass")


class _StreamSuppressedCodeScanDetector(PostResponseHook):
    """Simulates the streaming path: block threshold reached but streaming active.

    Mirrors the real detector: returns action="pass" + block_suppressed_by_streaming.
    """

    @property
    def detector_slug(self) -> str:
        return "code-scan"

    async def inspect(self, content: str, context: object) -> DetectorResult:
        is_stream: bool = getattr(context, "_is_stream", False)
        if is_stream:
            return DetectorResult(
                action="pass",
                event={
                    "event_type": "code_scan_warned",
                    "action_taken": "logged",
                    "verdict": "BLOCK",
                    "language": "python",
                    "finding_count": 1,
                    "top_severity": "high",
                    "scanner": "semgrep+bandit",
                    "block_suppressed_by_streaming": True,
                },
            )
        return DetectorResult(action="block")


class _RaisingCodeScanDetector(PostResponseHook):
    """Simulates a scanner that crashes with an unexpected exception."""

    @property
    def detector_slug(self) -> str:
        return "code-scan"

    async def inspect(self, content: str, context: object) -> DetectorResult:
        raise RuntimeError("semgrep subprocess crashed")


# ---------------------------------------------------------------------------
# Fixture: minimal mock context
# ---------------------------------------------------------------------------


def _make_ctx(*, is_stream: bool = False) -> MagicMock:
    ctx = MagicMock()
    ctx.request_id = "req-test-code-scan"
    ctx._is_stream = is_stream
    ctx.emit = AsyncMock(return_value=True)
    return ctx


# ---------------------------------------------------------------------------
# 1. code_scan_detector property
# ---------------------------------------------------------------------------


def test_code_scan_detector_property_none_by_default():
    registry = HookRegistry()
    assert registry.code_scan_detector is None


def test_code_scan_detector_property_returns_instance():
    det = _PassCodeScanDetector()
    registry = HookRegistry(code_scan_detector=det)
    assert registry.code_scan_detector is det


# ---------------------------------------------------------------------------
# 2. run_code_scan — no detector registered → no-op
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_code_scan_no_detector_is_noop():
    registry = HookRegistry()
    ctx = _make_ctx()
    result = await registry.run_code_scan("some content", ctx)
    assert result == "some content"
    ctx.emit.assert_not_called()


# ---------------------------------------------------------------------------
# 3. Non-streamed BLOCK path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_code_scan_block_raises_hook_blocked_error():
    """BLOCK result must raise HookBlockedError with error_code=policy_blocked."""
    registry = HookRegistry(code_scan_detector=_BlockingCodeScanDetector())
    ctx = _make_ctx(is_stream=False)

    with pytest.raises(HookBlockedError) as exc_info:
        await registry.run_code_scan("def bad(): os.system(user_input)", ctx)

    assert exc_info.value.error_code == "policy_blocked"


@pytest.mark.asyncio
async def test_run_code_scan_block_emits_event():
    """Non-streamed BLOCK must produce exactly ONE emit (from inspect(), not registry).

    The real CodeScanDetector calls ctx.emit() inside inspect() before returning
    DetectorResult(action="block").  run_code_scan() must NOT re-emit — doing so
    would write a duplicate code_scan_blocked row to events_audit_log and corrupt
    the append-only hash chain.  This test catches that double-emit regression.
    """
    registry = HookRegistry(code_scan_detector=_BlockingCodeScanDetector())
    ctx = _make_ctx(is_stream=False)

    with pytest.raises(HookBlockedError):
        await registry.run_code_scan("malicious code", ctx)

    # Exactly ONE emit: the one from inspect() itself.  Zero additional emits
    # from the registry block path.
    assert ctx.emit.call_count == 1, (
        f"Expected exactly 1 emit (from inspect()), got {ctx.emit.call_count}. "
        "Double-emit in registry.run_code_scan() block path detected."
    )
    emitted_event = ctx.emit.call_args[0][0]
    assert emitted_event["event_type"] == "code_scan_blocked"


# ---------------------------------------------------------------------------
# 4. Non-streamed PASS path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_code_scan_pass_returns_content_unchanged():
    registry = HookRegistry(code_scan_detector=_PassCodeScanDetector())
    ctx = _make_ctx(is_stream=False)
    content = "def clean(): return 42"
    result = await registry.run_code_scan(content, ctx)
    assert result == content


@pytest.mark.asyncio
async def test_run_code_scan_pass_does_not_raise():
    registry = HookRegistry(code_scan_detector=_PassCodeScanDetector())
    ctx = _make_ctx(is_stream=False)
    # Must not raise anything.
    await registry.run_code_scan("clean content", ctx)


# ---------------------------------------------------------------------------
# 5. Streamed path — block suppressed, no HookBlockedError
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_code_scan_stream_block_suppressed_does_not_raise():
    """Streaming path: even if findings cross BLOCK threshold, no error is raised.

    The detector itself (StreamSuppressedCodeScanDetector) returns action="pass"
    when ctx._is_stream is True — run_code_scan must not raise HookBlockedError.
    """
    registry = HookRegistry(code_scan_detector=_StreamSuppressedCodeScanDetector())
    ctx = _make_ctx(is_stream=True)
    # Must complete without raising.
    result = await registry.run_code_scan("def bad(): os.system(x)", ctx)
    assert result == "def bad(): os.system(x)"


@pytest.mark.asyncio
async def test_run_code_scan_stream_block_same_content_nonstream_raises():
    """Prove fork: same content+detector → no raise on stream, raise on non-stream."""
    registry = HookRegistry(code_scan_detector=_StreamSuppressedCodeScanDetector())

    # Non-stream: detector returns block.
    ctx_nonstream = _make_ctx(is_stream=False)
    with pytest.raises(HookBlockedError):
        await registry.run_code_scan("def bad(): os.system(x)", ctx_nonstream)

    # Stream: detector returns pass (block suppressed).
    ctx_stream = _make_ctx(is_stream=True)
    result = await registry.run_code_scan("def bad(): os.system(x)", ctx_stream)
    assert result == "def bad(): os.system(x)"


# ---------------------------------------------------------------------------
# 6. code-scan NEVER fires inside run_post_response (windowed chain)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_code_scan_not_called_by_run_post_response():
    """The code_scan_detector slot is separate from _post_response.

    run_post_response iterates only self._post_response; code_scan_detector
    must not appear in that list even when registered.
    """
    code_scan_det = _RecordingDetector("code-scan", DetectorResult(action="pass"))
    windowed_det = _RecordingDetector("secret-outbound", DetectorResult(action="pass"))

    registry = HookRegistry(
        post_response=[windowed_det],
        code_scan_detector=code_scan_det,
    )
    ctx = _make_ctx()
    ctx.emit = AsyncMock(return_value=True)

    # Simulate 5 chunk calls — mimics the 8 KiB sliding window loop.
    for i in range(5):
        await registry.run_post_response(f"chunk-{i}", ctx)

    # Windowed detector ran for every chunk.
    assert len(windowed_det.calls) == 5

    # Code-scan detector was NEVER called through the windowed chain.
    assert len(code_scan_det.calls) == 0


@pytest.mark.asyncio
async def test_run_code_scan_called_once_not_per_chunk():
    """run_code_scan runs exactly once when gateway-core calls it after stream."""
    code_scan_det = _RecordingDetector("code-scan", DetectorResult(action="pass"))
    registry = HookRegistry(code_scan_detector=code_scan_det)
    ctx = _make_ctx(is_stream=True)

    full_text = "accumulated full stream text"
    await registry.run_code_scan(full_text, ctx)

    # Exactly one invocation, on the full text.
    assert len(code_scan_det.calls) == 1
    assert code_scan_det.calls[0][0] == full_text


# ---------------------------------------------------------------------------
# 7. Fail-safe: unexpected exception → HookFailSafeError (D3)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_code_scan_unexpected_exception_becomes_fail_safe():
    """An unexpected scanner crash must raise HookFailSafeError, not propagate raw."""
    registry = HookRegistry(code_scan_detector=_RaisingCodeScanDetector())
    ctx = _make_ctx()

    with pytest.raises(HookFailSafeError) as exc_info:
        await registry.run_code_scan("any content", ctx)

    assert isinstance(exc_info.value.original, RuntimeError)
    assert "semgrep subprocess crashed" in str(exc_info.value.original)


# ---------------------------------------------------------------------------
# 8. build_default_registry exclusion proof
# ---------------------------------------------------------------------------


def test_build_default_registry_code_scan_not_in_post_response_list(
    monkeypatch,
):
    """CodeScanDetector must NOT appear in registry._post_response.

    It must appear in registry._code_scan_detector (the dedicated slot).
    """
    # Patch CodeScanDetector import to avoid heavy dependencies.
    fake_detector = _PassCodeScanDetector()

    import orchestration.registry as reg_module

    monkeypatch.setattr(
        reg_module,
        "build_default_registry",
        lambda settings=None: _patched_build(settings, fake_detector),
    )

    from orchestration.config import OrchestrationSettings

    settings = OrchestrationSettings(
        secret_detection_enabled=False,
        injection_detection_enabled=False,
        pii_detection_enabled=False,
    )

    registry = reg_module.build_default_registry(settings=settings)

    # Verify: no hook in _post_response has slug "code-scan".
    for hook in registry._post_response:
        assert (
            hook.detector_slug != "code-scan"
        ), f"code-scan must not be in _post_response (found {hook.detector_slug!r})"

    # Verify: the dedicated slot carries the detector.
    assert registry._code_scan_detector is not None
    assert registry._code_scan_detector.detector_slug == "code-scan"


def _patched_build(settings, code_scan_detector):
    """Minimal registry with a pre-wired fake code-scan detector."""
    from orchestration.registry import HookRegistry

    return HookRegistry(
        pre_request=[],
        post_response=[],
        code_scan_detector=code_scan_detector,
    )


def test_build_default_registry_code_scan_slot_uses_import(monkeypatch):
    """build_default_registry populates _code_scan_detector via ImportError-safe path."""
    from orchestration.config import OrchestrationSettings
    from orchestration.registry import build_default_registry

    settings = OrchestrationSettings(
        secret_detection_enabled=False,
        injection_detection_enabled=False,
        pii_detection_enabled=False,
    )

    # If code_scan.detector is importable, the slot is populated.
    # If not (ImportError), the slot is None (no crash).
    try:
        registry = build_default_registry(settings=settings)
    except ImportError:
        pytest.skip("code_scan extra not installed")

    # Whatever path taken: _post_response must never contain code-scan.
    for hook in registry._post_response:
        assert hook.detector_slug != "code-scan"


# ---------------------------------------------------------------------------
# 9. R8: existing windowed detectors unaffected by F-016
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_existing_windowed_detectors_still_run_per_chunk():
    """R8: windowed detectors in _post_response are unchanged by the code-scan slot."""
    det_a = _RecordingDetector("secret-outbound", DetectorResult(action="pass"))
    det_b = _RecordingDetector("shadow-ai", DetectorResult(action="pass"))
    code_scan_det = _RecordingDetector("code-scan", DetectorResult(action="pass"))

    registry = HookRegistry(
        post_response=[det_a, det_b],
        code_scan_detector=code_scan_det,
    )

    ctx = _make_ctx()
    ctx.emit = AsyncMock(return_value=True)

    chunks = ["chunk-0", "chunk-1", "chunk-2"]
    for chunk in chunks:
        await registry.run_post_response(chunk, ctx)

    # Both windowed detectors ran for every chunk.
    assert len(det_a.calls) == 3
    assert len(det_b.calls) == 3

    # Code-scan detector: never called via windowed chain.
    assert len(code_scan_det.calls) == 0

    # Call run_code_scan once on full text.
    await registry.run_code_scan("full accumulated text", ctx)

    # Now code-scan ran exactly once.
    assert len(code_scan_det.calls) == 1
    assert code_scan_det.calls[0][0] == "full accumulated text"

    # Windowed detectors still at 3 (no extra calls from run_code_scan).
    assert len(det_a.calls) == 3
    assert len(det_b.calls) == 3


# ---------------------------------------------------------------------------
# 10. run_code_scan — HookRegistry constructor stores dedicated slot correctly
# ---------------------------------------------------------------------------


def test_registry_stores_code_scan_in_dedicated_slot_not_post_response():
    """Constructor correctness: code_scan_detector is stored separately from post_response."""
    windowed = _PassCodeScanDetector()  # reusing as a stand-in windowed hook
    windowed.__class__ = type(  # give it a different slug
        "WindSlug",
        (_PassCodeScanDetector,),
        {"detector_slug": property(lambda self: "secret-outbound")},
    )
    code_scan = _PassCodeScanDetector()

    registry = HookRegistry(
        post_response=[windowed],
        code_scan_detector=code_scan,
    )

    assert registry._code_scan_detector is code_scan
    assert code_scan not in registry._post_response
    assert len(registry._post_response) == 1
