"""Delta policy signing (D-005).

Delta is the spend authority that signs budget-enforcement policies; the Orchestrator
(O-004) is pass-through and never signs (ADR-0004 Fork A), and Sentinel
``intake_policy()`` is the verifying authority. This package vendors a byte-identical
copy of Sentinel's ``policy.crypto`` canonicalization so a Delta-signed policy is
accepted by the real Sentinel verifier, while keeping Delta independently deployable (no
runtime dependency on the Sentinel package). A conformance test
(``tests/policy/test_signer_conformance.py``) imports Sentinel's ``policy.crypto`` and
asserts the deterministic primitives agree byte-for-byte and that a Delta signature
verifies, so the vendored copy can never silently drift from the verifier (ADR-0005 §5).
"""
