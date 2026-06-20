"""Evidence pack export threat-model tests (F-011, ADR-0013 §10).

Covers vectors 2, 3, 5, 6, 8, 11, 12 from the threat model.

Vector 2  — tampered exported pack → signature verify fails.
Vector 3  — same inputs → byte-identical ZIP (deterministic export).
Vector 5  — embedded chain hashes verify offline without a live DB.
Vector 6  — full-record signature binding: altering any chain hash invalidates JWS.
Vector 8  — exported pack contains only the requesting tenant's chain data (RLS).
Vector 11 — no PII patterns in any generated pack.
Vector 12 — no secret/prompt markers in any generated pack.

DB-backed tests (vectors 5, 8) require:
  - Live Postgres at DATABASE_URL / APP_DATABASE_URL
  - SENTINEL_PROVISION_APP_ROLE=1

Pure-unit tests (vectors 2, 3, 6, 11, 12) have no DB dependency.

Honest framing: "audit-ready" throughout; never "compliant".
Every evidence artifact: "Certification requires an accredited auditor."
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import types
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from compliance.evidence import ChainLink, EvidenceProjection, read_chain_segment
from compliance.gap_analysis import GapReport, analyze_gaps
from compliance.mapping import ControlEntry, FrameworkMap
from compliance.pack import (
    build_pack_record,
    export_pack_zip,
    sign_pack,
    verify_chain_links_offline,
    verify_pack,
)
from persistence.repositories.audit_log_repository import AuditLogRepository
from policy.crypto import (
    CompactJWSError,
    canonical_claims,
    generate_keypair,
    private_key_to_pem,
    public_key_to_pem,
)

# ---------------------------------------------------------------------------
# Time constants
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
_T0 = _NOW - timedelta(hours=1)
_T1 = _NOW + timedelta(hours=1)

# ---------------------------------------------------------------------------
# Helpers — keypair + PEM writing
# ---------------------------------------------------------------------------


@pytest.fixture()
def keypair(tmp_path: Path):
    """Generate a fresh P-256 keypair, write PEMs to tmp_path."""
    priv, pub = generate_keypair()
    priv_path = tmp_path / "pack_signing.pem"
    pub_path = tmp_path / "pack_pubkey.pem"
    priv_path.write_bytes(private_key_to_pem(priv))
    pub_path.write_bytes(public_key_to_pem(pub))
    return priv, pub, priv_path, pub_path


@pytest.fixture()
def patched_env(monkeypatch, keypair):
    """Monkeypatch COMPLIANCE_PACK_SIGNING_KEY_PATH / PUBKEY_PATH env vars."""
    priv, pub, priv_path, pub_path = keypair
    monkeypatch.setenv("COMPLIANCE_PACK_SIGNING_KEY_PATH", str(priv_path))
    monkeypatch.setenv("COMPLIANCE_PACK_PUBKEY_PATH", str(pub_path))
    return priv, pub


# ---------------------------------------------------------------------------
# Helpers — minimal FrameworkMap + synthetic GapReport + EvidenceProjection
# ---------------------------------------------------------------------------

_SOC2_FMAP = FrameworkMap(
    framework="SOC2",
    framework_version="2017-TSC-rev2022",
    controls=(
        ControlEntry(
            control_id="CC7.2",
            title="System monitoring for anomalies",
            sentinel_controls=("injection_detection",),
            evidence_event_types=("injection_detected",),
            rationale="Test control.",
            status_override=None,
        ),
        ControlEntry(
            control_id="CC9.9",
            title="Vendor risk — N/A for gateway",
            sentinel_controls=(),
            evidence_event_types=(),
            rationale=None,
            status_override="not_applicable",
        ),
    ),
)


def _make_projection(
    event_counts: dict[str, int] | None = None,
    chain_tip=None,
) -> EvidenceProjection:
    counts = event_counts if event_counts is not None else {"injection_detected": 3}
    return EvidenceProjection(
        framework="SOC2",
        framework_version="2017-TSC-rev2022",
        t0=_T0,
        t1=_T1,
        event_counts=types.MappingProxyType(counts),
        total_events_in_window=sum(counts.values()),
        chain_tip=chain_tip,
    )


def _make_chain_links(n: int = 3, start_seq: int = 1) -> tuple[ChainLink, ...]:
    """Build a minimal syntactically-valid chain (sequential hashes)."""
    links: list[ChainLink] = []
    prev = "0" * 64  # genesis placeholder
    for i in range(n):
        seq = start_seq + i
        # Compute a deterministic row_hash from (prev, seq) for chain integrity.
        row_hash = hashlib.sha256(f"{prev}:{seq}".encode()).hexdigest()
        links.append(ChainLink(sequence_number=seq, prev_hash=prev, row_hash=row_hash))
        prev = row_hash
    return tuple(links)


def _build_report_and_record(
    chain_links: tuple[ChainLink, ...] | None = None,
    event_counts: dict[str, int] | None = None,
    chain_tip=None,
) -> tuple[GapReport, EvidenceProjection, tuple[ChainLink, ...], dict[str, Any]]:
    links = chain_links if chain_links is not None else _make_chain_links()
    projection = _make_projection(event_counts=event_counts, chain_tip=chain_tip)
    gap_report = analyze_gaps(_SOC2_FMAP, projection)
    record = build_pack_record(
        gap_report,
        projection,
        links,
        tenant_id="tenant-test-001",
        sentinel_version="2.0.0-test",
    )
    return gap_report, projection, links, record


# ---------------------------------------------------------------------------
# Vector 2 — Tampered pack → signature verification fails
# ---------------------------------------------------------------------------


def test_evidence_pack_tamper_detected(keypair) -> None:
    """Vector 2: mutating any byte of the pack after signing must fail verification.

    Arrange: sign a valid pack record.
    Act:     tamper with a field in the record and attempt to verify the original JWS.
    Assert:  verify_pack raises CompactJWSError or InvalidSignature.
    """
    import base64

    from cryptography.exceptions import InvalidSignature

    priv, pub, _, _ = keypair

    # Arrange
    _, _, _, record = _build_report_and_record()
    jws = sign_pack(record, priv)

    # Act — mutate a field without re-signing.
    tampered = dict(record)
    tampered["readiness"] = 0.9999  # changed without re-signing

    # Produce a forged JWS: replace the payload with the tampered record's canonical
    # bytes but keep the original signature.  The signature covers the original
    # payload bytes so verification must fail (full-record binding, vector 2).
    parts = jws.split(".")
    forged_payload = base64.urlsafe_b64encode(canonical_claims(tampered)).rstrip(b"=").decode()
    forged_token = f"{parts[0]}.{forged_payload}.{parts[2]}"

    with pytest.raises((CompactJWSError, InvalidSignature)):
        verify_pack(forged_token, pub)


# ---------------------------------------------------------------------------
# Vector 3 — Deterministic ZIP: same inputs → byte-identical archive
# ---------------------------------------------------------------------------


def test_evidence_pack_reproducible(keypair, tmp_path: Path) -> None:
    """Vector 3: export_pack_zip must produce a byte-identical archive for same inputs.

    Arrange: build a pack record and sign it.
    Act:     export to two different paths.
    Assert:  both ZIP files are byte-identical; canonical_claims is identical too.
    """
    priv, pub, _, _ = keypair

    # Arrange
    _, _, _, record = _build_report_and_record()
    jws = sign_pack(record, priv)

    # Act
    path_a = tmp_path / "pack_a.zip"
    path_b = tmp_path / "pack_b.zip"
    export_pack_zip(record, jws, pub, out_path=path_a)
    export_pack_zip(record, jws, pub, out_path=path_b)

    # Assert — byte-identical archives.
    bytes_a = path_a.read_bytes()
    bytes_b = path_b.read_bytes()
    assert bytes_a == bytes_b, (
        "export_pack_zip is NOT deterministic: two exports of the same record "
        "produced different bytes.  Check ZipInfo.date_time and file ordering."
    )

    # Also assert canonical_claims is stable across calls.
    assert canonical_claims(record) == canonical_claims(record)


# ---------------------------------------------------------------------------
# Vector 5 — Embedded chain hashes verify offline (no DB connection during check)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pack_chain_hashes_verify_offline(monkeypatch, keypair, tmp_path: Path) -> None:
    """Vector 5: embedded chain hashes must validate as a correct F-003 chain offline.

    Seeds rows for a SINGLE tenant so its sequence_numbers are contiguous.
    Reads the chain segment via read_chain_segment (monkeypatched to share the
    same session), builds a pack, then calls verify_chain_links_offline with
    NO live DB connection.

    NO-COMMIT pattern (Pattern A):
    Rows are seeded via _seed_savepoint_rows on a shared privileged session.
    Both AuditLogRepository.append and read_chain_segment see the same
    session → consistent chain without any committed rows.  The outer SAVEPOINT
    in the `session` fixture rolls back at test end → zero table pollution.

    Also tests negative: corrupt one embedded row_hash → offline check returns False.
    """
    priv, pub, _, _ = keypair

    raw_db_url = os.environ.get("DATABASE_URL", "")
    if not raw_db_url:
        pytest.skip("DATABASE_URL not set — skipping DB-backed pack chain test")

    db_url = re.sub(r"^postgresql(\+psycopg)?://", "postgresql+asyncpg://", raw_db_url)
    tenant_id = f"tenant-chain-v5-{uuid.uuid4().hex[:8]}"

    # Arrange — open a shared privileged session for both seed + read.
    engine = create_async_engine(
        db_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )
    try:
        factory = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
        )
        async with factory() as shared_session:
            async with shared_session.begin():
                # Seed 4 rows via savepoint (uncommitted, visible only in this session).
                await _seed_savepoint_rows(shared_session, tenant_id, count=4)

                # Monkeypatch compliance.evidence.get_tenant_session → shared session.
                _patch_tenant_session_pack(monkeypatch, shared_session, tenant_id)

                # Read the chain segment via the shared session.
                chain_links = await read_chain_segment(_T0, _T1, tenant_id=tenant_id)
                assert len(chain_links) == 4, (
                    f"Expected 4 chain links, got {len(chain_links)}.  "
                    "Ensure rows were seeded inside the test window."
                )

                # Build and sign the pack.
                _, _, _, record = _build_report_and_record(chain_links=chain_links)
                jws = sign_pack(record, priv)
                zip_path = tmp_path / "pack_v5.zip"
                export_pack_zip(record, jws, pub, out_path=zip_path)

                # Verify offline (no DB) — positive case.
                assert (
                    verify_chain_links_offline(record) is True
                ), "verify_chain_links_offline returned False for a valid contiguous chain."

                # Verify offline — negative: corrupt one embedded row_hash.
                corrupted = copy.deepcopy(record)
                corrupted["chain"]["links"][0]["row_hash"] = "a" * 64  # wrong hash
                assert (
                    verify_chain_links_offline(corrupted) is False
                ), "verify_chain_links_offline returned True despite a corrupted row_hash."

                # Inner transaction rolls back here (savepoint); no committed rows.
    finally:
        await engine.dispose()


# ---------------------------------------------------------------------------
# Vector 6 — Full-record signature binding: altering chain hash invalidates JWS
# ---------------------------------------------------------------------------


def test_pack_signature_covers_chain_hashes(keypair) -> None:
    """Vector 6: altering an embedded chain link hash must invalidate the ES256 JWS.

    The signature is computed over canonical_claims(record), which includes
    the 'chain' block.  Mutating any embedded hash changes the canonical bytes,
    breaking the signature (full-record binding — ADR-0013 §6 D5).

    Arrange: sign a valid record.
    Act:     alter an embedded chain link hash in the record dict; produce a
             forged JWS with the new payload but the ORIGINAL signature.
    Assert:  verify_pack raises CompactJWSError or InvalidSignature.
    """
    import base64

    from cryptography.exceptions import InvalidSignature  # noqa: F401 — raised by verify_pack

    priv, pub, _, _ = keypair

    # Arrange
    _, _, _, record = _build_report_and_record()
    jws = sign_pack(record, priv)

    # Act — alter an embedded chain link row_hash and forge the JWS.
    altered = copy.deepcopy(record)
    if altered["chain"]["links"]:
        altered["chain"]["links"][0]["row_hash"] = "b" * 64

    parts = jws.split(".")
    forged_payload = base64.urlsafe_b64encode(canonical_claims(altered)).rstrip(b"=").decode()
    forged_token = f"{parts[0]}.{forged_payload}.{parts[2]}"

    # Assert
    with pytest.raises((CompactJWSError, InvalidSignature)):
        verify_pack(forged_token, pub)


# ---------------------------------------------------------------------------
# Vector 8 — Export is tenant-scoped (RLS): no cross-tenant data in pack
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_tenant_scoped(keypair, tmp_path: Path, truncate_audit_log_after) -> None:
    """Vector 8: the exported pack must reflect ONLY the requesting tenant's chain data.

    Seeds committed rows for tenant A (4 rows) and tenant B (3 rows).
    Calls read_chain_segment for tenant A.
    Asserts the exported pack's chain.links contain only tenant-A sequence_numbers
    (none from tenant B) and link_count == 4.

    COMMITTED-SEED + TRUNCATE pattern (Pattern B):
    Both tenants' rows MUST be committed so that read_chain_segment's separate
    RLS-scoped connection (get_tenant_session) can see them.  This is the empirical
    cross-tenant RLS proof — a savepoint on the same session would not cross the
    connection boundary that RLS enforcement requires.

    The truncate_audit_log_after fixture TRUNCATEs the table in teardown (TRUNCATE
    bypasses the BEFORE DELETE trigger), restoring the empty-table precondition for
    test_single_event_first_row_uses_genesis_hash under any test ordering.
    """
    priv, pub, _, _ = keypair

    raw_db_url = os.environ.get("DATABASE_URL", "")
    if not raw_db_url:
        pytest.skip("DATABASE_URL not set — skipping DB-backed tenant isolation test")

    db_url = re.sub(r"^postgresql(\+psycopg)?://", "postgresql+asyncpg://", raw_db_url)
    tenant_a = f"tenant-pack-a-{uuid.uuid4().hex[:8]}"
    tenant_b = f"tenant-pack-b-{uuid.uuid4().hex[:8]}"

    # Seed both tenants' rows (committed, so RLS query can see them).
    await _seed_committed_rows(db_url, tenant_a, count=4)
    await _seed_committed_rows(db_url, tenant_b, count=3)

    # Generate pack for tenant A only.
    chain_links_a = await read_chain_segment(_T0, _T1, tenant_id=tenant_a)
    chain_links_b = await read_chain_segment(_T0, _T1, tenant_id=tenant_b)

    # Assert RLS scoped: tenant A sees only its own 4 rows.
    assert len(chain_links_a) == 4, f"Expected 4 links for tenant A, got {len(chain_links_a)}"
    assert len(chain_links_b) == 3, f"Expected 3 links for tenant B, got {len(chain_links_b)}"

    # Build + export pack for tenant A.
    _, _, _, record = _build_report_and_record(chain_links=chain_links_a)
    jws = sign_pack(record, priv)
    zip_path = tmp_path / "pack_tenant_a.zip"
    export_pack_zip(record, jws, pub, out_path=zip_path)

    # Parse the exported ZIP and verify chain links.
    with zipfile.ZipFile(zip_path) as zf:
        evidence_bytes = zf.read("evidence.json")
    evidence = json.loads(evidence_bytes)

    exported_seqs = {lk["sequence_number"] for lk in evidence["chain"]["links"]}
    tenant_b_seqs = {lk.sequence_number for lk in chain_links_b}

    assert evidence["chain"]["link_count"] == 4
    assert len(exported_seqs & tenant_b_seqs) == 0, (
        f"Pack for tenant A contains tenant B sequence_numbers: "
        f"{exported_seqs & tenant_b_seqs}.  RLS isolation has failed."
    )


# ---------------------------------------------------------------------------
# Vector 11 — No PII in any generated pack
# ---------------------------------------------------------------------------


def test_pack_no_pii(keypair, tmp_path: Path) -> None:
    """Vector 11: the serialized pack must contain no PII patterns.

    Checks the canonical pack bytes for SSN, email, and phone-number patterns.
    The pack record contains only metadata and opaque hashes (R6).
    """
    priv, pub, _, _ = keypair

    # Arrange — build a record with benign metadata.
    _, _, _, record = _build_report_and_record()
    pack_bytes = canonical_claims(record)
    pack_str = pack_bytes.decode("utf-8")

    # Assert — no PII patterns present.
    ssn_re = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    email_re = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    phone_re = re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")

    assert not ssn_re.search(pack_str), "Pack contains SSN-like PII"
    assert not email_re.search(pack_str), "Pack contains email-like PII"
    assert not phone_re.search(pack_str), "Pack contains phone-number-like PII"

    # Also check the exported ZIP's evidence.json.
    jws = sign_pack(record, priv)
    zip_path = tmp_path / "pack_pii_check.zip"
    export_pack_zip(record, jws, pub, out_path=zip_path)

    with zipfile.ZipFile(zip_path) as zf:
        evidence_content = zf.read("evidence.json").decode("utf-8")

    assert not ssn_re.search(evidence_content), "evidence.json in ZIP contains SSN-like PII"
    assert not email_re.search(evidence_content), "evidence.json in ZIP contains email-like PII"
    assert not phone_re.search(evidence_content), "evidence.json in ZIP contains phone-like PII"


# ---------------------------------------------------------------------------
# Vector 12 — No secrets or prompt content in any generated pack
# ---------------------------------------------------------------------------


def test_pack_no_secrets(keypair, tmp_path: Path) -> None:
    """Vector 12: the serialized pack must contain no secret markers or prompt content.

    Checks the canonical pack bytes for API key prefixes, virtual-key prefixes,
    Bearer tokens, and raw prompt/content payload field names (R6).
    """
    priv, pub, _, _ = keypair

    # Arrange
    _, _, _, record = _build_report_and_record()
    pack_bytes = canonical_claims(record)
    pack_str = pack_bytes.decode("utf-8")

    # Assert — no secret markers or prompt/content payload fields.
    secret_markers = [
        "sk-",  # OpenAI-style API key prefix
        "Bearer ",  # HTTP Authorization header value
        "api_key",  # common field name
        "vk-",  # Sentinel virtual-key prefix
        '"prompt"',  # raw prompt payload field
        '"content"',  # raw content payload field
        '"messages"',  # raw messages payload field
    ]
    for marker in secret_markers:
        assert marker not in pack_str, (
            f"Pack contains secret/payload marker {marker!r} — R6 violation.  "
            "Pack records must contain only metadata and opaque hashes."
        )

    # Also check the exported ZIP.
    jws = sign_pack(record, priv)
    zip_path = tmp_path / "pack_secrets_check.zip"
    export_pack_zip(record, jws, pub, out_path=zip_path)

    with zipfile.ZipFile(zip_path) as zf:
        evidence_content = zf.read("evidence.json").decode("utf-8")

    for marker in secret_markers:
        assert (
            marker not in evidence_content
        ), f"evidence.json in ZIP contains secret/payload marker {marker!r} — R6 violation."


# ---------------------------------------------------------------------------
# load_pack_signing_keys — env / file failure paths (coverage)
# ---------------------------------------------------------------------------


def test_load_pack_signing_keys_missing_priv_env(monkeypatch, tmp_path: Path) -> None:
    """PackSigningKeyError raised when COMPLIANCE_PACK_SIGNING_KEY_PATH is unset."""
    from compliance.errors import PackSigningKeyError
    from compliance.pack import load_pack_signing_keys

    monkeypatch.delenv("COMPLIANCE_PACK_SIGNING_KEY_PATH", raising=False)
    monkeypatch.delenv("COMPLIANCE_PACK_PUBKEY_PATH", raising=False)

    with pytest.raises(PackSigningKeyError, match="COMPLIANCE_PACK_SIGNING_KEY_PATH"):
        load_pack_signing_keys()


def test_load_pack_signing_keys_missing_pub_env(monkeypatch, keypair) -> None:
    """PackSigningKeyError raised when COMPLIANCE_PACK_PUBKEY_PATH is unset."""
    from compliance.errors import PackSigningKeyError
    from compliance.pack import load_pack_signing_keys

    priv, pub, priv_path, _ = keypair
    monkeypatch.setenv("COMPLIANCE_PACK_SIGNING_KEY_PATH", str(priv_path))
    monkeypatch.delenv("COMPLIANCE_PACK_PUBKEY_PATH", raising=False)

    with pytest.raises(PackSigningKeyError, match="COMPLIANCE_PACK_PUBKEY_PATH"):
        load_pack_signing_keys()


def test_load_pack_signing_keys_unreadable_priv(monkeypatch, tmp_path: Path) -> None:
    """PackSigningKeyError raised when the private key file does not exist."""
    from compliance.errors import PackSigningKeyError
    from compliance.pack import load_pack_signing_keys

    monkeypatch.setenv("COMPLIANCE_PACK_SIGNING_KEY_PATH", str(tmp_path / "nonexistent_priv.pem"))
    monkeypatch.setenv("COMPLIANCE_PACK_PUBKEY_PATH", str(tmp_path / "nonexistent_pub.pem"))

    with pytest.raises(PackSigningKeyError, match="unreadable"):
        load_pack_signing_keys()


def test_load_pack_signing_keys_bad_priv_pem(monkeypatch, tmp_path: Path) -> None:
    """PackSigningKeyError raised when the private key file contains garbage."""
    from compliance.errors import PackSigningKeyError
    from compliance.pack import load_pack_signing_keys

    bad_pem = tmp_path / "bad_priv.pem"
    bad_pem.write_bytes(b"not-a-pem")
    pub_pem = tmp_path / "dummy_pub.pem"
    pub_pem.write_bytes(b"not-a-pem")
    monkeypatch.setenv("COMPLIANCE_PACK_SIGNING_KEY_PATH", str(bad_pem))
    monkeypatch.setenv("COMPLIANCE_PACK_PUBKEY_PATH", str(pub_pem))

    with pytest.raises(PackSigningKeyError):
        load_pack_signing_keys()


def test_load_pack_signing_keys_unreadable_pub(monkeypatch, keypair, tmp_path: Path) -> None:
    """PackSigningKeyError raised when the public key file does not exist."""
    from compliance.errors import PackSigningKeyError
    from compliance.pack import load_pack_signing_keys

    priv, pub, priv_path, _ = keypair
    monkeypatch.setenv("COMPLIANCE_PACK_SIGNING_KEY_PATH", str(priv_path))
    monkeypatch.setenv("COMPLIANCE_PACK_PUBKEY_PATH", str(tmp_path / "missing_pub.pem"))

    with pytest.raises(PackSigningKeyError, match="unreadable"):
        load_pack_signing_keys()


def test_load_pack_signing_keys_success(monkeypatch, keypair) -> None:
    """load_pack_signing_keys returns (priv, pub) when both env vars point at valid keys."""
    from compliance.pack import load_pack_signing_keys

    priv, pub, priv_path, pub_path = keypair
    monkeypatch.setenv("COMPLIANCE_PACK_SIGNING_KEY_PATH", str(priv_path))
    monkeypatch.setenv("COMPLIANCE_PACK_PUBKEY_PATH", str(pub_path))

    loaded_priv, loaded_pub = load_pack_signing_keys()
    # Both returned objects must be usable for signing and verification.
    _, _, _, record = _build_report_and_record()
    jws = sign_pack(record, loaded_priv)
    verify_pack(jws, loaded_pub)


# ---------------------------------------------------------------------------
# verify_chain_links_offline — additional branch coverage
# ---------------------------------------------------------------------------


def test_verify_chain_links_offline_empty_is_true() -> None:
    """An empty chain segment is trivially consistent."""
    record = {"chain": {"links": []}}
    assert verify_chain_links_offline(record) is True


def test_verify_chain_links_offline_malformed_hash() -> None:
    """A link with a non-hex row_hash must return False."""
    record = {
        "chain": {"links": [{"sequence_number": 1, "prev_hash": "0" * 64, "row_hash": "Z" * 64}]}
    }
    assert verify_chain_links_offline(record) is False


def test_verify_chain_links_offline_noncontiguous_not_asserted() -> None:
    """Non-contiguous sequence_numbers (RLS gap) must not be asserted and return True."""
    links = _make_chain_links(n=4, start_seq=1)
    # Simulate a tenant-B row removed by RLS: keep seq 1, 2, 4 (skip 3).
    # seq 2 and seq 4 are not consecutive → linkage gap not asserted.
    record = {
        "chain": {
            "links": [
                {
                    "sequence_number": links[0].sequence_number,
                    "prev_hash": links[0].prev_hash,
                    "row_hash": links[0].row_hash,
                },
                {
                    "sequence_number": links[1].sequence_number,
                    "prev_hash": links[1].prev_hash,
                    "row_hash": links[1].row_hash,
                },
                # seq 3 missing (removed by RLS)
                {
                    "sequence_number": links[3].sequence_number,  # seq 4
                    "prev_hash": links[3].prev_hash,
                    "row_hash": links[3].row_hash,
                },
            ]
        }
    }
    assert verify_chain_links_offline(record) is True


# ---------------------------------------------------------------------------
# generate_and_export — convenience wrapper (DB-backed)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_generate_and_export_produces_valid_signed_zip(
    monkeypatch, keypair, tmp_path: Path
) -> None:
    """generate_and_export wires the full pipeline and produces a signed ZIP.

    Uses a small window over the SOC2 framework with no seeded rows (empty
    evidence window is valid — controls will all be gaps/not_covered).
    Verifies the ZIP contains all required files and the JWS is valid.
    """
    import os as _os

    raw_db_url = _os.environ.get("DATABASE_URL", "")
    if not raw_db_url:
        pytest.skip("DATABASE_URL not set — skipping DB-backed generate_and_export test")

    from compliance.pack import generate_and_export

    priv, pub, priv_path, pub_path = keypair
    monkeypatch.setenv("COMPLIANCE_PACK_SIGNING_KEY_PATH", str(priv_path))
    monkeypatch.setenv("COMPLIANCE_PACK_PUBKEY_PATH", str(pub_path))

    tenant_id = f"tenant-gae-{uuid.uuid4().hex[:8]}"
    zip_path = tmp_path / "gae_pack.zip"

    # Far-future window: no rows → empty evidence, still a valid pack.
    t0 = datetime(2099, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2099, 12, 31, 0, 0, 0, tzinfo=timezone.utc)

    out = await generate_and_export(
        "SOC2",
        t0,
        t1,
        tenant_id=tenant_id,
        out_path=zip_path,
        sentinel_version="2.0.0-test",
    )

    assert out.exists(), "generate_and_export did not create the ZIP file"

    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
        assert "evidence.json" in names
        assert "evidence.json.jws" in names
        assert "pubkey.pem" in names
        assert "manifest.json" in names

        jws_bytes = zf.read("evidence.json.jws")
        evidence_bytes = zf.read("evidence.json")

    # Verify the JWS is valid.
    jws = jws_bytes.decode("ascii")
    payload = verify_pack(jws, pub)
    assert payload["schema"] == "sentinel-compliance-pack/v1"
    assert payload["tenant_id"] == tenant_id
    assert payload["framework"] == "SOC2"

    # Verify evidence.json matches canonical bytes of the payload.
    assert evidence_bytes == canonical_claims(payload)


# ---------------------------------------------------------------------------
# DB seed helpers
#
# Pattern A (no-commit savepoint) — for single-tenant tests that monkeypatch
# get_tenant_session to share one session:
#   _seed_savepoint_rows : seeds rows inside a shared session SAVEPOINT
#   _patch_tenant_session_pack : monkeypatches compliance.evidence.get_tenant_session
#
# Pattern B (committed + TRUNCATE) — for cross-tenant RLS proofs (vector 8):
#   _seed_committed_rows : commits rows on a dedicated privileged connection
# ---------------------------------------------------------------------------


async def _seed_savepoint_rows(session: AsyncSession, tenant_id: str, count: int) -> None:
    """Seed *count* rows for *tenant_id* via savepoint (no commit, no table pollution).

    Rows are visible only within *session* until the enclosing transaction rolls back.
    Used by tests that monkeypatch get_tenant_session to return *session*, so that
    read_chain_segment / generate_evidence can see the rows without a real commit.

    Uses begin_nested() as an async context manager — SQLAlchemy issues SAVEPOINT
    on entry and RELEASE on clean exit.
    """
    async with session.begin_nested():
        repo = AuditLogRepository(session)
        for i in range(count):
            ts = _T0 + timedelta(minutes=5 + i)
            event_data = {
                "event_id": uuid.uuid4().hex,
                "event_type": "injection_detected",
                "event_timestamp": ts.isoformat(),
                "request_id": uuid.uuid4().hex,
                "tenant_id": tenant_id,
                "team_id": f"team-{uuid.uuid4().hex[:6]}",
                "project_id": f"proj-{uuid.uuid4().hex[:6]}",
                "agent_id": "compliance-test",
                "action_taken": "blocked",
            }
            await repo.append(event_data)


def _patch_tenant_session_pack(monkeypatch, session: AsyncSession, tenant_id: str) -> None:
    """Monkeypatch compliance.evidence.get_tenant_session → yield *session*.

    The patched context manager sets app.current_tenant_id on the session (same GUC
    the real get_tenant_session sets) then yields the shared session, so that
    read_chain_segment reads uncommitted rows seeded by _seed_savepoint_rows.
    RLS enforcement is not the point of single-tenant vector 5; the privileged
    shared session is sufficient to verify chain link integrity offline.
    """
    from contextlib import asynccontextmanager
    from typing import AsyncIterator

    from sqlalchemy import text as _text
    from sqlalchemy.ext.asyncio import AsyncSession as _AsyncSession

    import compliance.evidence as _ev

    @asynccontextmanager
    async def _shared_session_ctx(_tid: str) -> AsyncIterator[_AsyncSession]:
        await session.execute(
            _text("SELECT set_config('app.current_tenant_id', :tid, true)"),
            {"tid": _tid},
        )
        yield session

    monkeypatch.setattr(_ev, "get_tenant_session", _shared_session_ctx)


# ---------------------------------------------------------------------------
# DB seed helper (committed pattern — visible to separate RLS connection)
# ---------------------------------------------------------------------------


async def _seed_committed_rows(db_url: str, tenant_id: str, count: int) -> None:
    """Seed *count* committed rows for *tenant_id* inside the test window.

    Used ONLY by cross-tenant tests (vector 8) that MUST prove RLS invisibility
    across a real second connection.  Caller must request the truncate_audit_log_after
    fixture to restore the empty-table precondition for the genesis chain test.
    """
    engine = create_async_engine(
        db_url,
        pool_pre_ping=True,
        echo=False,
        connect_args={"server_settings": {"app.session_kind": "privileged"}},
    )
    try:
        factory = async_sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False,
        )
        async with factory() as s:
            async with s.begin():
                repo = AuditLogRepository(s)
                for i in range(count):
                    ts = _T0 + timedelta(minutes=5 + i)
                    event_data = {
                        "event_id": uuid.uuid4().hex,
                        "event_type": "injection_detected",
                        "event_timestamp": ts.isoformat(),
                        "request_id": uuid.uuid4().hex,
                        "tenant_id": tenant_id,
                        "team_id": f"team-{uuid.uuid4().hex[:6]}",
                        "project_id": f"proj-{uuid.uuid4().hex[:6]}",
                        "agent_id": "compliance-test",
                        "action_taken": "blocked",
                    }
                    await repo.append(event_data)
    finally:
        await engine.dispose()
