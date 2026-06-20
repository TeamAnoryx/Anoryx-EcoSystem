"""Compliance Evidence Pack — two-layer tamper-evident export (F-011, ADR-0013 §6-§7).

Layer A: embedded F-003 chain hashes (offline-verifiable source-event integrity).
Layer B: ES256 compact-JWS signature over the full canonical pack record
         (full-record binding via policy/crypto.py — ADR-0013 §6 D5).

Export is a DETERMINISTIC, byte-reproducible ZIP (D6): fixed date_time on every
ZipInfo, stable file order, canonical JSON bytes — same inputs → byte-identical
archive (vector 3).

R1: this module issues ZERO writes to events_audit_log.  Pack export is a
    pure read + sign + write-to-caller-supplied path.
R6: pack records contain ONLY metadata + opaque hashes.  No event payloads,
    no PII, no prompt content, no secrets/API keys ever appear in a pack.

Mandatory framing: "audit-ready" throughout; never "compliant".
Every artifact: "Certification requires an accredited auditor."
"""

from __future__ import annotations

import hashlib
import io
import os
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
)

from compliance.constants import DISCLAIMER
from compliance.errors import PackSigningKeyError
from compliance.evidence import ChainLink, EvidenceProjection, read_chain_segment
from compliance.gap_analysis import GapReport, analyze_gaps
from compliance.mapping import load_framework
from persistence.hash_chain import GENESIS_HASH
from policy.crypto import (
    canonical_claims,
    load_private_key_pem,
    load_public_key_pem,
    public_key_to_pem,
    sign_claims,
    verify_compact_jws,
)

__all__ = [
    "load_pack_signing_keys",
    "build_pack_record",
    "sign_pack",
    "verify_pack",
    "verify_chain_links_offline",
    "export_pack_zip",
    "generate_and_export",
]

# ---------------------------------------------------------------------------
# Environment variable names for pack signing keys (distinct from POLICY_SIGNING_*)
# ---------------------------------------------------------------------------

_PACK_PRIVKEY_ENV = "COMPLIANCE_PACK_SIGNING_KEY_PATH"
_PACK_PUBKEY_ENV = "COMPLIANCE_PACK_PUBKEY_PATH"

# Stable ZIP file order (deterministic archive — vector 3).
_ZIP_FILES_ORDER = ("evidence.json", "evidence.json.jws", "pubkey.pem", "manifest.json")
# Fixed ZIP epoch date_time — never "now" (determinism, D6).
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


# ---------------------------------------------------------------------------
# Key loader (fail-closed)
# ---------------------------------------------------------------------------


def load_pack_signing_keys() -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """Load compliance pack signing keys from env-configured PEM files.

    Fails closed: if either env var is set but the file is unreadable or
    not a P-256 key, raises PackSigningKeyError.  Callers should invoke this
    at startup so a misconfigured key is caught before serving requests.

    Returns
    -------
    (private_key, public_key)

    Raises
    ------
    PackSigningKeyError
        If either env var is set but the file is unreadable or not P-256.
    """
    priv_path = os.environ.get(_PACK_PRIVKEY_ENV, "").strip()
    pub_path = os.environ.get(_PACK_PUBKEY_ENV, "").strip()

    if not priv_path:
        raise PackSigningKeyError(
            f"{_PACK_PRIVKEY_ENV} is not set — compliance pack signing key required"
        )
    if not pub_path:
        raise PackSigningKeyError(
            f"{_PACK_PUBKEY_ENV} is not set — compliance pack public key required"
        )

    try:
        with open(priv_path, "rb") as fh:
            priv_data = fh.read()
        private_key = load_private_key_pem(priv_data)
    except PackSigningKeyError:
        # TODO(code-review MED-6): intentional defensive pass-through — keeps a
        # PackSigningKeyError from a future load_*_pem refactor fail-closed rather
        # than re-wrapping it. Currently uncovered (load_*_pem raises only the
        # generic branch); left as belt-and-suspenders.
        raise
    except OSError as exc:
        raise PackSigningKeyError(
            f"{_PACK_PRIVKEY_ENV} is set but the private key file is unreadable: {exc}"
        ) from exc
    except Exception as exc:
        raise PackSigningKeyError(
            f"{_PACK_PRIVKEY_ENV} is set but the private key could not be parsed: {exc}"
        ) from exc

    try:
        with open(pub_path, "rb") as fh:
            pub_data = fh.read()
        public_key = load_public_key_pem(pub_data)
    except PackSigningKeyError:
        # TODO(code-review MED-6): intentional defensive pass-through — keeps a
        # PackSigningKeyError from a future load_*_pem refactor fail-closed rather
        # than re-wrapping it. Currently uncovered (load_*_pem raises only the
        # generic branch); left as belt-and-suspenders.
        raise
    except OSError as exc:
        raise PackSigningKeyError(
            f"{_PACK_PUBKEY_ENV} is set but the public key file is unreadable: {exc}"
        ) from exc
    except Exception as exc:
        raise PackSigningKeyError(
            f"{_PACK_PUBKEY_ENV} is set but the public key could not be parsed: {exc}"
        ) from exc

    return private_key, public_key


# ---------------------------------------------------------------------------
# Pack record construction (metadata + hashes only — R6)
# ---------------------------------------------------------------------------


def _build_controls_list(gap_report: GapReport) -> list[dict[str, Any]]:
    """Extract per-control metadata from GapReport.results (no raw event payloads)."""
    return [
        {
            "control_id": r.control_id,
            "title": r.title,
            "status": r.status,
            "evidence_count": r.evidence_count,
            "evidence_event_types": list(r.evidence_event_types),
        }
        for r in gap_report.results
    ]


def _build_chain_block(
    projection: EvidenceProjection,
    chain_links: tuple[ChainLink, ...],
) -> dict[str, Any]:
    """Build the Layer-A chain block (opaque hashes only, no payload)."""
    tip = projection.chain_tip
    return {
        "genesis_hash": GENESIS_HASH,
        "tip": (
            {"sequence_number": tip.sequence_number, "row_hash": tip.row_hash}
            if tip is not None
            else None
        ),
        "links": [
            {
                "sequence_number": link.sequence_number,
                "prev_hash": link.prev_hash,
                "row_hash": link.row_hash,
            }
            for link in chain_links
        ],
        "link_count": len(chain_links),
    }


def build_pack_record(
    gap_report: GapReport,
    projection: EvidenceProjection,
    chain_links: tuple[ChainLink, ...],
    *,
    tenant_id: str,
    sentinel_version: str,
) -> dict[str, Any]:
    """Build a canonical, metadata-only compliance pack record.

    Contains NO event payloads, NO PII, NO prompt content, NO secrets (R6).
    The record is the payload that will be signed by sign_pack (Layer B).

    generated_at is derived from the window (projection.t1), NOT wall-clock time,
    so the record is reproducible from the same inputs (D6 / vector 3).

    Parameters
    ----------
    gap_report:
        Immutable GapReport from analyze_gaps.
    projection:
        Immutable EvidenceProjection from generate_evidence.
    chain_links:
        Tenant-scoped chain segment from read_chain_segment (Layer A).
    tenant_id:
        Server-resolved tenant identifier.
    sentinel_version:
        Caller-supplied Sentinel release version string.

    Returns
    -------
    dict
        Canonical pack record ready for sign_pack and export_pack_zip.
    """
    return {
        "schema": "sentinel-compliance-pack/v1",
        "tenant_id": tenant_id,
        "framework": gap_report.framework,
        "framework_version": gap_report.framework_version,
        "window": {
            "t0": projection.t0.isoformat(),
            "t1": projection.t1.isoformat(),
        },
        "generated_at": projection.t1.isoformat(),
        "sentinel_version": sentinel_version,
        "readiness": gap_report.readiness,
        "controls": _build_controls_list(gap_report),
        "summary": {
            "passed": gap_report.passed,
            "gap": gap_report.gap,
            "not_applicable": gap_report.not_applicable,
            "not_covered": gap_report.not_covered,
            "applicable": gap_report.applicable,
            "total": gap_report.total,
        },
        "chain": _build_chain_block(projection, chain_links),
        "disclaimer": DISCLAIMER,
    }


# ---------------------------------------------------------------------------
# Layer B — ES256 sign / verify (full-record binding)
# ---------------------------------------------------------------------------


def sign_pack(record: dict[str, Any], private_key: EllipticCurvePrivateKey) -> str:
    """Sign the full pack record as an ES256 compact-JWS (Layer B).

    The JWS payload is canonical_claims(record) — the full record is bound,
    so altering any embedded chain hash invalidates the signature (vector 6).

    Returns the compact-JWS string (header.payload.signature).
    """
    return sign_claims(record, private_key)


def verify_pack(token: str, public_key: EllipticCurvePublicKey) -> dict[str, Any]:
    """Verify a compliance pack JWS and return the payload claims dict.

    Raises CompactJWSError or cryptography.exceptions.InvalidSignature on
    any tamper or malformation (vector 2).
    """
    return verify_compact_jws(token, public_key)


# ---------------------------------------------------------------------------
# Layer A — offline chain-link consistency check (no DB)
# ---------------------------------------------------------------------------


def verify_chain_links_offline(record: dict[str, Any]) -> bool:
    """Verify the internal consistency of the embedded chain links (Layer A).

    Checks that:
    - Every row_hash and prev_hash is a 64-character hex string.
    - For any two CONSECUTIVE links (sorted by sequence_number), the later
      link's prev_hash equals the earlier link's row_hash.

    Where sequence_numbers are NON-CONTIGUOUS (because RLS removed other
    tenants' rows from the segment), linkage ACROSS the gap is NOT asserted.
    Global cross-tenant chain replay requires privileged access and is
    outside the scope of a detached offline check.  This is an honest
    documented limitation, not a silent omission.

    Parameters
    ----------
    record:
        A pack record dict as returned by build_pack_record (or parsed from
        evidence.json inside the ZIP).

    Returns
    -------
    bool
        True  — all checkable consecutive links are internally consistent
                and every hash is well-formed.
        False — any hash is malformed, or any consecutive-link pair has a
                broken prev_hash → row_hash linkage.
    """
    links_raw = record.get("chain", {}).get("links", [])
    if not links_raw:
        return True  # empty segment: trivially consistent

    # Sort by sequence_number so the caller need not guarantee order.
    links = sorted(links_raw, key=lambda lk: lk["sequence_number"])

    hex_re_len = 64
    for link in links:
        rh = link.get("row_hash", "")
        ph = link.get("prev_hash", "")
        if not (_is_hex64(rh, hex_re_len) and _is_hex64(ph, hex_re_len)):
            return False

    # Check consecutive pairs only (contiguous sequence_numbers).
    for prev_link, curr_link in zip(links, links[1:], strict=False):
        if curr_link["sequence_number"] == prev_link["sequence_number"] + 1:
            if curr_link["prev_hash"] != prev_link["row_hash"]:
                return False

    return True


def _is_hex64(value: str, expected_len: int) -> bool:
    """Return True iff value is a lowercase hex string of exactly expected_len chars."""
    if len(value) != expected_len:
        return False
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Deterministic ZIP export (D6, vector 3)
# ---------------------------------------------------------------------------


def _make_zip_info(filename: str) -> zipfile.ZipInfo:
    """Return a ZipInfo with a fixed epoch date_time for determinism."""
    info = zipfile.ZipInfo(filename=filename, date_time=_ZIP_EPOCH)
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def export_pack_zip(
    record: dict[str, Any],
    jws: str,
    public_key: EllipticCurvePublicKey,
    *,
    out_path: str | Path,
) -> Path:
    """Export a deterministic, byte-reproducible signed compliance pack ZIP.

    Files inside the ZIP (stable order, fixed date_time — D6):
      evidence.json      — canonical_claims(record) bytes (the signed payload)
      evidence.json.jws  — the ES256 compact-JWS string (Layer B)
      pubkey.pem         — the public key PEM (for offline auditor verification)
      manifest.json      — file list + content_hash + schema + disclaimer

    Determinism guarantees (vector 3):
      - ZipInfo.date_time is fixed to (1980,1,1,0,0,0) for all entries.
      - Files are written in _ZIP_FILES_ORDER (stable, sorted).
      - evidence.json uses canonical_claims(record) bytes (deterministic JSON).
      - manifest.json uses canonical_claims(manifest_dict) bytes.
      - zf.writestr() is used throughout — never zf.write() which embeds mtime.

    Parameters
    ----------
    record:
        Pack record dict as returned by build_pack_record.
    jws:
        Compact-JWS string as returned by sign_pack.
    public_key:
        Public key to bundle for offline verification.
    out_path:
        Destination path for the ZIP file (created or overwritten).

    Returns
    -------
    Path
        Absolute path to the written ZIP file.
    """
    evidence_bytes = canonical_claims(record)
    content_hash = hashlib.sha256(evidence_bytes).hexdigest()
    pubkey_bytes = public_key_to_pem(public_key)
    jws_bytes = jws.encode("ascii")

    manifest: dict[str, Any] = {
        "content_hash": content_hash,
        "disclaimer": DISCLAIMER,
        "files": list(_ZIP_FILES_ORDER),
        "schema": record.get("schema", "sentinel-compliance-pack/v1"),
    }
    manifest_bytes = canonical_claims(manifest)

    file_contents: dict[str, bytes] = {
        "evidence.json": evidence_bytes,
        "evidence.json.jws": jws_bytes,
        "manifest.json": manifest_bytes,
        "pubkey.pem": pubkey_bytes,
    }

    out = Path(out_path)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for filename in _ZIP_FILES_ORDER:
            zf.writestr(_make_zip_info(filename), file_contents[filename])

    out.write_bytes(buf.getvalue())
    return out.resolve()


# ---------------------------------------------------------------------------
# Top-level convenience
# ---------------------------------------------------------------------------


async def generate_and_export(
    framework_name: str,
    t0: datetime,
    t1: datetime,
    *,
    tenant_id: str,
    out_path: str | Path,
    sentinel_version: str,
) -> Path:
    """Wire load_framework → generate_evidence → read_chain_segment → analyze_gaps
    → build_pack_record → sign_pack → export_pack_zip.

    This is the read path only (R1: zero writes to events_audit_log).
    Emitting compliance_pack_exported audit events is STEP 6 (not here).

    Signing keys are loaded from COMPLIANCE_PACK_SIGNING_KEY_PATH /
    COMPLIANCE_PACK_PUBKEY_PATH at call time (fail-closed via load_pack_signing_keys).

    Parameters
    ----------
    framework_name:
        Framework identifier, e.g. "SOC2" or "ISO27001".
    t0:
        Window start (inclusive).
    t1:
        Window end (exclusive).
    tenant_id:
        Server-resolved tenant identifier.
    out_path:
        Destination path for the signed ZIP.
    sentinel_version:
        Sentinel release version string to embed in the pack.

    Returns
    -------
    Path
        Absolute path to the written ZIP.

    Raises
    ------
    PackSigningKeyError
        If signing keys are misconfigured (fail-closed).
    EvidenceWindowError
        If t0 >= t1.
    """
    from compliance.evidence import generate_evidence

    private_key, public_key = load_pack_signing_keys()
    framework_map = load_framework(framework_name)
    projection = await generate_evidence(framework_map, t0, t1, tenant_id=tenant_id)
    chain_links = await read_chain_segment(t0, t1, tenant_id=tenant_id)
    gap_report = analyze_gaps(framework_map, projection)
    record = build_pack_record(
        gap_report,
        projection,
        chain_links,
        tenant_id=tenant_id,
        sentinel_version=sentinel_version,
    )
    jws = sign_pack(record, private_key)
    return export_pack_zip(record, jws, public_key, out_path=out_path)
