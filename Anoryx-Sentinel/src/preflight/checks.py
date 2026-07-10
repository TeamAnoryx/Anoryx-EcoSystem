"""The individual production due-diligence checks (F-031, ADR-0037).

Each check reuses an existing subsystem rather than reimplementing it:
  - secrets-vaulted   -> F-027 KeyVaultSettings / GatewaySettings
  - audit-chain       -> F-003 admin.audit_read.verify_chain()
  - migrations-head   -> Alembic ScriptDirectory head vs DB alembic_version
  - open-findings     -> the repo's OPEN/Severity markdown convention
  - config-sane       -> GatewaySettings load + bounds

Each returns a CheckResult; none raise for an expected "not ready" state — a
gate that crashes is a worse gate than one that reports FAIL.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from preflight.result import (
    STATUS_FAIL,
    STATUS_PASS,
    STATUS_SKIP,
    STATUS_WARN,
    CheckResult,
)

# Anoryx-Sentinel/ root (src/preflight/checks.py -> parents[2]).
_SENTINEL_ROOT = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# 1. Secrets vaulted (F-027)
# ---------------------------------------------------------------------------


def check_secrets_vaulted() -> CheckResult:
    """FAIL if provider secrets are still raw env vars (keyvault_backend=env)."""
    name = "secrets-vaulted"
    try:
        from gateway.keyvault.settings import get_keyvault_settings

        backend = get_keyvault_settings().keyvault_backend
    except Exception as exc:  # settings load / validation error
        return CheckResult(
            name=name,
            status=STATUS_FAIL,
            detail=f"could not read key-vault settings: {type(exc).__name__}",
            remediation="Fix KeyVaultSettings (VAULT_ADDR/VAULT_TOKEN for vault backend).",
        )

    if backend == "env":
        return CheckResult(
            name=name,
            status=STATUS_FAIL,
            detail="keyvault_backend=env — upstream provider secrets are raw environment "
            "variables, not vault/KMS-backed.",
            remediation="Set KEYVAULT_BACKEND=vault (with VAULT_ADDR/VAULT_TOKEN) or "
            "KEYVAULT_BACKEND=kms before production launch (F-027, ADR-0033).",
            evidence={"keyvault_backend": backend},
        )
    return CheckResult(
        name=name,
        status=STATUS_PASS,
        detail=f"provider secrets are {backend}-backed (not raw env).",
        evidence={"keyvault_backend": backend},
    )


# ---------------------------------------------------------------------------
# 2. Core config loads + SLO/sanity bounds
# ---------------------------------------------------------------------------


def check_config_sane() -> CheckResult:
    """FAIL if GatewaySettings will not load; WARN on out-of-range SLO knobs."""
    name = "config-sane"
    try:
        from gateway.config import GatewaySettings

        settings = GatewaySettings()
    except Exception as exc:
        return CheckResult(
            name=name,
            status=STATUS_FAIL,
            detail=f"GatewaySettings failed to load: {type(exc).__name__} — a required "
            "setting is missing or invalid.",
            remediation="Set all required env vars (UPSTREAM_BASE_URL, DATABASE_URL, "
            "APP_DATABASE_URL, SENTINEL_KEY_SECRET) with valid values.",
        )

    concerns: list[str] = []
    # SLO-adjacent sanity (ADR-0029 perf budget is enforced by perf tests, not
    # runtime; here we bound the knobs that most affect latency/availability).
    if settings.request_timeout_seconds <= 0 or settings.request_timeout_seconds > 300:
        concerns.append(
            f"request_timeout_seconds={settings.request_timeout_seconds} out of (0,300]"
        )
    if settings.rate_limit_rpm <= 0:
        concerns.append(f"rate_limit_rpm={settings.rate_limit_rpm} must be > 0")
    if settings.redis_url.startswith("redis://localhost"):
        concerns.append("redis_url points at localhost — likely a dev default, not production")

    if concerns:
        return CheckResult(
            name=name,
            status=STATUS_WARN,
            detail="config loads but has production concerns: " + "; ".join(concerns),
            remediation="Review the flagged settings against your production SLOs.",
        )
    return CheckResult(
        name=name,
        status=STATUS_PASS,
        detail="core runtime config loads and passes sanity bounds.",
    )


# ---------------------------------------------------------------------------
# 3. Open CRITICAL/HIGH security findings (repo markdown convention)
# ---------------------------------------------------------------------------

_STATUS_OPEN_RE = re.compile(r"status:\*{0,2}\s*open", re.IGNORECASE)
_SEVERITY_HIGH_CRIT_RE = re.compile(r"severity:\*{0,2}\s*(high|critical)", re.IGNORECASE)


def check_no_open_critical_high(root: Path | None = None) -> CheckResult:
    """FAIL if any tracked finding doc is OPEN with High/Critical severity.

    Uses the repo's existing markdown convention (`**Status:** OPEN` +
    `**Severity:** High/Critical`), the same used by docs/followups and
    docs/audit. HONEST LIMITATION: this sees only DOCUMENTED findings — it is
    not a live scanner and does not replace security-auditor / SAST. A clean
    result means 'no documented open High/Critical', not 'no vulnerabilities'.
    """
    name = "no-open-critical-high"
    base = root or _SENTINEL_ROOT
    search_dirs = [base / "docs" / "followups", base / "docs" / "audit"]

    scanned = 0
    open_findings: list[str] = []
    for d in search_dirs:
        if not d.is_dir():
            continue
        for md in sorted(d.glob("*.md")):
            scanned += 1
            try:
                text = md.read_text(encoding="utf-8")
            except OSError:
                continue
            if _STATUS_OPEN_RE.search(text) and _SEVERITY_HIGH_CRIT_RE.search(text):
                open_findings.append(md.relative_to(base).as_posix())

    if scanned == 0:
        return CheckResult(
            name=name,
            status=STATUS_WARN,
            detail="no findings docs found to scan (docs/followups, docs/audit absent).",
            remediation="Ensure the findings ledger is present in the deployed artifact, "
            "or wire a machine-readable findings source (SARIF).",
        )
    if open_findings:
        return CheckResult(
            name=name,
            status=STATUS_FAIL,
            detail=f"{len(open_findings)} OPEN High/Critical finding(s): "
            + ", ".join(open_findings),
            remediation="Remediate and mark each finding's Status as CLOSED/RESOLVED before "
            "launch, or accept the risk via a documented, signed exception.",
            evidence={"open_findings": open_findings, "docs_scanned": scanned},
        )
    return CheckResult(
        name=name,
        status=STATUS_PASS,
        detail=f"no documented OPEN High/Critical findings ({scanned} docs scanned). "
        "NOTE: documented findings only — not a substitute for a live security scan.",
        evidence={"docs_scanned": scanned},
    )


# ---------------------------------------------------------------------------
# 4. Alembic migrations applied to head (async — reads DB)
# ---------------------------------------------------------------------------


def _script_head() -> str:
    """Return the Alembic script-directory head revision (in-process)."""
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    cfg = Config(str(_SENTINEL_ROOT / "alembic.ini"))
    # env.py resolves the DB URL itself; ScriptDirectory only needs script_location.
    script = ScriptDirectory.from_config(cfg)
    head = script.get_current_head()
    if head is None:  # pragma: no cover — a repo always has migrations
        raise RuntimeError("no Alembic head revision found")
    return head


async def check_migrations_at_head() -> CheckResult:
    """FAIL if the DB's applied revision is not the script head. SKIP if no DB."""
    name = "migrations-at-head"
    if not os.environ.get("DATABASE_URL"):
        return CheckResult(
            name=name,
            status=STATUS_SKIP,
            detail="DATABASE_URL not set — cannot check applied migration revision.",
            remediation="Run with DATABASE_URL pointing at the production DB to verify.",
        )
    try:
        head = _script_head()
    except Exception as exc:
        return CheckResult(
            name=name,
            status=STATUS_FAIL,
            detail=f"could not resolve Alembic script head: {type(exc).__name__}",
            remediation="Verify alembic.ini and the migrations package are in the artifact.",
        )

    try:
        from sqlalchemy import text

        from persistence.database import get_privileged_session

        async with get_privileged_session() as s:
            result = await s.execute(text("SELECT version_num FROM alembic_version"))
            db_rev = result.scalar_one_or_none()
    except Exception as exc:
        return CheckResult(
            name=name,
            status=STATUS_FAIL,
            detail=f"could not read alembic_version from the DB: {type(exc).__name__}",
            remediation="Ensure the DB is reachable and migrations have been initialised.",
        )

    if db_rev != head:
        return CheckResult(
            name=name,
            status=STATUS_FAIL,
            detail=f"DB at revision {db_rev!r} but script head is {head!r} — migrations not "
            "fully applied.",
            remediation="Run `alembic upgrade head` against the production DB.",
            evidence={"db_revision": db_rev, "script_head": head},
        )
    return CheckResult(
        name=name,
        status=STATUS_PASS,
        detail=f"migrations applied to head ({head}).",
        evidence={"db_revision": db_rev, "script_head": head},
    )


# ---------------------------------------------------------------------------
# 5. Audit hash-chain integrity (async — reads DB, reuses F-003)
# ---------------------------------------------------------------------------


async def check_audit_chain_integrity() -> CheckResult:
    """FAIL if the F-003 audit hash-chain does not verify. SKIP if no DB."""
    name = "audit-chain-integrity"
    if not os.environ.get("DATABASE_URL"):
        return CheckResult(
            name=name,
            status=STATUS_SKIP,
            detail="DATABASE_URL not set — cannot verify the audit hash-chain.",
            remediation="Run with DATABASE_URL pointing at the production DB to verify.",
        )
    try:
        from admin.audit_read import verify_chain

        result = await verify_chain()
    except Exception as exc:
        return CheckResult(
            name=name,
            status=STATUS_FAIL,
            detail=f"chain verification could not run: {type(exc).__name__}",
            remediation="Ensure the DB is reachable with the privileged (BYPASSRLS) role.",
        )

    if not result.is_valid:
        return CheckResult(
            name=name,
            status=STATUS_FAIL,
            detail=f"audit hash-chain INVALID at sequence {result.first_mismatch_sequence}: "
            f"{result.error_detail}",
            remediation="Investigate audit-log tampering immediately — do NOT launch. "
            "Restore from a verified backup (F-024) and determine the cause.",
            evidence={"rows_checked": result.rows_checked},
        )
    return CheckResult(
        name=name,
        status=STATUS_PASS,
        detail=f"audit hash-chain verified intact ({result.rows_checked} rows).",
        evidence={"rows_checked": result.rows_checked},
    )
