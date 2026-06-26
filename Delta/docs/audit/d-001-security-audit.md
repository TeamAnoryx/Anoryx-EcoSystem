# Delta D-001 — Arms-Length Red-Team Security Audit

**Subject:** Delta Financial Domain Model (D-001) — Pydantic v2 types + JSON Schemas + integrity invariants
**Auditor posture:** Independent / adversarial. Author did not write this code. No benefit of the doubt.
**Date:** 2026-06-26
**Code under audit:** `Delta/` (src/delta/*.py, contracts/delta-financial.schema.json, docs/adr/0001)
**Tooling:** Python 3.12, `delta` installed `-e`; Semgrep 1.166.0; jsonschema Draft 2020-12 (`jsonschema[format]`).
**Honesty boundary verified:** D-001 ships the MODEL + invariants only. No ledger engine (D-003), no budget engine (D-005), **no DDL/.sql/Alembic/migrations**. Baseline suite: `python -m pytest -q` → **94 passed**.

> STATUS: this is the **initial** audit (VERDICT FAIL). A remediation section is appended after fixes + re-audit.

---

## Scope of attack
Eight integrity vectors attacked with running code (not inspection): float smuggling, double-entry non-bypassability, negative/overflow/precision, cross-tenant leakage, JSON-Schema permissiveness, reconciliation bypass, locked-budget round-trip integrity, honest scoping. The locked Sentinel contract `Anoryx-Sentinel/contracts/policy.schema.json` was checked for tampering.

---

## Per-vector findings (exact attack + observed result)

### Vector 1 — Float / bool / Decimal / NaN / Inf / numeric-string smuggling — **PASS (repelled)**
Fed `1.0, 1.5, True, Decimal(1), Decimal("1.5"), NaN, Inf, "100"` into every monetary/count field (`Money.minor_units`, `BudgetConcept.limit_tokens/limit_cost_cents`, `UsageRecord.tokens_in/tokens_out/cost_estimate_cents`, `BurnRate.total_cost_cents/total_tokens/sample_count`). **24/24 rejected.** `mode="before"` validators reject bool/float/Decimal/strings before coercion. The one sanctioned float entry `Money.from_wire_cents` quantizes half-even and never retains the float.

### Vector 2 — Double-entry invariant non-bypassable — **FAIL at the mutation surface** (construction PASS)
Construction attacks (unbalanced, single-entry, mixed-currency, cross-tenant) all rejected at construction; `txn.entries = []` blocked (frozen). **But:** `frozen=True` blocks attribute *reassignment*, not in-place mutation of the `list` field. `txn.entries.append(entry(T2, DEBIT, 999999))` mutates the validated object with no re-validation → unbalanced (debit 1000099 != credit 100) AND cross-tenant. See **H-1**.

### Vector 3 — Negative / overflow / precision — **PASS for Money; gaps in BurnRate + from_wire_cents edge**
- `Money(minor_units=-1)` / `> 1e11` rejected; wire maxima enforced; half-even correct (`100.5→100, 101.5→102`). **PASS.**
- `from_wire_cents(1e30)` → uncaught `decimal.InvalidOperation` (not `ValueError`). Fail-closed but wrong exception type. See **L-3**.
- `BurnRate(sample_count=-5, total_cost_cents=-100000, total_tokens=10**20)` constructs — `_integer_only` rejects float/bool but never bounds. See **L-2**.

### Vector 4 — Cross-tenant attribution leakage — **PASS at construction; MEDIUM identity divergence**
- `tenant_id` required on every tenant-scoped type; cross-tenant txn / mixed-tenant `burn_rate()` rejected. **PASS.** (Post-construction blend = H-1.)
- **Parser differential (M-1):** Pydantic `UuidStr` accepts non-canonical forms (`32-hex-no-dashes`, `{braces}`, `urn:uuid:…`) that the wire `format:uuid` rejects, for all id types. See **M-1**.

### Vector 5 — JSON-Schema permissiveness — **PASS**
0 object defs missing `additionalProperties:false`; 0 unbounded scalar string defs; extra-key injection rejected on every object; arrays capped (`maxItems:1024`); bad slug/type/missing-tenant/float/overflow all rejected. The JSON-Schema layer is airtight. (Pydantic collections are not equally bounded — L-1.)

### Vector 6 — Reconciliation bypass — **PASS at construction**
Cannot construct an `Allocation` with desynced targets or mixed currency (`reconcile_allocation` in the validator). `reconcile_*` flag desynced/cross-tenant/mixed sets. **PASS.** (Post-construction `alloc.targets.append(...)` desyncs — H-1's second instance.)

### Vector 7 — Budget round-trip vs LOCKED policy.schema.json — **PASS (core claim holds); LOW builder gaps**
- Locked schema **byte-untouched**: `git status`/`git diff` clean; last commit `1a823bf` (F-019), not Delta. Whole `Delta/` tree untracked.
- Valid `BudgetConcept` → builder → validates against LOCKED `BudgetLimitPolicy`; cost emitted as int; all scopes validate; 12 round-trip tests pass. **Core compatibility holds; schema does not move.**
- Builder checks only `policy_version >= 1`; `policy_version=10**18` / `signature="short"` pass the builder but are rejected downstream by the locked schema (fail-closed). See **L-4**.

### Vector 8 — Honest scoping — **PASS with one over-claim**
All honesty hits benign ("never an authoritative bill", "risk reduction", "client-side cost estimate"). **Except** `ledger.py` + ADR assert the mutation invariant H-1 falsifies. Folded into **H-1**.

### Static analysis — **PASS**
`semgrep --config=p/python,p/security-audit,p/secrets --severity=ERROR src/delta` → **0 findings** (101 rules / 24 files). Secrets ruleset → 0. No SSRF/path-traversal/SQLi/command-injection/deserialization surface (pure value types; no I/O, eval, subprocess, network, pickle).

---

## Severity table (only what was actually broken)

| ID | Sev | File | Issue | Fix |
|----|-----|------|-------|-----|
| **H-1** | **High** | `ledger.py` (+ `allocation.py`); claim at `ledger.py` docstring + `adr/0001` | `frozen=True` does not deep-freeze collection fields. `Transaction.entries`/`Allocation.targets` are plain `list`; `.append()` mutates a validated object with no re-validation → unbalanced AND cross-tenant transaction; falsifies the central documented "non-bypassable / no mutation path" guarantee D-003 is told it relies on. | Type collections as `tuple[..., ...]` (immutable under frozen, no `.append`), or re-validate at the persistence boundary; then make the wording true. |
| **M-1** | Medium | `identifiers.py` | `UuidStr` validates via `uuid.UUID()`, accepting non-canonical forms the wire `format:uuid` rejects, for every tenant-scoped id → parser differential vs the "byte-shape identical join" claim. Fails closed (Sentinel body IDs non-authoritative) but can mis-attribute. | Constrain to canonical dashed UUID (strict pattern / `UUID4` / normalize-then-compare). |
| **L-1** | Low | `ledger.py`, `allocation.py` | Pydantic collections set `min_length` but no `max_length` (schema caps 1024) → 4000-entry object type-valid but wire-invalid; DoS-via-construction. | Add `max_length=1024` to the `Field` (folded into the tuple fix). |
| **L-2** | Low | `burn_rate.py` | `_integer_only` uses `reject_non_integer` only (no `bounded_count`) → direct `BurnRate` accepts negative money/count, over-max tokens. | Use `bounded_count` for totals; non-negative bound for `sample_count`. |
| **L-3** | Low | `money.py` | `from_wire_cents(1e30)` raises uncaught `decimal.InvalidOperation` (not `ValueError`) — undocumented exception on the float-ingest path. | Catch `decimal.InvalidOperation` (or early magnitude check) → raise clean `ValueError`. |
| **L-4** | Low | `attribution.py` | Builder validates only `policy_version >= 1`; not the locked upper bound (2^53-1) or compact-JWS signature → can emit a record it knows the locked schema rejects. | Mirror the locked bounds: `1 <= policy_version <= 9007199254740991`; validate signature pattern. |

---

## VERDICT: FAIL
- **Critical: 0 · High: 1 (H-1) · Medium: 1 (M-1) · Low: 4 (L-1…L-4)**
- Per project rule, the single High (H-1) escalates to the human immediately. No High/Critical in static/secret/SSRF/injection/deserialization/contract-tamper classes: Semgrep ERROR = 0, no secrets, no DDL, LOCKED `policy.schema.json` byte-untouched.
- Fix (tuple-typed immutable collections + honest wording, plus the M/L items) is small and standard and should land before this foundation is inherited by D-003.

---

## Remediation re-audit — VERDICT: PASS

**Date:** 2026-06-26. Independent re-audit: every fix re-attacked against live code; every prior PASS re-confirmed. Coordinator claims not trusted.

| ID | Sev | Status | Re-run result |
|----|-----|--------|---------------|
| H-1 | High | **RESOLVED** | `entries`/`targets` are now `tuple`; `.append()` → `AttributeError: 'tuple' object has no attribute 'append'`. No mutation path to an unbalanced/cross-tenant txn or desynced allocation. Construction-time invariants still reject (no regression). The "no mutation path" claim is now substantiated. |
| M-1 | Medium | **RESOLVED** | Strict dashed-UUID regex: `no-dashes`/`{braces}`/`urn:uuid:` → Pydantic=False matching wire=False; canonical → True/True. Parser differential closed. |
| L-1 | Low | **RESOLVED** | 4000-entry `Transaction` rejected; 1024 boundary accepted (`max_length=1024` matches schema `maxItems`). |
| L-2 | Low | **RESOLVED** | `BurnRate(total_cost_cents=-100000)`, `total_tokens=10**20`, `sample_count=-5`, `=1.0` all rejected (`bounded_count`); `burn_rate([])` factory unaffected. |
| L-3 | Low | **RESOLVED** | `Money.from_wire_cents(1e30)` → clean `ValueError`; half-even still exact (100.5→100, 101.5→102). |
| L-4 | Low | **RESOLVED** | Builder rejects `policy_version` outside [1, 2**53-1] and non-compact-JWS/<16-char signature; boundary `2**53-1` accepted; valid record still validates vs LOCKED schema. |

**Regressions re-confirmed (still PASS):** float/bool/Decimal/NaN/Inf/string smuggling repelled; construction-time double-entry + reconciliation invariants reject; every JSON-Schema object closed + `additionalProperties:false` bites; budget round-trip validates vs **byte-untouched** LOCKED `policy.schema.json` (`$id=sentinel:policy:v1`, lock marker present, `git` shows it last touched by F-019 not Delta); no DDL/.sql/Alembic; Semgrep `p/python`+`p/security-audit`+`p/secrets` `--severity=ERROR` → **0**. Full suite **111 passed / 0 errors**; the previously fixture-masked round-trip tests now run (33-test subset green).

**VERDICT: PASS — 0 Critical, 0 High.** The single escalation trigger (H-1) is closed; all six findings independently confirmed resolved with no regression.
