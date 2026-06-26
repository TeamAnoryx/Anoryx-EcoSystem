# D-003 Double-Entry Ledger — Security Audit

- **Task:** D-003 (Delta double-entry ledger persistence)
- **Auditor:** independent arms-length red-team (security-auditor, Opus), live adversarial
  testing as the real `delta_app` role (NOSUPERUSER, NOBYPASSRLS) against a live
  Postgres 16. Semgrep `p/python p/security-audit p/secrets` at ERROR+WARNING: 0 findings.
- **Verdict:** **PASS-WITH-NOTES** — no High/Critical. 4 Low findings; L-1 and L-2 fixed
  in-place after the audit, L-3 and L-4 accepted/documented.

---

## Core guarantees — all defended (live, non-stubbed, real COMMITs)

| # | Attack (as `delta_app`) | Result |
|---|---|---|
| 1 | Single unbalanced one-leg INSERT, committed | REJECTED at COMMIT (`< 2 entries`) |
| 2 | Balanced +X/−X amendment of an already-committed txn (incl. via SAVEPOINT) | REJECTED at INSERT (xmin immutability trigger) |
| 3 | UPDATE / DELETE on a committed entry, transaction, and account | BLOCKED (no grant → `InsufficientPrivilegeError`; deny-trigger RAISEs even for the superuser owner; RLS `USING(false)`) |
| 4 | Cross-tenant READ / WRITE; GUC-unset read | 0 rows / WITH CHECK reject / 0 rows (fail-closed). `delta_app` is NOBYPASSRLS; migration provisions it **with** a SCRAM password (no migration-0006 repeat) |
| 5 | Float / negative / overflow money | BIGINT-only columns + D-001 `Money` validator + `CheckViolationError` |
| 6 | Idempotent replay / 20-way concurrent replay race | exactly 1 txn + 1 debit (`ON CONFLICT DO NOTHING` + partial UNIQUE) |
| 7 | Durability — ack'd write absent from Postgres | none: no Redis/cache write-buffer in `src`; Postgres is sole authority; `applied=True` only after commit |
| 8 | 40 concurrent writers | `debit_sum == credit_sum`, all balanced, no torn/lost state |
| 9 | Reversal | net 0 on the reversed account; cannot create an unbalanced state |

**Privilege lockdown verified (all BLOCKED for `delta_app`):** `SET session_replication_role
= replica` (the key trigger-disable vector), `ALTER TABLE … DISABLE TRIGGER/RLS`, `NO FORCE
RLS`, `DROP POLICY`, `TRUNCATE`, `COPY … FROM PROGRAM`, `CREATE` in schema `delta`,
`UPDATE alembic_version`, reading `pg_authid`, self-`ALTER ROLE … BYPASSRLS/SUPERUSER`. No
hardcoded secrets; no URL/credential logged; the entrypoint sends only the opaque SCRAM
verifier; identifier interpolation in DDL uses fixed module constants (no injection surface).

---

## Findings

### L-1 (Low) — xid comparison not epoch-safe + inaccurate claim — **FIXED**
`migrations/versions/0001_ledger_schema.py` (immutability trigger). The original
`txid_current()::text::xid` does **not** wrap mod 2³² — `'4294967300'::xid` raises
`NumericValueOutOfRangeError`. It worked today (epoch 0) and correctly blocked amendment,
but once the xid epoch ≥ 1 (~4.29B txns) every `ledger_entries` INSERT would raise → a
fail-**closed** append outage (no bad row ever admitted; not attacker-triggerable). **Fix:**
compare in 64-bit space — `v_xmin::text::bigint <> (txid_current() & 4294967295)`; ADR
wording corrected. Covered by the existing immutability test (vector 4b).

### L-2 (Low) — entry currency vs transaction currency not guarded — **FIXED**
`balances.py` / deferred trigger. The deferred trigger enforced one currency across
*entries* but did not check that the entries' currency equals the parent
`transactions.currency` column; balance reads sum `amount_minor_units` with no currency
dimension. Not a D-003 bypass (single-currency-per-txn held; ledger stayed balanced) but a
latent footgun for D-004/D-005. **Fix:** the deferred trigger now rejects when the entries'
currency ≠ the transaction's currency (`test_entry_currency_must_match_txn_currency`); the
single-currency-per-account read assumption is documented in `balances.py`.

### L-3 (Low) — `delta_app` can set its own tenant GUC — **ACCEPTED (documented)**
`database.py`. With a raw `delta_app` connection an attacker can `set_config(
'app.current_tenant_id', <victim>)` and read that tenant. This is the inherited, accepted
F-003b boundary: RLS protects against application bugs and pooled-connection leakage, not
against credential theft. The tenant_id must come from an authenticated source and is
treated as a tenant-spanning secret (load-bearing in D-004). Documented in ADR-0003.

### L-4 (Low) — no over-reversal guard — **ACCEPTED (deferred to posting layer)**
`ledger_store.py`. A transaction can be reversed more than once (or a reversal reversed)
unless the caller supplies an `idempotency_key`; the ledger stays balanced, but the net
economic effect is a posting-semantics concern. Reversal deduplication is deferred to D-004
/ D-005, documented in ADR-0003.

---

## Disposition

No High/Critical. The four core ledger guarantees (balanced, append-only/immutable,
tenant-isolated, idempotent) are non-bypassable by direct SQL as `delta_app`. L-1 and L-2
fixed and re-verified; L-3 and L-4 accepted as documented boundaries owned by the posting
layer. **PASS-WITH-NOTES.**
