# ADR-0039 — Multi-Layer Tokenization Architecture (F-033)

- Status: Accepted (implemented)
- Date: 2026-07-10
- Builds on: F-014's `admin/sso/secret_box.py` (the AES-256-GCM fail-closed
  key-loading pattern the vault crypto mirrors), ADR-0005 (tenant RLS — the
  vault table follows it), ADR-0033 (F-027 vaulting — the token-vault key is a
  deploy-injected secret in the same spirit).
- Scope: `src/tokenization/` (new), `src/persistence/models/
  tenant_token_vault.py` + `repositories/tenant_token_vault_repository.py` +
  migration 0035. **No `contracts/` change, no HTTP surface.**

## Context

Roadmap F-033: "Reversible PII tokenization, format-preserving encryption,
separate token vault. Depends on F-005, F-027." The goal: replace a PII value
with a token that downstream systems accept (format-preserving), reversibly, with
the original held only as ciphertext in a separate vault.

## The two layers

- **LAYER 1 — surface token (format-preserving surrogate).** `tokenize()`
  generates a RANDOM token that preserves the value's FORMAT so a downstream
  16-digit card column / NNN-NN-NNNN SSN field still accepts it: a Luhn-valid
  16-digit number for `card`, an NNN-NN-NNNN shape for `ssn`, a same-length
  digit string for `digits`, an opaque `tok_…` for `generic`. The token carries
  no information about the original.
- **LAYER 2 — vault ciphertext.** The original is AES-256-GCM encrypted (key from
  `SENTINEL_TOKEN_VAULT_KEY`, fail-closed) and stored in the RLS-scoped
  `tenant_token_vault` (migration 0035) keyed by the token. `detokenize()` looks
  up the row via a TENANT session (RLS) and decrypts.

The layers are independent: token-without-vault reveals nothing; vault-ciphertext-
without-key reveals nothing; a token from tenant A cannot be reversed under
tenant B (RLS — proven by a cross-tenant test).

## The honest crypto decision — surrogate tokenization, NOT hand-rolled FF3-1

The roadmap says "format-preserving encryption". True NIST **FF3-1** FPE is a
specific cipher construction. Implementing FF3-1 by hand for a **security
product** would violate the "no hand-rolled crypto" rule (R3) and is a
well-known footgun (FF3-1 itself has had cryptanalytic issues; correct
implementation is subtle). No vetted FF3-1 implementation is available in the
current dependency set.

So F-033 ships **random format-preserving SURROGATE tokenization** instead:
- It achieves the SAME downstream goal FPE is usually wanted for — a token that
  passes the destination's format validation — using only vetted AES-256-GCM.
- Reversibility comes from the vault (the token→ciphertext mapping), not from a
  reversible cipher over the value. This is a standard, widely-deployed
  tokenization design.
- Because surrogates are RANDOM, tokenizing the same value twice yields
  different tokens (no equality leakage through the surface token) — the
  opposite of FPE/deterministic tokenization's referential-integrity property.

This tradeoff is named explicitly rather than papered over. A true FF3-1 FPE
mode (and a deterministic-tokenization option for referential integrity) are
deferred to `docs/followups/f-033-ff3-1-fpe.md`, contingent on a vetted library.

## Decision (modules)

- `formats.py` — `generate_surrogate(token_type, original)` + `luhn_valid`.
  Validates the value matches the requested format; `secrets.SystemRandom` for
  randomness.
- `crypto.py` — AES-256-GCM `encrypt`/`decrypt` over `SENTINEL_TOKEN_VAULT_KEY`
  (base64 32 bytes), fail-closed (unset/short key → refuse; wrong key/tamper →
  raise), `nonce ‖ ct` layout, fresh nonce per encrypt. Mirrors secret_box.
- `service.py` — `tokenize()` / `detokenize()` wiring layer 1 + layer 2 through
  a tenant session, with a unique-token retry on the rare collision.
- `tenant_token_vault` (migration 0035, `TenantTokenVault`) — RLS-scoped,
  `GRANT SELECT, INSERT` only (a token→ciphertext mapping is immutable; no
  UPDATE/DELETE), `UNIQUE(tenant_id, token)`.
- `cli.py` — `sentinel-token tokenize/detokenize`.

## Honest limitations

- **Not FF3-1 FPE** — random surrogate tokenization (see above). No
  format-preserving ENCRYPTION of the value itself; the reversible mapping lives
  in the vault.
- **Random (non-deterministic) by default** — no referential integrity across
  separate tokenizations of the same value. A deterministic mode is a documented
  future option (with its equality-leakage caveat).
- **Vault key management** is a deploy concern (`SENTINEL_TOKEN_VAULT_KEY`
  injected from Vault/KMS, CLAUDE.md #4); losing it means the vault is
  unrecoverable, by design. Key rotation over an existing vault (re-encrypt) is
  not implemented here.
- **CLI/library only** — no HTTP tokenize/detokenize endpoint (that would need a
  `contracts/` route). The gateway could call `tokenize()` inline in a future
  masking mode; that wiring is out of scope for F-033.
