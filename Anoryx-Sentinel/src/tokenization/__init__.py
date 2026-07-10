"""Multi-layer reversible PII tokenization (F-033, ADR-0039).

Two layers:
  LAYER 1 (surface) — a FORMAT-PRESERVING surrogate TOKEN replaces the PII value
    so downstream systems that validate format (a 16-digit card column, an
    NNN-NN-NNNN SSN field) still accept it. The token carries no information
    about the original value.
  LAYER 2 (vault)   — the original value is AES-256-GCM encrypted and stored in
    a SEPARATE, RLS-scoped token vault (tenant_token_vault) keyed by the token.
    Only a holder of the vault key + the right tenant session can detokenize.

`tokenize()` writes the vault row and returns the surface token; `detokenize()`
reverses it. The two layers are independent: someone with the token but not the
vault (or not the tenant session) learns nothing; someone with the vault
ciphertext but not the key learns nothing.

HONEST SCOPE (ADR-0039): the surface token is a RANDOM format-preserving
SURROGATE, not NIST FF3-1 format-preserving ENCRYPTION. This is deliberate — a
security product must not hand-roll FF3-1 (R3). Surrogate tokenization achieves
the same downstream goal (format compatibility + reversibility via the vault)
with vetted AES-GCM only. True FF3-1 FPE is deferred, see docs/followups/.
"""
