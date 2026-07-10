# Follow-up — F-033: true FF3-1 FPE + deterministic tokenization

**Status:** deferred (documented, not built)
**Owner track:** data-protection
**Blocked on:** a vetted format-preserving-encryption library in the dependency set,
and (for the HTTP surface) an api-architect `contracts/` route.

## What F-033 shipped

F-033 (ADR-0039) shipped **random format-preserving surrogate tokenization** with a
separate RLS-scoped vault:

- LAYER 1 — a random surrogate token that preserves the value's FORMAT (Luhn-valid
  16-digit for `card`, `NNN-NN-NNNN` for `ssn`, same-length for `digits`, opaque
  `tok_…` for `generic`).
- LAYER 2 — the original AES-256-GCM encrypted into `tenant_token_vault`, reversible
  only by looking up the token under the owning tenant's RLS session.

That design meets the practical goal FPE is usually reached for — a token the
downstream system's format validators accept — using only vetted AES-256-GCM, and
avoids hand-rolling a cipher in a security product (rule R3).

## What is deferred here, and why

### 1. True NIST FF3-1 format-preserving ENCRYPTION

The roadmap wording ("format-preserving encryption") literally implies FF3-1 (or
FF1). We deliberately did NOT hand-roll it:

- FF3-1 is a specific, subtle Feistel construction over a radix alphabet. A wrong
  implementation is a silent confidentiality failure.
- FF3 (the predecessor) had a published cryptanalytic break; FF3-1 was the NIST
  revision. This is exactly the class of primitive rule R3 says not to hand-roll.
- No vetted FF3-1 implementation is currently in the dependency set.

**To pick this up:** add a reviewed FPE library (e.g. an audited `pyffx`-class or
`ff3` package, subject to a security review of the dependency itself), expose it as
an alternative LAYER-1 mode behind an explicit `mode="ff3-1"` flag, and keep the
random-surrogate mode as the default. FF3-1 would let the token itself be
reversible without a vault row — but note the vault still gives tenant-scoped
revocation and an audit anchor, so the vault stays even under FPE.

### 2. Deterministic tokenization (referential integrity)

The shipped surrogates are RANDOM: tokenizing the same value twice yields two
different tokens. That deliberately avoids equality leakage through the surface
token, but it also means you cannot JOIN or de-duplicate on the token — there is no
referential integrity across separate tokenizations.

Some use cases (analytics on tokenized columns, joining two tokenized datasets)
need the opposite: the same input → the same token, every time.

**To pick this up:** add a `deterministic=True` mode that derives the surrogate from
a keyed PRF over the normalized value (HMAC-SHA256 with a per-tenant derived key,
truncated/encoded into the target format), so equal inputs map to equal tokens.

- Store the mapping in the same vault (INSERT-or-get-existing instead of
  always-INSERT).
- **Name the tradeoff loudly in the ADR and UI:** deterministic tokens LEAK equality
  and frequency (an attacker who sees the tokens learns which rows share a value and
  the value-frequency distribution). This is the same honest caveat the F-032 ZK SDK
  blind index carries.

### 3. HTTP tokenize/detokenize endpoint

F-033 is CLI/library only (`sentinel-token`, `tokenization.service`). A network
tokenize/detokenize surface (so the gateway could tokenize inline in a masking mode)
needs an api-architect-authored `contracts/openapi.yaml` route + `policy.schema.json`
consideration, then a thin handler. Deferred with the same contract-gating rationale
as the other CLI-only features this phase (HIPAA/EU-AI-Act export, ZK SDK).

## Explicitly out of scope for all of the above

- Vault key rotation / re-encryption over an existing vault (noted in ADR-0039 as a
  separate operational task).
- Any change to the vault's INSERT/SELECT-only grant posture unless deterministic
  mode's get-or-create requires a narrowly-scoped change (it does not — a SELECT then
  INSERT covers get-or-create).
