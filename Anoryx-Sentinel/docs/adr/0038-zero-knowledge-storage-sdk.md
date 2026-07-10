# ADR-0038 — Practical Zero-Knowledge Storage SDK (F-032)

- Status: Accepted (implemented)
- Date: 2026-07-10
- Builds on: F-014's `admin/sso/secret_box.py` (the AES-256-GCM AEAD pattern +
  honest-crypto discipline this mirrors), `cryptography` (all primitives — no
  hand-rolled crypto, R3).
- Scope: `src/zk_sdk/` (new library + CLI). **No `contracts/` change, no server
  endpoint, no DB migration** — this is a CLIENT-SIDE SDK.

## Context

Roadmap F-032: "Client-side encryption SDK, keys never leave client,
ciphertext-only server, encrypted indexes. Depends on F-004." The goal is that
a client can store records through Sentinel such that a fully-compromised
server/DB learns nothing of the plaintext CONTENT.

## The honest threat model (read this first)

"Zero-knowledge storage" here is the **practical/colloquial** sense: the SERVER
has zero knowledge of plaintext content. It is **NOT** a zero-knowledge PROOF
system and **NOT** homomorphic encryption. Precisely:

**What it provides**
- Confidentiality of record content against a fully-compromised server/DB: the
  server stores only AES-256-GCM ciphertext + a random nonce + blind-index
  tags. Without the client's keys it cannot recover plaintext.
- Integrity/tamper-evidence: GCM authentication + an optional record-id bound as
  AAD (a server that swaps a ciphertext onto a different id is detected on
  decrypt).
- Keys never leave the client — the SDK has no code path that serialises key
  material to a server-bound form (enforced by construction + a dedicated test
  that greps the server representation for the raw keys).

**What it deliberately LEAKS (unavoidable for equality search)**
- Equality-searchable blind indexes are DETERMINISTIC, so they leak **equality
  and frequency**: two records with the same value for an indexed field produce
  the same tag, and an attacker holding the ciphertext DB can see which records
  share a value and run frequency analysis. Only index fields whose
  equality/frequency leakage you can accept.
- Record size, record count, and access patterns leak (this is not ORAM).
- Client-side compromise is out of scope — keys live on the client.

This is the standard, well-understood tradeoff of searchable-symmetric
encryption. The SDK names it plainly rather than overclaiming "zero-knowledge".

## Decision

A layered client-side SDK in `src/zk_sdk/`:

- **`keys.py`** — a 32-byte MASTER key (random, or scrypt-derived from a
  passphrase + client-stored salt) held only by the client. HKDF-SHA256 with
  distinct `info` labels derives two sub-keys (data + index) so a blind-index
  tag can never be used to attack the data ciphertext (domain separation).
- **`envelope.py`** — `encrypt_record`/`decrypt_record` using AES-256-GCM, a
  fresh 12-byte random nonce per record (never reused), optional AAD, producing
  an `EncryptedRecord` whose `to_server_dict()` is the ONLY thing sent to the
  server: `{scheme, nonce_b64, ciphertext_b64, index_tags}` — no plaintext, no
  keys. Fail-closed on wrong key / tamper (`DecryptionError`, never a guessed
  plaintext).
- **`blind_index.py`** — `HMAC-SHA256(index_key, field_name ‖ value)` truncated
  to 128 bits. Field name folded in so the same value under different fields
  yields different tags (no cross-field correlation). Deterministic by
  necessity (that is what enables server-side equality matching) — with the
  leakage that implies.
- **`sdk.py`** — `ZkClient`: `encrypt(payload, record_id, index_fields)`,
  `decrypt(record, record_id)`, `query_tag(field, value)` (the tag a client
  sends the server to ask for equality matches).
- **`cli.py`** — `sentinel-zk keygen/encrypt/decrypt/query-tag/verify`. `verify`
  confirms a stored record is ciphertext-only (and, with `--probe`, that a known
  plaintext value does not appear) — the operator-facing demonstration of the ZK
  property.

## Why no server endpoint (yet)

The SDK is deliberately client-side and self-contained: it produces opaque
records a client could store via ANY channel. Wiring a first-class
"ciphertext-blob store + blind-index equality query" HTTP surface into Sentinel
would need a new `contracts/openapi.yaml` route (api-architect-owned, the same
gap that scoped F-025/F-026/F-027) plus a persistence table and query path. That
server side is deferred to `docs/followups/f-032-ciphertext-store-endpoint.md`.
Shipping the client SDK first is the correct order anyway — the server can only
ever be as trustworthy as "it holds opaque bytes", which is exactly what the SDK
guarantees regardless of where the bytes land.

## Honest limitations (recap)

- Equality-searchable indexes leak equality/frequency; size/count/access
  patterns leak. Not homomorphic, not ORAM, not a ZK proof system.
- Range/prefix/substring search over ciphertext is NOT provided (only exact
  equality). Order-revealing/order-preserving encryption is intentionally
  excluded — its leakage is far worse and rarely worth it.
- Key management (backup, rotation, multi-device) is the client's
  responsibility; losing the master key means losing the data (there is no
  server-side recovery, by design).
