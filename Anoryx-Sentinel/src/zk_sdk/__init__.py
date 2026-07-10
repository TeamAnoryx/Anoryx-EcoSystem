"""Practical zero-knowledge storage SDK (F-032, ADR-0038).

A CLIENT-SIDE encryption SDK: the client encrypts records with keys that never
leave the client, and the server stores ONLY ciphertext plus blind-index tags.
Without the client's keys, a fully-compromised server/DB cannot read the
plaintext CONTENT of a record.

HONEST NAMING (read ADR-0038): "zero-knowledge storage" here is the practical/
colloquial sense — the SERVER has zero knowledge of plaintext content. This is
NOT a zero-knowledge PROOF system and NOT homomorphic encryption. Equality-
searchable blind indexes deliberately LEAK equality and frequency (identical
plaintext values produce identical tags); record size, count, and access
patterns also leak. Choose which fields to index accordingly.

Layers:
  keys.py         — client-held master key -> HKDF-derived data + index keys.
  envelope.py     — AES-256-GCM per-record encryption -> server-storable record.
  blind_index.py  — HMAC deterministic equality tags for search over ciphertext.
  sdk.py          — ZkClient high-level API.
  cli.py          — sentinel-zk operator/dev CLI.
"""
