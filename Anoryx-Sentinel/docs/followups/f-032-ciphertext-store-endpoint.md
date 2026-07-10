# Follow-up: server-side ciphertext store + blind-index query endpoint

**Context:** F-032 (ADR-0038) ships the CLIENT-side ZK storage SDK
(`src/zk_sdk/`): it produces ciphertext-only records (`{scheme, nonce_b64,
ciphertext_b64, index_tags}`) and the blind-index query tags a client would send
to search them. It does NOT ship the server side that stores those blobs and
answers equality queries over the tags.

**Why deferred:** a first-class server surface needs (a) a new
`contracts/openapi.yaml` route family (e.g. `PUT /v1/zk/records/{id}`,
`POST /v1/zk/query`) — api-architect-owned, unavailable this session (the
`ANORYX_ACTIVE_AGENT` propagation gap, ADR-0031/0032) — and (b) a persistence
table (`zk_records`: id, tenant_id, scheme, nonce, ciphertext, index_tags JSONB)
with RLS + a GIN index on the tags for equality lookup. That is a materially
larger change than the client SDK.

**What it would look like:**

1. Table `zk_records` (RLS-scoped like every per-tenant table): `record_id` PK,
   `tenant_id` FK, `scheme`, `nonce_b64`, `ciphertext_b64`, `index_tags` JSONB.
   A GIN index on `index_tags` supports `WHERE index_tags @> '{"email":"<tag>"}'`
   equality lookup WITHOUT the server ever seeing plaintext.
2. `PUT /v1/zk/records/{id}` stores a client-produced record verbatim; the
   server MUST reject any body containing keys other than the four opaque fields
   (defence-in-depth against a client that accidentally attaches plaintext — the
   same check `sentinel-zk verify` performs).
3. `POST /v1/zk/query` takes `{field, tag}` and returns matching record ids /
   ciphertexts; the server matches tags only, never values.
4. Honest documentation on the endpoint that equality/frequency leaks via the
   tags (ADR-0038's threat model), so a tenant chooses indexed fields
   accordingly.

The client SDK is unchanged by this — it already emits exactly the record and
query-tag shapes such an endpoint would consume.
