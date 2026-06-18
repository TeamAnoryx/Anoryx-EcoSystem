# DB-Integration Tests (persistence + policy) — Setup Guide

Both `tests/persistence/**` and `tests/policy/**` are **DB-integration** suites whose
conftests call `pytest.fail()` at module import when the env vars below are absent — a
deliberate F-003b safety so the isolation/RLS suite never runs against an unprovisioned
database (which could pass spuriously). This is **not a defect**: these tests are
CI-validated against a freshly-provisioned Postgres and simply require credentials to run
locally. The DB-free suites (`tests/gateway`, `tests/deploy`, `tests/orchestration`) run
without any of this.

## Required Environment Variables

The following environment variables **must** be set before running the DB-integration
tests (persistence + policy). The conftests call `pytest.fail()` immediately if any
required variable is absent — there is no silent fallback.

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string (privileged / owner role) | `postgresql+asyncpg://sentinel:secret@localhost:5432/sentinel_dev` |
| `APP_DATABASE_URL` | PostgreSQL connection string (sentinel_app role, NOBYPASSRLS) | `postgresql+asyncpg://sentinel_app:devlocalpw@localhost:5432/sentinel_dev` |
| `SENTINEL_KEY_SECRET` | HMAC secret for virtual API key fingerprinting | `my-dev-hmac-secret-at-least-32-chars` |

### Setting variables

Copy the root `.env.example` to `.env` and fill in real values:

```
DATABASE_URL=postgresql+asyncpg://sentinel:secret@localhost:5432/sentinel_dev
APP_DATABASE_URL=postgresql+asyncpg://sentinel_app:devlocalpw@localhost:5432/sentinel_dev
SENTINEL_KEY_SECRET=<random-string-at-least-32-chars>
```

The `.env` file is gitignored and hook-protected. **Never commit secrets to the repo.**

### SENTINEL_PROVISION_APP_ROLE — opt-in password provisioning (MED-2)

The `ensure_schema_at_head` session fixture can provision the `sentinel_app` role
password from `APP_DATABASE_URL` using a pre-computed SCRAM-SHA-256 verifier (the
plaintext password is never logged or written to SQL as a literal). This step is
**opt-in** and only runs when `SENTINEL_PROVISION_APP_ROLE` is truthy.

**Local dev — run once after initial DB setup:**

```bash
SENTINEL_PROVISION_APP_ROLE=1 python -m pytest tests/persistence/ -q
```

Subsequent test runs do not need the flag — the password persists across sessions.
If the role password is reset (e.g. by `alembic downgrade` / re-creating the role),
re-run with `SENTINEL_PROVISION_APP_ROLE=1` once.

**CI (ephemeral DB):** set `SENTINEL_PROVISION_APP_ROLE=1` in the CI workflow
environment so each fresh DB gets the password provisioned before tests run.

If provisioning fails (e.g. the role does not exist yet, or the privileged role
lacks ALTER ROLE privilege), a warning is emitted but tests continue. The warning
is traceable: check `alembic upgrade head` output to ensure migration 0006 ran.
The password value is **never** included in the warning message.

### Variable name consistency

The HMAC secret variable is named `SENTINEL_KEY_SECRET` in both
`virtual_api_key_repository.py` and `conftest.py`. Do not introduce a second
name (e.g. `SENTINEL_HMAC_SECRET`). If you rename the variable, rename it in
both places.

---

## Running Tests

```bash
# From Anoryx-Sentinel/ directory:
python -m pytest tests/persistence/ -v

# Unit tests only (no DB required):
python -m pytest tests/persistence/test_hash_chain_unit.py -v

# With coverage:
python -m pytest tests/persistence/ --cov=src/persistence --cov-report=term-missing
```

---

## Session Fixture and Transaction Isolation

The `session` fixture in `conftest.py` uses a **nested SAVEPOINT** pattern:

1. Opens an outer transaction (`BEGIN`).
2. Creates a SAVEPOINT for the test.
3. Yields the session to the test.
4. Rolls back to the SAVEPOINT on teardown.
5. Rolls back the outer transaction.

This means:
- Each test sees a clean DB state (changes from other tests are not visible).
- Nothing is committed to the DB — the DB is clean after the full test run.

**Known limitation (item 17 — test hygiene):** The outer transaction is never
committed. Tests that rely on committed-and-visible data from outside the current
connection (e.g., tamper tests that use a raw `UPDATE` to simulate tampering on
committed rows) need to manage their own engine/connection outside the `session`
fixture. See `test_audit_chain.py` tamper-detection tests for the current approach
(raw SQL within the same savepoint). A future improvement would use explicit
per-test transaction commit + cleanup hooks for stricter isolation, but this is
non-blocking for the current test suite.

---

## Schema Management

The `ensure_schema_at_head` autouse fixture runs `alembic upgrade head` once per
test session. This guarantees the schema is at the latest migration even if a
previous run left it in a downgraded state.

If `alembic upgrade head` fails, all tests in the session will fail with a clear
error message showing the Alembic output.

---

## Docker Postgres (local dev)

Use the Compose stack (see `deploy/README.md`):

```bash
docker compose up -d postgres        # F-009/F-010 dev Postgres
```

Point `DATABASE_URL` / `APP_DATABASE_URL` at it (user `sentinel`, db `sentinel_dev`,
password = your `POSTGRES_PASSWORD`).

## Optional-feature suites (slim/full — F-010)

The default install (`pip install -e ".[dev]"`) is **slim** — it omits Bedrock
(`boto3`), PII (`spaCy`/`Presidio`), and the gRPC OTLP exporter. The corresponding
`tests/orchestration` (PII/Bedrock) cases **skip** cleanly when those extras are absent.
To run them, install the extras: `pip install -e ".[all,dev]"`.
