# Persistence Tests — Setup Guide

## Required Environment Variables

The following environment variables **must** be set before running persistence tests.
Tests will call `pytest.fail()` immediately if any required variable is absent — there
is no silent fallback.

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+asyncpg://sentinel:secret@localhost:5432/sentinel_dev` |
| `SENTINEL_KEY_SECRET` | HMAC secret for virtual API key fingerprinting | `my-dev-hmac-secret-at-least-32-chars` |

### Setting variables

Copy the root `.env.example` to `.env` and fill in real values:

```
DATABASE_URL=postgresql+asyncpg://sentinel:secret@localhost:5432/sentinel_dev
SENTINEL_KEY_SECRET=<random-string-at-least-32-chars>
```

The `.env` file is gitignored and hook-protected. **Never commit secrets to the repo.**

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

A Docker Compose file is planned for F-infra. For now, run Postgres manually:

```bash
docker run -d \
  --name sentinel-postgres \
  -e POSTGRES_USER=sentinel \
  -e POSTGRES_PASSWORD=secret \
  -e POSTGRES_DB=sentinel_dev \
  -p 5432:5432 \
  postgres:16-alpine
```
