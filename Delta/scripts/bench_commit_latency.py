"""Local commit-latency benchmark for the Delta ledger (D-003, Fork 6).

Measures the p95 latency of an atomic balanced-transaction append under concurrent
load and asserts it is < 1s. This is a LOCAL/manual benchmark — it is NOT run in CI
(perf thresholds flake on shared runners). Run against a live Postgres with the
delta schema migrated and delta_app provisioned:

    DATABASE_URL=postgresql://delta:delta@localhost:5544/delta_dev \
    APP_DATABASE_URL=postgresql://delta_app:delta@localhost:5544/delta_dev \
    python Delta/scripts/bench_commit_latency.py --writers 32 --txns 2000

Prints the latency distribution and exits non-zero if p95 >= 1s.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from delta.ledger import EntryDirection, LedgerEntry, Transaction
from delta.money import Money
from delta.persistence.ledger_store import append_transaction

_NOW = datetime(2026, 6, 26, 12, 0, 0, tzinfo=timezone.utc)


def _asyncpg(url: str) -> str:
    url = re.sub(r"^postgresql\+psycopg://", "postgresql+asyncpg://", url)
    return re.sub(r"^postgresql://", "postgresql+asyncpg://", url)


def _balanced(tenant_id: str, cents: int) -> Transaction:
    common = dict(
        team_id=str(uuid.uuid4()),
        project_id=str(uuid.uuid4()),
        agent_id="gateway-core",
        timestamp=_NOW,
    )
    return Transaction(
        txn_id=str(uuid.uuid4()),
        tenant_id=tenant_id,
        entries=(
            LedgerEntry(
                entry_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                account_id=str(uuid.uuid4()),
                direction=EntryDirection.DEBIT,
                amount=Money(minor_units=cents, currency="USD"),
                **common,
            ),
            LedgerEntry(
                entry_id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                account_id=str(uuid.uuid4()),
                direction=EntryDirection.CREDIT,
                amount=Money(minor_units=cents, currency="USD"),
                **common,
            ),
        ),
        timestamp=_NOW,
        description="bench",
    )


async def _run(writers: int, txns: int, sync_off: bool) -> int:
    app_url = os.environ.get("APP_DATABASE_URL", "")
    if not app_url:
        print("APP_DATABASE_URL is not set")
        return 2
    engine = create_async_engine(_asyncpg(app_url), pool_size=writers, max_overflow=8)
    factory = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
    tenant_id = str(uuid.uuid4())
    latencies: list[float] = []
    sem = asyncio.Semaphore(writers)

    async def one() -> None:
        async with sem:
            async with factory() as s:
                await s.execute(
                    text("SELECT set_config('app.current_tenant_id', :t, true)"),
                    {"t": tenant_id},
                )
                if sync_off:
                    # Isolate ledger-compute latency from this dev box's slow
                    # Docker-bind fsync. Production runs synchronous_commit=on with
                    # fast storage; this flag does not change the ledger logic.
                    await s.execute(text("SET LOCAL synchronous_commit = off"))
                t0 = time.perf_counter()
                await append_transaction(s, _balanced(tenant_id, 100))
                latencies.append(time.perf_counter() - t0)

    await asyncio.gather(*(one() for _ in range(txns)))
    await engine.dispose()

    latencies.sort()
    p50 = latencies[len(latencies) // 2]
    p95 = latencies[int(len(latencies) * 0.95)]
    p99 = latencies[int(len(latencies) * 0.99)]
    print(f"appends={txns} writers={writers}")
    print(f"p50={p50 * 1000:.1f}ms  p95={p95 * 1000:.1f}ms  p99={p99 * 1000:.1f}ms")
    if p95 >= 1.0:
        print(f"FAIL: p95 {p95:.3f}s >= 1s")
        return 1
    print("OK: p95 < 1s")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--writers", type=int, default=32)
    ap.add_argument("--txns", type=int, default=2000)
    ap.add_argument(
        "--sync-off",
        action="store_true",
        help="SET synchronous_commit=off per session to isolate ledger-compute "
        "latency from slow dev-box fsync (production uses synchronous_commit=on).",
    )
    args = ap.parse_args()
    # asyncpg's auth handshake fails on Windows' default ProactorEventLoop
    # (WinError 64). Use the selector loop, as pytest-asyncio does on Windows.
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    return asyncio.run(_run(args.writers, args.txns, args.sync_off))


if __name__ == "__main__":
    raise SystemExit(main())
