"""Worker entrypoint — initialises the Redis pool then runs the bulk worker loop.

The gateway image's redis_client module requires redis_client.init(settings)
to be called before get_client() is used. In normal gateway operation this is
done by the FastAPI lifespan hook. The standalone worker bypasses the lifespan,
so this thin runner calls init() explicitly before starting run_worker().

This file is bind-mounted at /worker/run_worker.py by docker-compose.yml and
executed via: python /worker/run_worker.py

NOTE: The slim gateway image (INSTALL_EXTRAS="") does not include boto3/aioboto3
which the bulk storage backend requires. In the compose stack the worker service
is built with INSTALL_EXTRAS=bulk to get these dependencies.
"""

import asyncio
import subprocess
import sys


def _ensure_bulk_deps() -> None:
    """Install bulk extras if boto3 is not available (slim-image fallback)."""
    try:
        import boto3  # noqa: F401
    except ImportError:
        print("run_worker: boto3 not found — installing [bulk] extras at runtime", flush=True)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--no-warn-script-location",
                "--user",
                "boto3>=1.34,<2",
                "aioboto3>=12,<14",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"run_worker: pip install failed:\n{result.stderr}", flush=True, file=sys.stderr)
            sys.exit(1)
        print("run_worker: bulk deps installed", flush=True)
        # Reload importlib to pick up newly installed packages.
        import importlib  # noqa: E401, E402

        importlib.invalidate_caches()
        import importlib.machinery  # noqa: F401


_ensure_bulk_deps()

from bulk.worker import run_worker  # noqa: E402
from gateway.config import get_settings  # noqa: E402
from gateway.redis_client import init as redis_init  # noqa: E402


async def main() -> None:
    settings = get_settings()
    await redis_init(settings)
    await run_worker()


if __name__ == "__main__":
    asyncio.run(main())
