"""
scripts/seed_admin.py

Purpose:
    Registration (/api/v1/auth/register) is intentionally admin-only for
    auditability, which creates a chicken-and-egg problem: how does the
    FIRST admin account get created? This script does it directly against
    MongoDB, bypassing the API, and is meant to be run once per environment.

Usage:
    docker compose exec backend python scripts/seed_admin.py

    Or locally:
    cd backend && python -m scripts.seed_admin

Reads SEED_ADMIN_USERNAME / SEED_ADMIN_EMAIL / SEED_ADMIN_PASSWORD from
the environment (see .env.example). Safe to re-run — it's a no-op if
the admin username already exists.
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.config import settings  # noqa: E402
from app.core.logging_config import get_logger  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.db.mongo import connect_to_mongo, create_user, ensure_indexes, get_user_by_username  # noqa: E402

logger = get_logger("seed_admin")


async def main() -> None:
    connect_to_mongo()
    await ensure_indexes()

    username = os.getenv("SEED_ADMIN_USERNAME", "admin")
    email = os.getenv("SEED_ADMIN_EMAIL", "admin@example.com")
    password = os.getenv("SEED_ADMIN_PASSWORD", "ChangeMe123!")

    existing = await get_user_by_username(username)
    if existing:
        logger.info(f"Admin user '{username}' already exists — skipping.")
        return

    await create_user(
        username=username,
        email=email,
        hashed_password=hash_password(password),
        role="admin",
    )
    logger.info(f"Created initial admin user '{username}'. CHANGE THE PASSWORD after first login.")


if __name__ == "__main__":
    asyncio.run(main())
