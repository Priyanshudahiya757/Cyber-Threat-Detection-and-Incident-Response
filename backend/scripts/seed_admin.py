"""
scripts/seed_admin.py

Purpose:
    Creating users through the API (POST /api/v1/users) is admin-only,
    which creates a chicken-and-egg problem: how does the FIRST admin
    account get created? This script does it directly against MongoDB,
    bypassing the API, and is meant to be run once per environment.

Usage:
    docker compose exec backend python scripts/seed_admin.py

    Or locally:
    cd backend && python scripts/seed_admin.py

Reads SEED_ADMIN_USERNAME / SEED_ADMIN_EMAIL / SEED_ADMIN_PASSWORD from
the environment (see .env.example). Safe to re-run — it's a no-op if
the admin username already exists.
"""
import asyncio
import os
import sys

from pydantic import ValidationError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.security import hash_password  # noqa: E402
from app.db.mongo import connect_to_mongo, create_user, ensure_indexes, get_user_by_username  # noqa: E402
from app.models.user_schema import UserCreate, UserRole  # noqa: E402

DEFAULT_PASSWORD = "ChangeMe123!"


async def main() -> int:
    try:
        # Validating through UserCreate applies the same username/password rules as the API.
        admin = UserCreate(
            username=os.getenv("SEED_ADMIN_USERNAME", "admin"),
            email=os.getenv("SEED_ADMIN_EMAIL", "admin@example.com"),
            password=os.getenv("SEED_ADMIN_PASSWORD", DEFAULT_PASSWORD),
            role=UserRole.ADMIN,
        )
    except ValidationError as exc:
        print(f"Invalid SEED_ADMIN_* settings:\n{exc}", file=sys.stderr)
        return 1

    connect_to_mongo()
    await ensure_indexes()

    if await get_user_by_username(admin.username):
        print(f"Admin user '{admin.username}' already exists - nothing to do.")
        return 0

    await create_user(
        username=admin.username,
        email=admin.email,
        hashed_password=hash_password(admin.password),
        role=admin.role.value,
    )
    print(f"Created admin user '{admin.username}'.")
    if admin.password == DEFAULT_PASSWORD:
        print("WARNING: this account uses the default password. Change it under Settings after first login.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
