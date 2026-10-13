"""
tests/conftest.py

Purpose:
    Shared pytest fixtures. `mock_db` swaps the real MongoDB for an
    in-memory mongomock-motor instance so tests never need a running
    database; `client` gives an httpx AsyncClient bound to the FastAPI
    app. Elasticsearch is not faked wholesale — tests that touch it
    monkeypatch the specific db/elastic.py functions they need.

    `auth_headers` creates a user of the requested role and returns the
    Authorization header for it, which keeps API tests short.
"""
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.core.security import create_access_token, hash_password
from app.db import mongo as mongo_module

TEST_PASSWORD = "SecurePass123!"


@pytest_asyncio.fixture
async def mock_db(monkeypatch):
    fake_db = AsyncMongoMockClient()["siem_dashboard_test"]
    monkeypatch.setattr(mongo_module, "_db", fake_db)
    await mongo_module.ensure_indexes()
    return fake_db


@pytest_asyncio.fixture
async def client(mock_db):
    from app.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


@pytest_asyncio.fixture
async def auth_headers(mock_db):
    """Factory: `await auth_headers("admin")` -> headers for a freshly created user of that role."""

    async def _make(role: str = "soc_analyst", username: str | None = None) -> dict:
        username = username or f"{role}_user"
        await mongo_module.create_user(
            username=username,
            email=f"{username}@example.com",
            hashed_password=hash_password(TEST_PASSWORD),
            role=role,
        )
        return {"Authorization": f"Bearer {create_access_token(subject=username, role=role)}"}

    return _make
