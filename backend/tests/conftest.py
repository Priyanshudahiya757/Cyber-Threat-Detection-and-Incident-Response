"""
tests/conftest.py

Purpose:
    Shared pytest fixtures. Uses mongomock-motor to fake MongoDB in tests
    so the test suite never touches a real database — fast, and safe to
    run in CI without spinning up Docker.

    Elasticsearch is not mocked here (Phase 1); ingestion/detection tests
    added in later phases should mock db/elastic.py functions directly at
    the function level rather than standing up a fake ES.
"""
import asyncio

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from mongomock_motor import AsyncMongoMockClient

from app.db import mongo as mongo_module


@pytest_asyncio.fixture
async def mock_db(monkeypatch):
    fake_client = AsyncMongoMockClient()
    fake_db = fake_client["siem_dashboard_test"]

    monkeypatch.setattr(mongo_module, "_db", fake_db)
    await mongo_module.ensure_indexes()
    return fake_db


@pytest_asyncio.fixture
async def client(mock_db):
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
