"""
tests/test_auth.py

Purpose:
    Covers the auth vertical slice end-to-end at the API level: admin
    creation via seed logic, login success/failure, RBAC enforcement on
    /auth/register, and token refresh. This is the template pattern for
    tests in later phases (detection/, incidents/) — spin up mock_db,
    hit the API through the `client` fixture, assert on responses.
"""
import pytest

from app.core.security import hash_password
from app.db.mongo import create_user


@pytest.mark.asyncio
async def test_login_success(client, mock_db):
    await create_user(
        username="analyst1",
        email="analyst1@example.com",
        hashed_password=hash_password("SecurePass123!"),
        role="soc_analyst",
    )

    response = await client.post(
        "/api/v1/auth/login", json={"username": "analyst1", "password": "SecurePass123!"}
    )

    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["user"]["username"] == "analyst1"
    assert body["user"]["role"] == "soc_analyst"


@pytest.mark.asyncio
async def test_login_wrong_password(client, mock_db):
    await create_user(
        username="analyst2",
        email="analyst2@example.com",
        hashed_password=hash_password("CorrectPass1!"),
        role="soc_analyst",
    )

    response = await client.post(
        "/api/v1/auth/login", json={"username": "analyst2", "password": "WrongPass1!"}
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_register_requires_admin_role(client, mock_db):
    await create_user(
        username="analyst3",
        email="analyst3@example.com",
        hashed_password=hash_password("SecurePass123!"),
        role="soc_analyst",
    )
    login_resp = await client.post(
        "/api/v1/auth/login", json={"username": "analyst3", "password": "SecurePass123!"}
    )
    token = login_resp.json()["access_token"]

    response = await client.post(
        "/api/v1/auth/register",
        json={
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "SecurePass123!",
            "role": "soc_analyst",
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_can_register_new_user(client, mock_db):
    await create_user(
        username="admin1",
        email="admin1@example.com",
        hashed_password=hash_password("AdminPass123!"),
        role="admin",
    )
    login_resp = await client.post(
        "/api/v1/auth/login", json={"username": "admin1", "password": "AdminPass123!"}
    )
    token = login_resp.json()["access_token"]

    response = await client.post(
        "/api/v1/auth/register",
        json={
            "username": "newanalyst",
            "email": "newanalyst@example.com",
            "password": "SecurePass123!",
            "role": "soc_analyst",
        },
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 201
    assert response.json()["username"] == "newanalyst"


@pytest.mark.asyncio
async def test_refresh_token_issues_new_pair(client, mock_db):
    await create_user(
        username="analyst4",
        email="analyst4@example.com",
        hashed_password=hash_password("SecurePass123!"),
        role="soc_analyst",
    )
    login_resp = await client.post(
        "/api/v1/auth/login", json={"username": "analyst4", "password": "SecurePass123!"}
    )
    refresh_token = login_resp.json()["refresh_token"]

    response = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})

    assert response.status_code == 200
    assert "access_token" in response.json()
