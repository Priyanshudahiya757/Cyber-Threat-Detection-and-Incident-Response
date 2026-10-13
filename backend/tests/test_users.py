"""
tests/test_users.py

Purpose:
    Account administration: only admins manage users, and the guard
    rails that keep the platform from losing its last administrator.
"""
import pytest

from tests.conftest import TEST_PASSWORD

NEW_USER = {
    "username": "newanalyst",
    "email": "newanalyst@example.com",
    "password": "SecurePass123!",
    "role": "soc_analyst",
}


@pytest.mark.asyncio
async def test_analyst_cannot_manage_users(client, auth_headers):
    headers = await auth_headers("soc_analyst")

    assert (await client.get("/api/v1/users", headers=headers)).status_code == 403
    assert (await client.post("/api/v1/users", json=NEW_USER, headers=headers)).status_code == 403
    assert (
        await client.patch("/api/v1/users/soc_analyst_user", json={"role": "admin"}, headers=headers)
    ).status_code == 403


@pytest.mark.asyncio
async def test_admin_creates_and_lists_users(client, auth_headers):
    headers = await auth_headers("admin")

    created = await client.post("/api/v1/users", json=NEW_USER, headers=headers)
    assert created.status_code == 201
    assert created.json()["username"] == "newanalyst"
    assert "password" not in created.json() and "hashed_password" not in created.json()

    listed = await client.get("/api/v1/users", headers=headers)
    assert listed.status_code == 200
    assert {u["username"] for u in listed.json()} == {"admin_user", "newanalyst"}


@pytest.mark.asyncio
async def test_duplicate_username_or_email_is_rejected(client, auth_headers):
    headers = await auth_headers("admin")
    await client.post("/api/v1/users", json=NEW_USER, headers=headers)

    same_username = await client.post(
        "/api/v1/users", json={**NEW_USER, "email": "other@example.com"}, headers=headers
    )
    assert same_username.status_code == 409

    same_email = await client.post(
        "/api/v1/users", json={**NEW_USER, "username": "someoneelse"}, headers=headers
    )
    assert same_email.status_code == 409


@pytest.mark.asyncio
@pytest.mark.parametrize("password", ["short1", "onlyletters", "1234567890"])
async def test_weak_passwords_are_rejected(client, auth_headers, password):
    headers = await auth_headers("admin")
    response = await client.post("/api/v1/users", json={**NEW_USER, "password": password}, headers=headers)
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_admin_can_disable_and_promote_another_user(client, auth_headers):
    headers = await auth_headers("admin")
    await client.post("/api/v1/users", json=NEW_USER, headers=headers)

    promoted = await client.patch("/api/v1/users/newanalyst", json={"role": "admin"}, headers=headers)
    assert promoted.status_code == 200
    assert promoted.json()["role"] == "admin"

    disabled = await client.patch("/api/v1/users/newanalyst", json={"is_active": False}, headers=headers)
    assert disabled.status_code == 200
    assert disabled.json()["is_active"] is False

    login = await client.post(
        "/api/v1/auth/login", json={"username": "newanalyst", "password": NEW_USER["password"]}
    )
    assert login.status_code == 403


@pytest.mark.asyncio
async def test_admin_cannot_disable_or_demote_themselves(client, auth_headers):
    headers = await auth_headers("admin")

    assert (
        await client.patch("/api/v1/users/admin_user", json={"is_active": False}, headers=headers)
    ).status_code == 400
    assert (
        await client.patch("/api/v1/users/admin_user", json={"role": "soc_analyst"}, headers=headers)
    ).status_code == 400


@pytest.mark.asyncio
async def test_one_admin_can_demote_another(client, auth_headers):
    headers = await auth_headers("admin", username="admin_a")
    await auth_headers("admin", username="admin_b")

    demoted = await client.patch("/api/v1/users/admin_b", json={"role": "soc_analyst"}, headers=headers)
    assert demoted.status_code == 200
    assert demoted.json()["role"] == "soc_analyst"


@pytest.mark.asyncio
async def test_demoted_admin_loses_access_immediately(client, auth_headers):
    headers_a = await auth_headers("admin", username="admin_a")
    headers_b = await auth_headers("admin", username="admin_b")
    await client.patch("/api/v1/users/admin_b", json={"role": "soc_analyst"}, headers=headers_a)

    # admin_b's token still claims "admin", but the database is the authority.
    assert (await client.get("/api/v1/users", headers=headers_b)).status_code == 403


@pytest.mark.asyncio
async def test_unknown_user_is_404(client, auth_headers):
    headers = await auth_headers("admin")
    assert (await client.patch("/api/v1/users/ghost", json={"is_active": False}, headers=headers)).status_code == 404


@pytest.mark.asyncio
async def test_admin_password_reset_signs_the_user_out(client, auth_headers):
    admin_headers = await auth_headers("admin")
    await auth_headers("soc_analyst", username="victim")

    reset = await client.post(
        "/api/v1/users/victim/reset-password", json={"new_password": "ResetPass789"}, headers=admin_headers
    )
    assert reset.status_code == 204

    old = await client.post("/api/v1/auth/login", json={"username": "victim", "password": TEST_PASSWORD})
    assert old.status_code == 401
    new = await client.post("/api/v1/auth/login", json={"username": "victim", "password": "ResetPass789"})
    assert new.status_code == 200


@pytest.mark.asyncio
async def test_assignable_lists_only_active_users(client, auth_headers, mock_db):
    headers = await auth_headers("soc_analyst", username="alice")
    await auth_headers("soc_analyst", username="bob")
    await mock_db.users.update_one({"username": "bob"}, {"$set": {"is_active": False}})

    response = await client.get("/api/v1/users/assignable", headers=headers)
    assert response.status_code == 200
    assert response.json() == ["alice"]
