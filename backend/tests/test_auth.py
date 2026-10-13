"""
tests/test_auth.py

Purpose:
    Session endpoints: login, brute-force lockout, single-use refresh
    tokens, logout, and password change invalidating older sessions.
"""
import pytest

from app.core.config import settings
from app.core.security import hash_password
from app.db.mongo import create_user

PASSWORD = "SecurePass123!"


async def _create(username: str, role: str = "soc_analyst") -> None:
    await create_user(
        username=username,
        email=f"{username}@example.com",
        hashed_password=hash_password(PASSWORD),
        role=role,
    )


async def _login(client, username: str, password: str = PASSWORD):
    return await client.post("/api/v1/auth/login", json={"username": username, "password": password})


@pytest.mark.asyncio
async def test_login_success(client, mock_db):
    await _create("analyst1")

    response = await _login(client, "analyst1")

    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["user"]["username"] == "analyst1"
    assert body["user"]["role"] == "soc_analyst"
    assert "hashed_password" not in body["user"]


@pytest.mark.asyncio
async def test_login_wrong_password(client, mock_db):
    await _create("analyst2")
    assert (await _login(client, "analyst2", "WrongPass1!")).status_code == 401


@pytest.mark.asyncio
async def test_unknown_user_gets_same_response_as_wrong_password(client, mock_db):
    response = await _login(client, "nobody")
    assert response.status_code == 401
    assert response.json()["detail"] == "Incorrect username or password"


@pytest.mark.asyncio
async def test_disabled_account_cannot_log_in(client, mock_db):
    await _create("leaver")
    await mock_db.users.update_one({"username": "leaver"}, {"$set": {"is_active": False}})
    assert (await _login(client, "leaver")).status_code == 403


@pytest.mark.asyncio
async def test_repeated_failures_lock_the_account(client, mock_db):
    await _create("target")

    for _ in range(settings.LOGIN_MAX_FAILED_ATTEMPTS - 1):
        assert (await _login(client, "target", "WrongPass1!")).status_code == 401

    locking_attempt = await _login(client, "target", "WrongPass1!")
    assert locking_attempt.status_code == 429
    assert int(locking_attempt.headers["Retry-After"]) > 0

    # Even the correct password is refused while the lock is active.
    assert (await _login(client, "target")).status_code == 429


@pytest.mark.asyncio
async def test_successful_login_resets_the_failure_count(client, mock_db):
    await _create("forgetful")

    for _ in range(settings.LOGIN_MAX_FAILED_ATTEMPTS - 1):
        await _login(client, "forgetful", "WrongPass1!")
    assert (await _login(client, "forgetful")).status_code == 200

    # The counter restarted, so one more mistake does not lock the account.
    assert (await _login(client, "forgetful", "WrongPass1!")).status_code == 401
    assert (await _login(client, "forgetful")).status_code == 200


@pytest.mark.asyncio
async def test_me_requires_a_valid_access_token(client, mock_db):
    await _create("analyst3")
    tokens = (await _login(client, "analyst3")).json()

    ok = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert ok.status_code == 200
    assert ok.json()["username"] == "analyst3"

    # A refresh token must not be accepted where an access token is expected.
    wrong_type = await client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['refresh_token']}"}
    )
    assert wrong_type.status_code == 401
    assert (await client.get("/api/v1/auth/me")).status_code == 401


@pytest.mark.asyncio
async def test_refresh_token_issues_new_pair_and_is_single_use(client, mock_db):
    await _create("analyst4")
    refresh_token = (await _login(client, "analyst4")).json()["refresh_token"]

    first = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert first.status_code == 200
    assert first.json()["refresh_token"] != refresh_token

    replay = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert replay.status_code == 401


@pytest.mark.asyncio
async def test_logout_revokes_the_refresh_token(client, mock_db):
    await _create("analyst5")
    refresh_token = (await _login(client, "analyst5")).json()["refresh_token"]

    assert (await client.post("/api/v1/auth/logout", json={"refresh_token": refresh_token})).status_code == 204
    after = await client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert after.status_code == 401


@pytest.mark.asyncio
async def test_logout_with_garbage_token_still_succeeds(client, mock_db):
    assert (await client.post("/api/v1/auth/logout", json={"refresh_token": "not-a-token"})).status_code == 204


@pytest.mark.asyncio
async def test_change_password(client, mock_db):
    await _create("analyst6")
    tokens = (await _login(client, "analyst6")).json()
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    wrong_current = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "NotMyPassword1", "new_password": "BrandNewPass456"},
        headers=headers,
    )
    assert wrong_current.status_code == 400

    weak = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": PASSWORD, "new_password": "allletters"},
        headers=headers,
    )
    assert weak.status_code == 422

    changed = await client.post(
        "/api/v1/auth/change-password",
        json={"current_password": PASSWORD, "new_password": "BrandNewPass456"},
        headers=headers,
    )
    assert changed.status_code == 200
    assert "access_token" in changed.json()

    assert (await _login(client, "analyst6")).status_code == 401
    assert (await _login(client, "analyst6", "BrandNewPass456")).status_code == 200


@pytest.mark.asyncio
async def test_password_change_invalidates_tokens_issued_earlier(client, mock_db):
    from datetime import timedelta

    from app.db.mongo import utcnow

    await _create("analyst7")
    tokens = (await _login(client, "analyst7")).json()

    # Equivalent to a password change one minute from now: every token
    # issued up to this point predates the cut-off.
    await mock_db.users.update_one(
        {"username": "analyst7"}, {"$set": {"token_valid_after": utcnow() + timedelta(minutes=1)}}
    )

    me = await client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert me.status_code == 401
    refresh = await client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh.status_code == 401
