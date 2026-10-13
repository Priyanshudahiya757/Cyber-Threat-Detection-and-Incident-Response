"""
app/api/v1/auth.py

Purpose:
    Session endpoints: login (issues JWT access + refresh tokens), token
    refresh, logout, "who am I", and changing one's own password.
    Account administration lives in api/v1/users.py.

    Security behaviour:
      - Repeated failed logins lock the username (core/login_guard.py).
      - Refresh tokens are single-use: exchanging one revokes it, and
        logout revokes the one the client holds.
      - Changing a password invalidates every token issued before it.

Connects to:
    - core/security.py for password verification and token creation
    - core/login_guard.py for brute-force lockout
    - db/mongo.py for user lookup and token revocation
    - Mounted in main.py under /api/v1/auth
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Response, status

from app.core import login_guard
from app.core.dependencies import get_current_user
from app.core.logging_config import audit_event
from app.core.security import (
    REFRESH_TOKEN,
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    issued_before,
    token_expiry,
    verify_password,
)
from app.db import mongo
from app.models.user_schema import (
    ChangePasswordRequest,
    LoginRequest,
    RefreshRequest,
    TokenResponse,
    UserInDB,
    UserPublic,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])

#: A bcrypt hash of a random value, verified against when the username
#: doesn't exist so unknown and known usernames take the same time.
_DUMMY_HASH = hash_password("timing-equalisation-placeholder")


def _issue_tokens(user: UserInDB) -> TokenResponse:
    return TokenResponse(
        access_token=create_access_token(subject=user.username, role=user.role.value),
        refresh_token=create_refresh_token(subject=user.username, role=user.role.value),
        user=user.to_public(),
    )


def _locked_response(until: datetime) -> HTTPException:
    retry_after = max(1, int((until - mongo.utcnow()).total_seconds()))
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many failed login attempts. Try again later.",
        headers={"Retry-After": str(retry_after)},
    )


@router.post("/login", response_model=TokenResponse)
async def login(credentials: LoginRequest):
    locked = await login_guard.locked_until(credentials.username)
    if locked:
        raise _locked_response(locked)

    user = await mongo.get_user_by_username(credentials.username)
    password_ok = verify_password(credentials.password, user.hashed_password if user else _DUMMY_HASH)

    if user is None or not password_ok:
        locked = await login_guard.register_failure(credentials.username)
        audit_event("login_failed", username=credentials.username, locked=locked is not None)
        if locked:
            raise _locked_response(locked)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    await login_guard.register_success(user.username)
    await mongo.update_last_login(user.username)
    audit_event("login_success", username=user.username, role=user.role.value)
    return _issue_tokens(user)


async def _user_for_refresh_token(token: str) -> tuple[UserInDB, dict]:
    """Validate a refresh token and return its user and decoded payload, or raise 401."""
    invalid = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")
    try:
        payload = decode_token(token, expected_type=REFRESH_TOKEN)
    except TokenError:
        raise invalid

    if await mongo.is_token_revoked(payload.get("jti", "")):
        raise invalid

    user = await mongo.get_user_by_username(payload["sub"])
    if user is None or not user.is_active or issued_before(payload, user.token_valid_after):
        raise invalid
    return user, payload


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(body: RefreshRequest):
    user, payload = await _user_for_refresh_token(body.refresh_token)
    # Rotation: the presented refresh token is spent the moment it is exchanged.
    await mongo.revoke_token(payload["jti"], token_expiry(payload))
    return _issue_tokens(user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(body: RefreshRequest):
    """
    Revoke the client's refresh token. Always answers 204 — an invalid or
    already-expired token simply has nothing left to revoke.
    """
    try:
        payload = decode_token(body.refresh_token, expected_type=REFRESH_TOKEN)
    except TokenError:
        return Response(status_code=status.HTTP_204_NO_CONTENT)

    await mongo.revoke_token(payload["jti"], token_expiry(payload))
    audit_event("logout", username=payload["sub"])
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=UserPublic)
async def get_me(current_user: UserInDB = Depends(get_current_user)):
    return current_user.to_public()


@router.post("/change-password", response_model=TokenResponse)
async def change_password(body: ChangePasswordRequest, current_user: UserInDB = Depends(get_current_user)):
    """
    Change the caller's own password. All existing sessions are signed
    out; a fresh token pair is returned so the current one continues.
    """
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    if body.new_password == body.current_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="New password must differ from the current one"
        )

    await mongo.set_user_password(current_user.username, hash_password(body.new_password))
    audit_event("password_changed", username=current_user.username)
    return _issue_tokens(current_user)
