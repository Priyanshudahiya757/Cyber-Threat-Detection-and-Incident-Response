"""
app/core/dependencies.py

Purpose:
    FastAPI dependency-injection functions used across API routers:
      - get_current_user: extracts + validates JWT, loads the user from Mongo
      - require_role(...): factory for role-gated endpoints (RBAC)

Connects to:
    - Used as `Depends(...)` in api/v1/*.py routers
    - Relies on core/security.py to decode tokens
    - Relies on db/mongo.py to fetch the user document
"""
from typing import List

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.core.security import TokenError, decode_token
from app.db.mongo import get_user_by_username
from app.models.user_schema import UserRole, UserInDB

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")


async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_token(token, expected_type="access")
    except TokenError:
        raise credentials_exception

    username: str = payload.get("sub")
    if username is None:
        raise credentials_exception

    user = await get_user_by_username(username)
    if user is None:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User account is disabled")

    return user


def require_role(*allowed_roles: UserRole):
    """
    Usage:
        @router.get("/admin-only")
        async def admin_endpoint(user: UserInDB = Depends(require_role(UserRole.ADMIN))):
            ...

    Returns a dependency that raises 403 if the authenticated user's role
    is not in `allowed_roles`. Admin is not implicitly granted access to
    analyst-only routes or vice versa — each route states exactly which
    roles may call it.
    """

    async def role_checker(user: UserInDB = Depends(get_current_user)) -> UserInDB:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.role}' is not permitted to access this resource",
            )
        return user

    return role_checker
