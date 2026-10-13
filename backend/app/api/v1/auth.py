"""
app/api/v1/auth.py

Purpose:
    Authentication endpoints: login (issues JWT access + refresh tokens),
    token refresh, admin-only user registration, and "who am I".

Connects to:
    - core/security.py for password verification and token creation
    - db/mongo.py for user lookup/creation
    - core/dependencies.py for get_current_user / require_role on
      protected routes (registration is admin-only)
    - Mounted in main.py under /api/v1/auth
"""
from fastapi import APIRouter, Depends, HTTPException, status

from app.core.dependencies import get_current_user, require_role
from app.core.logging_config import get_audit_logger, get_logger
from app.core.security import (
    TokenError,
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    verify_password,
)
from app.db.mongo import (
    create_user,
    get_user_by_email,
    get_user_by_username,
    update_last_login,
)
from app.models.user_schema import (
    LoginRequest,
    RefreshRequest,
    TokenResponse,
    UserCreate,
    UserInDB,
    UserPublic,
    UserRole,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])
logger = get_logger(__name__)
audit = get_audit_logger()


def _to_public(user: UserInDB) -> UserPublic:
    return UserPublic(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at,
        last_login=user.last_login,
    )


@router.post("/login", response_model=TokenResponse)
async def login(credentials: LoginRequest):
    user = await get_user_by_username(credentials.username)

    if user is None or not verify_password(credentials.password, user.hashed_password):
        audit.info(f'{{"event": "login_failed", "username": "{credentials.username}"}}')
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    access_token = create_access_token(subject=user.username, role=user.role)
    refresh_token = create_refresh_token(subject=user.username, role=user.role)
    await update_last_login(user.username)

    audit.info(f'{{"event": "login_success", "username": "{user.username}", "role": "{user.role}"}}')

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        user=_to_public(user),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(payload: RefreshRequest):
    try:
        decoded = decode_token(payload.refresh_token, expected_type="refresh")
    except TokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    user = await get_user_by_username(decoded["sub"])
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User no longer valid")

    new_access = create_access_token(subject=user.username, role=user.role)
    new_refresh = create_refresh_token(subject=user.username, role=user.role)

    return TokenResponse(access_token=new_access, refresh_token=new_refresh, user=_to_public(user))


@router.post("/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
async def register_user(
    new_user: UserCreate,
    current_user: UserInDB = Depends(require_role(UserRole.ADMIN)),
):
    """
    Admin-only. SOC analysts cannot self-register or create other accounts —
    account provisioning is deliberately centralized for auditability.
    """
    if await get_user_by_username(new_user.username):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
    if await get_user_by_email(new_user.email):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    hashed = hash_password(new_user.password)
    created = await create_user(
        username=new_user.username,
        email=new_user.email,
        hashed_password=hashed,
        role=new_user.role.value,
    )

    audit.info(
        f'{{"event": "user_created", "username": "{created.username}", '
        f'"role": "{created.role}", "created_by": "{current_user.username}"}}'
    )
    return _to_public(created)


@router.get("/me", response_model=UserPublic)
async def get_me(current_user: UserInDB = Depends(get_current_user)):
    return _to_public(current_user)
