"""
app/api/v1/users.py

Purpose:
    Account administration. Analysts cannot self-register — an admin
    creates accounts, changes roles, disables accounts and resets
    passwords, and every such action is written to the audit log.
    Accounts are disabled rather than deleted so incident timelines and
    audit records keep pointing at a real user.

    Guard rail: an admin cannot disable or demote their own account.
    Since only an active admin can make these changes at all, that one
    rule guarantees the platform always keeps at least one administrator.

Connects to:
    - db/mongo.py user repository
    - core/dependencies.py for role checks
    - Mounted in main.py under /api/v1/users
"""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status

from app.core.dependencies import get_current_user, require_admin
from app.core.logging_config import audit_event
from app.core.security import hash_password
from app.db import mongo
from app.models.user_schema import (
    ResetPasswordRequest,
    UserCreate,
    UserInDB,
    UserPublic,
    UserRole,
    UserUpdate,
)

router = APIRouter(prefix="/users", tags=["User Management"])


async def _get_or_404(username: str) -> UserInDB:
    user = await mongo.get_user_by_username(username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{username}' not found")
    return user


@router.get("", response_model=List[UserPublic])
async def list_users(admin: UserInDB = Depends(require_admin)):
    return [user.to_public() for user in await mongo.list_users()]


@router.get("/assignable", response_model=List[str])
async def list_assignable_usernames(current_user: UserInDB = Depends(get_current_user)):
    """Usernames an incident can be assigned to: every active account."""
    return [user.username for user in await mongo.list_users() if user.is_active]


@router.post("", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
async def create_user(new_user: UserCreate, admin: UserInDB = Depends(require_admin)):
    if await mongo.get_user_by_username(new_user.username):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
    if await mongo.get_user_by_email(new_user.email):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    created = await mongo.create_user(
        username=new_user.username,
        email=new_user.email,
        hashed_password=hash_password(new_user.password),
        role=new_user.role.value,
    )
    audit_event("user_created", username=created.username, role=created.role.value, actor=admin.username)
    return created.to_public()


@router.patch("/{username}", response_model=UserPublic)
async def update_user(username: str, body: UserUpdate, admin: UserInDB = Depends(require_admin)):
    target = await _get_or_404(username)

    changes = body.model_dump(exclude_unset=True, exclude_none=True, mode="json")
    if not changes:
        return target.to_public()

    loses_admin = changes.get("role", UserRole.ADMIN.value) != UserRole.ADMIN.value or changes.get("is_active") is False
    if loses_admin and target.username == admin.username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot disable or demote your own account",
        )

    updated = await mongo.update_user(username, changes)
    audit_event("user_updated", username=username, changes=changes, actor=admin.username)
    return updated.to_public()


@router.post("/{username}/reset-password", status_code=status.HTTP_204_NO_CONTENT)
async def reset_password(username: str, body: ResetPasswordRequest, admin: UserInDB = Depends(require_admin)):
    """Set a new password for another account and sign out all of its sessions."""
    target = await _get_or_404(username)
    await mongo.set_user_password(target.username, hash_password(body.new_password))
    audit_event("password_reset", username=target.username, actor=admin.username)
