"""
app/models/user_schema.py

Purpose:
    Pydantic models for users and roles. This is the contract shared
    between core/dependencies.py (RBAC), db/mongo.py (persistence),
    and the auth / user-management API (request/response bodies).

Connects to:
    - db/mongo.py: reads/writes documents shaped like UserInDB
    - core/dependencies.py: get_current_user returns a UserInDB
    - api/v1/auth.py: login, refresh, logout, change-password
    - api/v1/users.py: UserCreate (input) -> UserInDB (stored) -> UserPublic (output)
"""
import re
from datetime import datetime
from enum import Enum
from typing import Annotated, Optional

from pydantic import AfterValidator, BaseModel, EmailStr, Field


class UserRole(str, Enum):
    ADMIN = "admin"
    SOC_ANALYST = "soc_analyst"


def _validate_password_strength(password: str) -> str:
    if not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
        raise ValueError("Password must contain at least one letter and one digit")
    return password


#: Plaintext password as submitted by a client; hashed before storage.
Password = Annotated[str, Field(min_length=8, max_length=128), AfterValidator(_validate_password_strength)]


class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    role: UserRole = UserRole.SOC_ANALYST


class UserCreate(UserBase):
    """Input schema for creating a user (admin-only endpoint)."""
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    password: Password


class UserUpdate(BaseModel):
    """Admin-editable account fields. Omitted fields are left unchanged."""
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


class UserInDB(UserBase):
    """Internal representation, includes the hashed password. Never returned by the API."""
    id: str = Field(..., alias="_id")
    hashed_password: str
    is_active: bool = True
    created_at: datetime
    last_login: Optional[datetime] = None
    #: Tokens issued before this moment are rejected (set on password change/reset).
    token_valid_after: Optional[datetime] = None

    model_config = {"populate_by_name": True}

    def to_public(self) -> "UserPublic":
        return UserPublic(
            id=self.id,
            username=self.username,
            email=self.email,
            role=self.role,
            is_active=self.is_active,
            created_at=self.created_at,
            last_login=self.last_login,
        )


class UserPublic(UserBase):
    """Safe representation returned by the API — no password hash, ever."""
    id: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None


class LoginRequest(BaseModel):
    username: str = Field(..., max_length=50)
    password: str = Field(..., max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserPublic


class RefreshRequest(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., max_length=128)
    new_password: Password


class ResetPasswordRequest(BaseModel):
    new_password: Password
