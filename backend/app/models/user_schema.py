"""
app/models/user_schema.py

Purpose:
    Pydantic models for users and roles. This is the contract shared
    between core/dependencies.py (RBAC), db/mongo.py (persistence),
    and api/v1/auth.py (request/response bodies).

Connects to:
    - db/mongo.py: reads/writes documents shaped like UserInDB
    - core/dependencies.py: get_current_user returns a UserInDB
    - api/v1/auth.py: UserCreate (input) -> UserInDB (stored) -> UserPublic (output)
"""
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class UserRole(str, Enum):
    ADMIN = "admin"
    SOC_ANALYST = "soc_analyst"


class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    role: UserRole = UserRole.SOC_ANALYST


class UserCreate(UserBase):
    """Input schema for user registration (admin-only endpoint)."""
    password: str = Field(..., min_length=8, description="Plaintext password, hashed before storage")


class UserInDB(UserBase):
    """Internal representation, includes the hashed password. Never returned by the API."""
    id: str = Field(..., alias="_id")
    hashed_password: str
    is_active: bool = True
    created_at: datetime
    last_login: Optional[datetime] = None

    model_config = {"populate_by_name": True}


class UserPublic(UserBase):
    """Safe representation returned by the API — no password hash, ever."""
    id: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserPublic


class RefreshRequest(BaseModel):
    refresh_token: str
