"""
app/core/security.py

Purpose:
    All cryptographic/auth primitives live here: password hashing/verification
    and JWT access + refresh token creation/decoding. Nothing outside this
    file should touch bcrypt or jwt libraries directly — that keeps the
    crypto surface area auditable in one place, which matters for a
    security-focused project.

    Every token carries a unique `jti` claim. Refresh tokens are single-use:
    api/v1/auth.py records a refresh token's jti as revoked when it is
    exchanged or when the user logs out.

Connects to:
    - api/v1/auth.py calls create_access_token / create_refresh_token / verify_password
    - core/dependencies.py calls decode_token to authenticate incoming requests
"""
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ACCESS_TOKEN = "access"
REFRESH_TOKEN = "refresh"


class TokenError(Exception):
    """Raised when a JWT is invalid, expired, or malformed."""


def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def _create_token(subject: str, role: str, expires_delta: timedelta, token_type: str) -> str:
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "sub": subject,
        "role": role,
        "type": token_type,
        "jti": uuid4().hex,
        "iat": now,
        "exp": now + expires_delta,
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_access_token(subject: str, role: str) -> str:
    expires = timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    return _create_token(subject, role, expires, token_type=ACCESS_TOKEN)


def create_refresh_token(subject: str, role: str) -> str:
    expires = timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    return _create_token(subject, role, expires, token_type=REFRESH_TOKEN)


def decode_token(token: str, expected_type: Optional[str] = None) -> Dict[str, Any]:
    """
    Decode and validate a JWT. Raises TokenError on any failure so callers
    (FastAPI dependencies) can convert it into a clean 401 response without
    leaking library-specific exception details.
    """
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError as exc:
        raise TokenError(f"Invalid or expired token: {exc}") from exc

    if expected_type and payload.get("type") != expected_type:
        raise TokenError(f"Expected token type '{expected_type}', got '{payload.get('type')}'")
    if not payload.get("sub"):
        raise TokenError("Token has no subject")

    return payload


def token_expiry(payload: Dict[str, Any]) -> datetime:
    """Expiry of a decoded token as an aware UTC datetime."""
    return datetime.fromtimestamp(payload["exp"], tz=timezone.utc)


def issued_before(payload: Dict[str, Any], cutoff: Optional[datetime]) -> bool:
    """
    True if the token was issued before `cutoff` — used to reject tokens
    that predate a password change. A naive `cutoff` is taken as UTC.
    """
    if cutoff is None:
        return False
    if cutoff.tzinfo is None:
        cutoff = cutoff.replace(tzinfo=timezone.utc)
    return payload.get("iat", 0) < cutoff.timestamp()
