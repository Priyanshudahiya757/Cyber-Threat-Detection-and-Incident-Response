"""
app/core/login_guard.py

Purpose:
    Brute-force protection for the login endpoint. Failed attempts are
    counted per username inside a rolling window; once
    LOGIN_MAX_FAILED_ATTEMPTS is reached the account is locked for
    LOGIN_LOCKOUT_MINUTES. Counters live in MongoDB so the limit holds
    across API workers and restarts.

    Attempts are tracked for unknown usernames too, so the endpoint's
    behaviour never reveals whether an account exists.

Connects to:
    - api/v1/auth.py calls these around credential verification
    - db/mongo.py stores the counters in `login_attempts`
"""
from datetime import datetime, timedelta
from typing import Optional

from app.core.config import settings
from app.db import mongo


def _key(username: str) -> str:
    return username.strip().lower()


async def locked_until(username: str) -> Optional[datetime]:
    """Return when the lock on `username` expires, or None if it is not locked."""
    doc = await mongo.get_login_attempts(_key(username))
    if not doc or not doc.get("locked_until"):
        return None
    until = mongo.as_utc(doc["locked_until"])
    return until if until > mongo.utcnow() else None


async def register_failure(username: str) -> Optional[datetime]:
    """Count one failed attempt. Returns the lock expiry if this attempt triggered a lockout."""
    now = mongo.utcnow()
    window = timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
    doc = await mongo.get_login_attempts(_key(username))

    if doc and mongo.as_utc(doc["window_started"]) + window > now:
        count, window_started = doc["count"] + 1, mongo.as_utc(doc["window_started"])
    else:
        count, window_started = 1, now

    lock = now + window if count >= settings.LOGIN_MAX_FAILED_ATTEMPTS else None
    await mongo.save_login_attempts(_key(username), count, window_started, lock)
    return lock


async def register_success(username: str) -> None:
    await mongo.clear_login_attempts(_key(username))
