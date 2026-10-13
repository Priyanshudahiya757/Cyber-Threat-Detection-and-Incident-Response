"""
app/db/mongo.py

Purpose:
    Single place that owns the MongoDB connection (via Motor, the async
    driver) and exposes small repository functions for each collection.
    Nothing else in the codebase should import `motor` directly — routers
    and services call these functions instead. This is the seam that lets
    you swap Mongo for something else later without touching business logic.

Collections:
    - users              accounts and roles
    - login_attempts     failed-login counters for brute-force lockout
    - revoked_tokens     refresh tokens that were used or logged out (TTL)
    - ingestion_batches  audit trail of every upload/ingest request
    - detections         rule and ML findings (unique by fingerprint)
    - alerts             high-severity findings surfaced to analysts
    - incidents          correlated detections with analyst workflow
    - detection_rules    persisted rule enable/disable state and thresholds
    - counters           atomic sequence for incident references
"""
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from bson import ObjectId
from bson.errors import InvalidId
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ReturnDocument

from app.core.config import settings
from app.core.logging_config import get_logger
from app.models.detection_schema import ML_THREAT_TYPE, threat_label
from app.models.user_schema import UserInDB

if TYPE_CHECKING:
    from app.models.alert_schema import Alert
    from app.models.detection_schema import DetectionEvent
    from app.models.log_schema import IngestionBatch

logger = get_logger(__name__)

_client: Optional[AsyncIOMotorClient] = None
_db: Optional[AsyncIOMotorDatabase] = None


def connect_to_mongo() -> None:
    global _client, _db
    # tz_aware so datetimes come back as UTC-aware and serialize with an
    # explicit offset; clients would otherwise read them as local time.
    _client = AsyncIOMotorClient(settings.MONGO_URI, tz_aware=True)
    _db = _client[settings.MONGO_DB_NAME]
    logger.info(f"Connected to MongoDB database '{settings.MONGO_DB_NAME}'")


def close_mongo_connection() -> None:
    global _client
    if _client:
        _client.close()
        logger.info("MongoDB connection closed")


def get_db() -> AsyncIOMotorDatabase:
    if _db is None:
        raise RuntimeError("MongoDB not initialized. Call connect_to_mongo() at startup.")
    return _db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: datetime) -> datetime:
    """Normalize a datetime read from Mongo, which may be naive UTC."""
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _stringify_id(doc: dict) -> dict:
    doc["_id"] = str(doc["_id"])
    return doc


async def ensure_indexes() -> None:
    """
    Create indexes required for correctness and performance. Called once
    at startup (idempotent — safe to call every boot).
    """
    db = get_db()
    await db.users.create_index("username", unique=True)
    await db.users.create_index("email", unique=True)
    await db.revoked_tokens.create_index("expires_at", expireAfterSeconds=0)
    await db.incidents.create_index("incident_ref", unique=True)
    await db.incidents.create_index("status")
    await db.incidents.create_index("created_at")
    await db.incidents.create_index([("entity.value", 1), ("correlation_key", 1), ("status", 1)])
    await db.detection_rules.create_index("rule_name", unique=True)
    await db.ingestion_batches.create_index("created_at")
    await db.ingestion_batches.create_index("batch_id", unique=True)
    await db.detections.create_index("timestamp")
    await db.detections.create_index("engine")
    await db.detections.create_index("entity.value")
    await db.detections.create_index("fingerprint", unique=True, sparse=True)
    await db.alerts.create_index("created_at")
    await db.alerts.create_index([("entity.value", 1), ("threat_type", 1), ("created_at", -1)])
    logger.info("MongoDB indexes ensured")


# --------------------------------------------------------------------------
# User repository
# --------------------------------------------------------------------------

def _doc_to_user(doc: dict) -> UserInDB:
    return UserInDB(**_stringify_id(doc))


async def get_user_by_username(username: str) -> Optional[UserInDB]:
    doc = await get_db().users.find_one({"username": username})
    return _doc_to_user(doc) if doc else None


async def get_user_by_email(email: str) -> Optional[UserInDB]:
    doc = await get_db().users.find_one({"email": email})
    return _doc_to_user(doc) if doc else None


async def list_users() -> List[UserInDB]:
    cursor = get_db().users.find().sort("username", 1)
    return [_doc_to_user(doc) async for doc in cursor]


async def create_user(username: str, email: str, hashed_password: str, role: str) -> UserInDB:
    doc = {
        "username": username,
        "email": email,
        "hashed_password": hashed_password,
        "role": role,
        "is_active": True,
        "created_at": utcnow(),
        "last_login": None,
        "token_valid_after": None,
    }
    result = await get_db().users.insert_one(doc)
    doc["_id"] = str(result.inserted_id)
    return UserInDB(**doc)


async def update_user(username: str, fields: Dict[str, Any]) -> Optional[UserInDB]:
    doc = await get_db().users.find_one_and_update(
        {"username": username},
        {"$set": fields},
        return_document=ReturnDocument.AFTER,
    )
    return _doc_to_user(doc) if doc else None


async def set_user_password(username: str, hashed_password: str) -> None:
    """
    Store a new password hash and invalidate every token issued before now.
    The cut-off is floored to the second because a JWT's `iat` claim has
    one-second resolution.
    """
    await get_db().users.update_one(
        {"username": username},
        {"$set": {"hashed_password": hashed_password, "token_valid_after": utcnow().replace(microsecond=0)}},
    )


async def update_last_login(username: str) -> None:
    await get_db().users.update_one({"username": username}, {"$set": {"last_login": utcnow()}})


# --------------------------------------------------------------------------
# Login attempt + token revocation repository
# --------------------------------------------------------------------------

async def get_login_attempts(key: str) -> Optional[dict]:
    return await get_db().login_attempts.find_one({"_id": key})


async def save_login_attempts(key: str, count: int, window_started: datetime, locked_until: Optional[datetime]) -> None:
    await get_db().login_attempts.update_one(
        {"_id": key},
        {"$set": {"count": count, "window_started": window_started, "locked_until": locked_until}},
        upsert=True,
    )


async def clear_login_attempts(key: str) -> None:
    await get_db().login_attempts.delete_one({"_id": key})


async def revoke_token(jti: str, expires_at: datetime) -> None:
    """Record a token id as unusable. The TTL index removes it once the token would have expired anyway."""
    await get_db().revoked_tokens.update_one(
        {"_id": jti}, {"$set": {"expires_at": expires_at}}, upsert=True
    )


async def is_token_revoked(jti: str) -> bool:
    return await get_db().revoked_tokens.find_one({"_id": jti}) is not None


# --------------------------------------------------------------------------
# Incident repository
# --------------------------------------------------------------------------

async def next_incident_sequence() -> int:
    """
    Atomic counter for human-readable incident IDs (INC-1001, INC-1002, ...).
    Uses a dedicated `counters` collection with findAndModify semantics so
    concurrent incident creation never collides.
    """
    result = await get_db().counters.find_one_and_update(
        {"_id": "incident_seq"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return result["seq"] + 1000  # first incident is INC-1001


async def insert_incident(doc: dict) -> None:
    await get_db().incidents.insert_one(doc)


async def get_incident_by_ref(incident_ref: str) -> Optional[dict]:
    return await get_db().incidents.find_one({"incident_ref": incident_ref})


async def find_open_incident(
    entity_value: str,
    correlation_key: str,
    statuses: List[str],
) -> Optional[dict]:
    return await get_db().incidents.find_one(
        {
            "entity.value": entity_value,
            "correlation_key": correlation_key,
            "status": {"$in": statuses},
        },
        sort=[("created_at", -1)],
    )


async def update_incident(incident_ref: str, update: dict) -> Optional[dict]:
    """Apply a raw Mongo update document and return the updated incident."""
    return await get_db().incidents.find_one_and_update(
        {"incident_ref": incident_ref},
        update,
        return_document=ReturnDocument.AFTER,
    )


async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assigned_to: Optional[str] = None,
    limit: int = 100,
) -> List[dict]:
    query: dict = {}
    if status:
        query["status"] = status
    if severity:
        query["severity"] = severity
    if assigned_to:
        query["assigned_to"] = assigned_to
    cursor = get_db().incidents.find(query).sort("created_at", -1).limit(limit)
    return [doc async for doc in cursor]


async def count_incidents(statuses: Optional[List[str]] = None) -> int:
    query: dict = {}
    if statuses:
        query["status"] = {"$in": statuses}
    return await get_db().incidents.count_documents(query)


# --------------------------------------------------------------------------
# Detection rule config repository
# --------------------------------------------------------------------------

async def get_rule_configs() -> List[dict]:
    return [doc async for doc in get_db().detection_rules.find()]


async def upsert_rule_config(rule_name: str, enabled: bool, config: dict) -> None:
    await get_db().detection_rules.update_one(
        {"rule_name": rule_name},
        {"$set": {"rule_name": rule_name, "enabled": enabled, "config": config, "updated_at": utcnow()}},
        upsert=True,
    )


# --------------------------------------------------------------------------
# Ingestion batch repository
# --------------------------------------------------------------------------

async def save_ingestion_batch(batch: "IngestionBatch") -> None:
    """Persist ingestion batch metadata for audit/traceability."""
    await get_db().ingestion_batches.insert_one(batch.model_dump())


async def list_ingestion_batches(limit: int = 50) -> List[dict]:
    cursor = get_db().ingestion_batches.find().sort("created_at", -1).limit(limit)
    return [_stringify_id(doc) async for doc in cursor]


# --------------------------------------------------------------------------
# Detection repository
# --------------------------------------------------------------------------

async def save_detections(detections: List["DetectionEvent"]) -> List["DetectionEvent"]:
    """
    Insert the detections that are not stored yet and return exactly those.
    A detection is "already stored" when one with the same fingerprint
    exists, which makes re-running detection over the same logs a no-op.
    """
    unique = list({d.fingerprint: d for d in detections}.values())
    if not unique:
        return []

    db = get_db()
    cursor = db.detections.find({"fingerprint": {"$in": [d.fingerprint for d in unique]}}, {"fingerprint": 1})
    known = {doc["fingerprint"] async for doc in cursor}

    new = [d for d in unique if d.fingerprint not in known]
    if new:
        await db.detections.insert_many([d.model_dump() for d in new])
    return new


async def list_detections(
    engine: Optional[str] = None,
    severity: Optional[str] = None,
    entity_value: Optional[str] = None,
    limit: int = 100,
) -> List[dict]:
    query: dict = {}
    if engine:
        query["engine"] = engine
    if severity:
        query["severity"] = severity
    if entity_value:
        query["entity.value"] = entity_value

    cursor = get_db().detections.find(query).sort("timestamp", -1).limit(limit)
    return [_stringify_id(doc) async for doc in cursor]


async def count_detections(engine: Optional[str] = None) -> int:
    query: dict = {}
    if engine:
        query["engine"] = engine
    return await get_db().detections.count_documents(query)


async def aggregate_threat_types(limit: int = 10) -> List[dict]:
    """Top threat types from detections (rule_name, or ML_THREAT_TYPE for the ML engine)."""
    pipeline = [
        {
            "$group": {
                "_id": {"$ifNull": ["$rule_name", ML_THREAT_TYPE]},
                "count": {"$sum": 1},
                "mitre": {"$first": "$mitre_technique"},
            }
        },
        {"$sort": {"count": -1}},
        {"$limit": limit},
    ]
    results = []
    async for doc in get_db().detections.aggregate(pipeline):
        results.append(
            {
                "threat_type": threat_label(doc["_id"]),
                "count": doc["count"],
                "mitre_technique": doc.get("mitre") or "N/A",
            }
        )
    return results


async def aggregate_detection_timeline(hours: int = 24) -> List[dict]:
    """
    Detection counts for each of the last `hours` hours, oldest first.
    Hours without detections are included with a count of 0 so the chart
    shows a continuous timeline rather than isolated points.
    """
    hour_format = "%Y-%m-%dT%H:00:00Z"
    current_hour = utcnow().replace(minute=0, second=0, microsecond=0)
    buckets = [current_hour - timedelta(hours=offset) for offset in range(hours - 1, -1, -1)]

    pipeline = [
        {"$match": {"timestamp": {"$gte": buckets[0]}}},
        {
            "$group": {
                "_id": {"$dateToString": {"format": hour_format, "date": "$timestamp"}},
                "count": {"$sum": 1},
            }
        },
    ]
    counts = {doc["_id"]: doc["count"] async for doc in get_db().detections.aggregate(pipeline)}
    return [
        {"timestamp": bucket.strftime(hour_format), "count": counts.get(bucket.strftime(hour_format), 0)}
        for bucket in buckets
    ]


# --------------------------------------------------------------------------
# Alert repository
# --------------------------------------------------------------------------

def _alert_object_id(alert_id: str) -> Optional[ObjectId]:
    try:
        return ObjectId(alert_id)
    except (InvalidId, TypeError):
        return None


async def save_alert(alert: "Alert") -> str:
    """Insert an alert and return its new id (also set on the passed-in model)."""
    result = await get_db().alerts.insert_one(alert.model_dump(exclude={"id"}))
    alert.id = str(result.inserted_id)
    return alert.id


async def has_recent_alert(entity_value: str, threat_type: str, since: datetime) -> bool:
    doc = await get_db().alerts.find_one(
        {"entity.value": entity_value, "threat_type": threat_type, "created_at": {"$gte": since}},
        {"_id": 1},
    )
    return doc is not None


async def set_alert_dispatched_channels(alert_id: str, channels: List[str]) -> None:
    oid = _alert_object_id(alert_id)
    if oid is not None:
        await get_db().alerts.update_one({"_id": oid}, {"$set": {"dispatched_channels": channels}})


async def acknowledge_alert(alert_id: str, username: str) -> Optional[dict]:
    oid = _alert_object_id(alert_id)
    if oid is None:
        return None
    doc = await get_db().alerts.find_one_and_update(
        {"_id": oid},
        {"$set": {"acknowledged": True, "acknowledged_by": username, "acknowledged_at": utcnow()}},
        return_document=ReturnDocument.AFTER,
    )
    return _stringify_id(doc) if doc else None


def _alert_query(severity: Optional[str], acknowledged: Optional[bool]) -> dict:
    query: dict = {}
    if severity:
        query["severity"] = severity
    if acknowledged is True:
        query["acknowledged"] = True
    elif acknowledged is False:
        # `$ne` also matches alerts stored before the field existed.
        query["acknowledged"] = {"$ne": True}
    return query


async def list_alerts(
    limit: int = 100, severity: Optional[str] = None, acknowledged: Optional[bool] = None
) -> List[dict]:
    cursor = get_db().alerts.find(_alert_query(severity, acknowledged)).sort("created_at", -1).limit(limit)
    return [_stringify_id(doc) async for doc in cursor]


async def count_alerts(severity: Optional[str] = None, acknowledged: Optional[bool] = None) -> int:
    return await get_db().alerts.count_documents(_alert_query(severity, acknowledged))
