"""
app/db/mongo.py

Purpose:
    Single place that owns the MongoDB connection (via Motor, the async
    driver) and exposes small repository functions for each collection.
    Nothing else in the codebase should import `motor` directly — routers
    and services call these functions instead. This is the seam that lets
    you swap Mongo for something else later without touching business logic.

Collections:
    - users
    - incidents
    - detection_rules   (rule engine configuration, toggled from the UI later)
    - system_config     (alert channel settings, ML thresholds, etc.)

Connects to:
    - core/dependencies.py -> get_user_by_username
    - api/v1/auth.py -> create_user, update_last_login
    - incidents/service.py -> incident CRUD (added in Phase 7)
"""
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, List, Optional

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo import ReturnDocument

from app.core.config import settings
from app.core.logging_config import get_logger
from app.models.user_schema import UserInDB

if TYPE_CHECKING:
    from app.models.alert_schema import AlertInDB
    from app.models.detection_schema import DetectionEvent
    from app.models.log_schema import IngestionBatch

logger = get_logger(__name__)

_client: Optional[AsyncIOMotorClient] = None
_db: Optional[AsyncIOMotorDatabase] = None


def connect_to_mongo() -> None:
    global _client, _db
    _client = AsyncIOMotorClient(settings.MONGO_URI)
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


async def ensure_indexes() -> None:
    """
    Create indexes required for correctness and performance. Called once
    at startup (idempotent — safe to call every boot).
    """
    db = get_db()
    await db.users.create_index("username", unique=True)
    await db.users.create_index("email", unique=True)
    await db.incidents.create_index("incident_ref", unique=True)
    await db.incidents.create_index("status")
    await db.incidents.create_index("created_at")
    await db.incidents.create_index([("entity.value", 1), ("status", 1)])
    await db.incidents.create_index([("entity.value", 1), ("correlation_key", 1), ("status", 1)])
    await db.detection_rules.create_index("rule_name", unique=True)
    await db.ingestion_batches.create_index("created_at")
    await db.ingestion_batches.create_index("batch_id", unique=True)
    await db.detections.create_index("timestamp")
    await db.detections.create_index("engine")
    await db.detections.create_index("entity.value")
    await db.alerts.create_index("created_at")
    await db.alerts.create_index("severity")
    logger.info("MongoDB indexes ensured")


# --------------------------------------------------------------------------
# User repository
# --------------------------------------------------------------------------

def _doc_to_user(doc: dict) -> UserInDB:
    doc["_id"] = str(doc["_id"])
    return UserInDB(**doc)


async def get_user_by_username(username: str) -> Optional[UserInDB]:
    db = get_db()
    doc = await db.users.find_one({"username": username})
    return _doc_to_user(doc) if doc else None


async def get_user_by_email(email: str) -> Optional[UserInDB]:
    db = get_db()
    doc = await db.users.find_one({"email": email})
    return _doc_to_user(doc) if doc else None


async def create_user(username: str, email: str, hashed_password: str, role: str) -> UserInDB:
    db = get_db()
    doc = {
        "username": username,
        "email": email,
        "hashed_password": hashed_password,
        "role": role,
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
        "last_login": None,
    }
    result = await db.users.insert_one(doc)
    doc["_id"] = str(result.inserted_id)
    return UserInDB(**doc)


async def update_last_login(username: str) -> None:
    db = get_db()
    await db.users.update_one({"username": username}, {"$set": {"last_login": datetime.now(timezone.utc)}})


async def next_incident_sequence() -> int:
    """
    Atomic counter for human-readable incident IDs (INC-1001, INC-1002, ...).
    Uses a dedicated `counters` collection with findAndModify semantics so
    concurrent incident creation never collides.
    """
    db = get_db()
    result = await db.counters.find_one_and_update(
        {"_id": "incident_seq"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return result["seq"] + 1000  # first incident is INC-1001


# --------------------------------------------------------------------------
# Incident repository (Phase 7)
# --------------------------------------------------------------------------

async def insert_incident(doc: dict) -> None:
    db = get_db()
    await db.incidents.insert_one(doc)


async def get_incident_by_ref(incident_ref: str) -> Optional[dict]:
    db = get_db()
    return await db.incidents.find_one({"incident_ref": incident_ref})


async def find_open_incident(
    entity_value: str,
    correlation_key: str,
    statuses: List[str],
) -> Optional[dict]:
    db = get_db()
    return await db.incidents.find_one(
        {
            "entity.value": entity_value,
            "correlation_key": correlation_key,
            "status": {"$in": statuses},
        },
        sort=[("created_at", -1)],
    )


async def update_incident_raw(incident_ref: str, update: dict) -> None:
    db = get_db()
    await db.incidents.update_one({"incident_ref": incident_ref}, update)


async def list_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assigned_to: Optional[str] = None,
    limit: int = 100,
) -> List[dict]:
    db = get_db()
    query: dict = {}
    if status:
        query["status"] = status
    if severity:
        query["severity"] = severity
    if assigned_to:
        query["assigned_to"] = assigned_to
    cursor = db.incidents.find(query).sort("created_at", -1).limit(limit)
    return [doc async for doc in cursor]


async def count_incidents(statuses: Optional[List[str]] = None) -> int:
    db = get_db()
    query: dict = {}
    if statuses:
        query["status"] = {"$in": statuses}
    return await db.incidents.count_documents(query)


async def count_detections(engine: Optional[str] = None, severity: Optional[str] = None) -> int:
    db = get_db()
    query: dict = {}
    if engine:
        query["engine"] = engine
    if severity:
        query["severity"] = severity
    return await db.detections.count_documents(query)


async def count_alerts(severity: Optional[str] = None) -> int:
    db = get_db()
    query: dict = {}
    if severity:
        query["severity"] = severity
    return await db.alerts.count_documents(query)


async def aggregate_threat_types(limit: int = 10) -> List[dict]:
    """Top threat types from detections (rule_name or 'ml_anomaly')."""
    db = get_db()
    pipeline = [
        {
            "$group": {
                "_id": {
                    "$ifNull": ["$rule_name", {"$cond": [{"$eq": ["$engine", "ml"]}, "ml_anomaly", "unknown"]}]
                },
                "count": {"$sum": 1},
                "mitre": {"$first": "$mitre_technique"},
            }
        },
        {"$sort": {"count": -1}},
        {"$limit": limit},
    ]
    results = []
    async for doc in db.detections.aggregate(pipeline):
        key = doc["_id"] or "unknown"
        label = "AI Anomaly" if key == "ml_anomaly" else str(key).replace("_", " ").title()
        results.append(
            {
                "threat_type": label,
                "count": doc["count"],
                "mitre_technique": doc.get("mitre") or "N/A",
            }
        )
    return results


async def aggregate_detection_timeline(hours: int = 24) -> List[dict]:
    """Hourly detection counts for the threat timeline chart."""
    db = get_db()
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    pipeline = [
        {"$match": {"timestamp": {"$gte": since}}},
        {
            "$group": {
                "_id": {
                    "$dateToString": {"format": "%Y-%m-%dT%H:00:00Z", "date": "$timestamp"}
                },
                "count": {"$sum": 1},
            }
        },
        {"$sort": {"_id": 1}},
    ]
    return [{"timestamp": doc["_id"], "count": doc["count"]} async for doc in db.detections.aggregate(pipeline)]


# --------------------------------------------------------------------------
# Detection rule config repository (Phase 5)
# --------------------------------------------------------------------------

async def get_rule_configs() -> List[dict]:
    db = get_db()
    return [doc async for doc in db.detection_rules.find()]


async def upsert_rule_config(rule_name: str, enabled: bool, config: Optional[dict] = None) -> dict:
    db = get_db()
    update: dict = {
        "rule_name": rule_name,
        "enabled": enabled,
        "updated_at": datetime.now(timezone.utc),
    }
    if config is not None:
        update["config"] = config
    await db.detection_rules.update_one(
        {"rule_name": rule_name},
        {"$set": update},
        upsert=True,
    )
    return await db.detection_rules.find_one({"rule_name": rule_name})


# --------------------------------------------------------------------------
# Ingestion batch repository (Phase 2)
# --------------------------------------------------------------------------

async def save_ingestion_batch(batch: "IngestionBatch") -> None:
    """Persist ingestion batch metadata for audit/traceability."""
    db = get_db()
    doc = batch.model_dump()
    await db.ingestion_batches.insert_one(doc)


async def list_ingestion_batches(limit: int = 50) -> list:
    db = get_db()
    cursor = db.ingestion_batches.find().sort("created_at", -1).limit(limit)
    return [doc async for doc in cursor]


# --------------------------------------------------------------------------
# Detection repository (Phase 3)
# --------------------------------------------------------------------------

async def save_detection(detection: "DetectionEvent") -> None:
    """Persist a single DetectionEvent (rule or ML) into the `detections` collection."""
    db = get_db()
    await db.detections.insert_one(detection.model_dump())


async def save_detections(detections: list) -> None:
    """Bulk-insert DetectionEvents. No-ops on an empty list."""
    if not detections:
        return
    db = get_db()
    await db.detections.insert_many([d.model_dump() for d in detections])


async def list_detections(
    engine: Optional[str] = None,
    severity: Optional[str] = None,
    entity_value: Optional[str] = None,
    limit: int = 100,
) -> list:
    db = get_db()
    query: dict = {}
    if engine:
        query["engine"] = engine
    if severity:
        query["severity"] = severity
    if entity_value:
        query["entity.value"] = entity_value

    cursor = db.detections.find(query).sort("timestamp", -1).limit(limit)
    return [doc async for doc in cursor]


# --------------------------------------------------------------------------
# Alert repository (Phase 3)
# --------------------------------------------------------------------------

async def save_alert(alert: "AlertInDB") -> None:
    db = get_db()
    doc = alert.model_dump(by_alias=True, exclude={"id"})
    await db.alerts.insert_one(doc)


async def list_alerts(limit: int = 100) -> list:
    db = get_db()
    cursor = db.alerts.find().sort("created_at", -1).limit(limit)
    results = []
    async for doc in cursor:
        doc["_id"] = str(doc["_id"])
        results.append(doc)
    return results
