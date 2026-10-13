"""
app/api/v1/detections.py

Purpose:
    Exposes rule-based (and, from Phase 4 onward, ML) detection results
    and generated alerts to the frontend, plus a manual trigger endpoint
    for re-running detection over a recent time window (useful for demos
    and for catching threats whose signal only becomes clear across logs
    ingested in separate batches).

Connects to:
    - db/mongo.py for reading persisted detections/alerts
    - db/elastic.py::search_logs to assemble a time-window for manual runs
    - detection/engine.py::default_rule_engine for the manual trigger
    - detection/alerting.py for alert generation on manual runs
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query, status

from app.core.dependencies import get_current_user
from app.core.logging_config import get_logger
from app.db.elastic import search_logs
from app.db.mongo import list_alerts, list_detections, save_detections
from app.detection.alerting import generate_alerts
from app.detection.engine import default_rule_engine
from app.models.log_schema import NormalizedLog
from app.models.user_schema import UserInDB

router = APIRouter(prefix="/detections", tags=["Threat Detection"])
logger = get_logger(__name__)


@router.get("")
async def get_detections(
    engine: Optional[str] = Query(default=None, description="'rule' or 'ml'"),
    severity: Optional[str] = None,
    entity: Optional[str] = Query(default=None, description="Filter by entity value, e.g. an IP or username"),
    limit: int = Query(default=100, ge=1, le=500),
    current_user: UserInDB = Depends(get_current_user),
):
    results = await list_detections(engine=engine, severity=severity, entity_value=entity, limit=limit)
    for r in results:
        r["_id"] = str(r["_id"])
    return {"detections": results, "count": len(results)}


@router.get("/alerts")
async def get_alerts(
    limit: int = Query(default=100, ge=1, le=500),
    current_user: UserInDB = Depends(get_current_user),
):
    results = await list_alerts(limit=limit)
    return {"alerts": results, "count": len(results)}


@router.get("/rules")
async def list_active_rules(current_user: UserInDB = Depends(get_current_user)):
    """
    Lists the rules currently loaded in the engine along with their MITRE
    mapping and enabled state. This is a READ view of the live engine —
    distinct from api/v1/rules.py, which will (Phase 5) manage persisted
    rule *configuration*; today's rule instances use in-code defaults.
    """
    return {
        "rules": [
            {
                "rule_name": rule.rule_name,
                "description": rule.description,
                "mitre_technique": rule.mitre_technique,
                "enabled": rule.enabled,
            }
            for rule in default_rule_engine.list_rules()
        ]
    }


@router.post("/run", status_code=status.HTTP_200_OK)
async def run_detection_manually(
    minutes: int = Query(default=60, ge=1, le=1440, description="How far back to scan, in minutes"),
    current_user: UserInDB = Depends(get_current_user),
):
    """
    Manually re-runs the rule engine over the last `minutes` of ingested
    logs. Useful when a threat pattern spans multiple ingestion batches
    (each batch only sees itself; this catches what individual-batch
    detection could miss) and for demoing detection without re-uploading
    a file.
    """
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=minutes)

    search_result = await search_logs(start_time=start_time, end_time=end_time, size=2000)
    raw_logs = search_result["results"]

    logs = [NormalizedLog(**doc) for doc in raw_logs]
    detections = default_rule_engine.run(logs)

    if detections:
        await save_detections(detections)
        alerts = await generate_alerts(detections)
        try:
            from app.incidents.correlator import correlate_detections

            await correlate_detections(detections)
        except Exception as exc:
            logger.error(f"Manual detection run: incident correlation failed: {exc}")
    else:
        alerts = []

    logger.info(
        f"Manual detection run by {current_user.username}: scanned {len(logs)} logs, "
        f"{len(detections)} detection(s), {len(alerts)} alert(s)"
    )

    return {
        "logs_scanned": len(logs),
        "detections_found": len(detections),
        "alerts_generated": len(alerts),
        "detections": [d.model_dump() for d in detections],
    }
