"""
app/api/v1/detections.py

Purpose:
    Exposes stored detections (rule-based and ML) to the frontend, plus a
    manual trigger for re-running the rule engine over recently ingested
    logs — useful for demos and after changing a rule's settings.

Connects to:
    - db/mongo.py for reading stored detections
    - detection/service.py for the manual scan
"""
from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.core.dependencies import get_current_user
from app.core.logging_config import get_logger
from app.db.mongo import list_detections
from app.detection import service as detection_service
from app.models.detection_schema import DetectionEngine
from app.models.log_schema import Severity
from app.models.user_schema import UserInDB

router = APIRouter(prefix="/detections", tags=["Threat Detection"])
logger = get_logger(__name__)


@router.get("")
async def get_detections(
    engine: Optional[DetectionEngine] = None,
    severity: Optional[Severity] = None,
    entity: Optional[str] = Query(default=None, description="Filter by entity value, e.g. an IP or username"),
    limit: int = Query(default=100, ge=1, le=500),
    current_user: UserInDB = Depends(get_current_user),
):
    results = await list_detections(
        engine=engine.value if engine else None,
        severity=severity.value if severity else None,
        entity_value=entity,
        limit=limit,
    )
    return {"detections": results, "count": len(results)}


@router.post("/run")
async def run_detection_manually(
    minutes: int = Query(default=60, ge=1, le=10_080, description="Scan logs ingested in the last N minutes"),
    current_user: UserInDB = Depends(get_current_user),
):
    """
    Re-runs the rule engine over logs ingested in the last `minutes`.
    Findings that are already stored are not duplicated, so this is safe
    to run repeatedly.
    """
    outcome = await detection_service.scan_recent_logs(DetectionEngine.RULE, minutes)
    logger.info(
        f"Manual rule scan by {current_user.username}: {outcome.logs_scanned} logs, "
        f"{len(outcome.detections)} new detection(s), {outcome.alerts_generated} alert(s)"
    )
    return detection_service.summarize(outcome)
