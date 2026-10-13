"""
app/api/v1/alerts.py

Purpose:
    Alert endpoints: list alerts, acknowledge one, see which external
    delivery channels are configured, and send a test alert through them.

Connects to:
    - db/mongo.py alert repository
    - alerts/dispatcher.py for channel status and test delivery
    - Mounted in main.py under /api/v1/alerts
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.alerts.dispatcher import channel_status, dispatch_alert
from app.core.dependencies import get_current_user, require_admin
from app.core.logging_config import audit_event
from app.db import mongo
from app.models.alert_schema import Alert
from app.models.detection_schema import Entity, EntityType
from app.models.log_schema import Severity
from app.models.user_schema import UserInDB

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("")
async def list_alerts(
    severity: Optional[Severity] = None,
    acknowledged: Optional[bool] = Query(default=None, description="Filter by acknowledgement state"),
    limit: int = Query(default=100, ge=1, le=500),
    current_user: UserInDB = Depends(get_current_user),
):
    severity_value = severity.value if severity else None
    alerts = await mongo.list_alerts(limit=limit, severity=severity_value, acknowledged=acknowledged)
    return {
        "alerts": alerts,
        "count": len(alerts),
        "unacknowledged_total": await mongo.count_alerts(acknowledged=False),
    }


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, current_user: UserInDB = Depends(get_current_user)):
    alert = await mongo.acknowledge_alert(alert_id, current_user.username)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    audit_event("alert_acknowledged", alert_id=alert_id, actor=current_user.username)
    return alert


@router.get("/channels")
async def list_channels(current_user: UserInDB = Depends(get_current_user)):
    """Which external delivery channels have credentials configured."""
    return {"channels": [result.model_dump(include={"channel", "configured"}) for result in channel_status()]}


@router.post("/test")
async def send_test_alert(admin: UserInDB = Depends(require_admin)):
    """
    Deliver a clearly-labelled test alert through every configured channel
    and report the outcome per channel. Nothing is stored.
    """
    test_alert = Alert(
        title="Test alert — delivery check",
        threat_type="test",
        severity=Severity.LOW,
        entity=Entity(type=EntityType.HOST, value="siem-dashboard"),
        detection_id="test",
        description=f"This is a test alert sent by {admin.username}. No action is required.",
    )
    results = await dispatch_alert(test_alert)
    audit_event("alert_test_sent", actor=admin.username)
    return {"results": [result.model_dump() for result in results]}
