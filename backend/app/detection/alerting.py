"""
app/detection/alerting.py

Purpose:
    Turns high-severity DetectionEvents into persisted Alert records and
    hands each one to alerts/dispatcher.py for external delivery.

    An alert is suppressed when one for the same entity and threat type
    was already raised within ALERT_COOLDOWN_MINUTES — an ongoing attack
    produces a detection per ingested batch, and analysts should be
    interrupted once, not once per batch. The detection itself is still
    stored and still updates its incident.

Connects to:
    - detection/service.py calls generate_alerts() for newly stored detections
    - db/mongo.py persists alerts
    - alerts/dispatcher.py delivers them to email / Discord / Telegram
"""
from datetime import timedelta
from typing import List

from app.alerts.dispatcher import dispatch_in_background
from app.core.config import settings
from app.core.logging_config import audit_event, get_logger
from app.db.mongo import has_recent_alert, save_alert, utcnow
from app.models.alert_schema import Alert
from app.models.detection_schema import DetectionEvent, threat_label
from app.models.log_schema import Severity

logger = get_logger(__name__)

#: Only detections at or above this severity generate an alert. Below this,
#: a detection is still stored and visible in the dashboard, but doesn't
#: warrant interrupting an analyst.
ALERT_SEVERITIES = {Severity.HIGH.value, Severity.CRITICAL.value}


def _build_alert(detection: DetectionEvent) -> Alert:
    return Alert(
        title=f"{threat_label(detection.threat_type)} — {detection.entity.value}",
        threat_type=detection.threat_type,
        severity=detection.severity,
        entity=detection.entity,
        detection_id=detection.detection_id,
        mitre_technique=detection.mitre_technique,
        description=detection.explanation,
    )


async def generate_alerts(detections: List[DetectionEvent]) -> List[Alert]:
    """
    Create, persist and dispatch an Alert for every detection at alerting
    severity that is not covered by a recent alert. Returns the alerts
    that were created. Never raises: a storage failure for one alert is
    logged and the rest are still processed.
    """
    created: List[Alert] = []
    cooldown_start = utcnow() - timedelta(minutes=settings.ALERT_COOLDOWN_MINUTES)
    raised_this_call = set()

    for detection in detections:
        if detection.severity not in ALERT_SEVERITIES:
            continue

        alert = _build_alert(detection)
        key = (alert.entity.value, alert.threat_type)
        try:
            if key in raised_this_call or await has_recent_alert(*key, since=cooldown_start):
                continue
            await save_alert(alert)
        except Exception as exc:
            logger.error(f"Failed to persist alert for detection {detection.detection_id}: {exc}")
            continue

        raised_this_call.add(key)
        created.append(alert)
        dispatch_in_background(alert)
        audit_event(
            "alert_generated",
            severity=alert.severity,
            threat_type=alert.threat_type,
            entity=alert.entity.value,
        )

    if created:
        logger.info(f"Alerting: generated {len(created)} alert(s) from {len(detections)} detection(s)")

    return created
