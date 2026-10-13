"""
app/detection/alerting.py

Purpose:
    Turns high-severity DetectionEvents into persisted Alert records —
    the "generate alerts automatically" requirement. Deliberately scoped
    to in-application alert creation only; dispatching those alerts to an
    external channel (email/Discord/Telegram) is out of scope here and
    left for the alerts/ module (Phase 8 per the original roadmap) to
    consume via Alert.channel_dispatched. Keeping alert *creation*
    (a detection-engine concern) separate from alert *dispatch* (an
    integration concern) is a deliberate SRP split.

Connects to:
    - detection/engine.py's post-ingestion handler calls generate_alerts()
      after running the rule engine
    - db/mongo.py::save_alert persists the result
"""
from typing import List

from app.core.logging_config import get_audit_logger, get_logger
from app.db.mongo import save_alert
from app.models.alert_schema import AlertInDB
from app.models.detection_schema import DetectionEvent
from app.models.log_schema import Severity

logger = get_logger(__name__)
audit = get_audit_logger()

#: Only detections at or above this severity generate an alert. Below this,
#: a detection is still stored and visible in the dashboard, but doesn't
#: warrant interrupting an analyst.
ALERT_SEVERITY_THRESHOLD = {Severity.HIGH.value, Severity.CRITICAL.value}


async def generate_alerts(detections: List[DetectionEvent]) -> List[AlertInDB]:
    """
    Create and persist an Alert for every detection at or above
    ALERT_SEVERITY_THRESHOLD. Returns the created alerts (mainly useful
    for tests/logging — callers don't need to do anything further with
    them since they're already persisted).
    """
    created: List[AlertInDB] = []

    for detection in detections:
        if detection.severity not in ALERT_SEVERITY_THRESHOLD:
            continue

        alert = AlertInDB(
            id="",  # Mongo assigns this; save_alert excludes it on insert
            title=_build_title(detection),
            threat_type=detection.rule_name or f"{detection.engine}_anomaly",
            severity=detection.severity,
            entity=detection.entity,
            detection_id=detection.detection_id,
            mitre_technique=detection.mitre_technique,
            description=detection.explanation,
        )

        try:
            await save_alert(alert)
            created.append(alert)
            audit.info(
                f'{{"event": "alert_generated", "severity": "{detection.severity}", '
                f'"rule": "{detection.rule_name}", "entity": "{detection.entity.value}"}}'
            )
        except Exception as exc:
            logger.error(f"Failed to persist alert for detection {detection.detection_id}: {exc}")

    if created:
        logger.info(f"AlertService: generated {len(created)} alert(s) from {len(detections)} detection(s)")

    return created


def _build_title(detection: DetectionEvent) -> str:
    threat_name = (detection.rule_name or "anomaly").replace("_", " ").title()
    return f"{threat_name} — {detection.entity.value}"
