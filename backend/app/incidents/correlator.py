"""
app/incidents/correlator.py

Purpose:
    Detection → Incident correlation. Buckets DetectionEvents by
    (entity, threat type) so a burst of related detections updates one
    active incident instead of spawning dozens. Called from
    detection/service.py after new detections are stored.
"""
from typing import List, Optional

from app.core.logging_config import get_logger
from app.db import mongo
from app.models.detection_schema import DetectionEvent, threat_label
from app.models.incident_schema import IncidentStatus

logger = get_logger(__name__)

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_ACTIVE_STATUSES = [IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value]


def _system_note(text: str) -> dict:
    return {"author": "system", "note": text, "created_at": mongo.utcnow()}


async def correlate_detections(detections: List[DetectionEvent]) -> List[dict]:
    """
    For each detection, update the active incident for the same
    (entity, threat type) or open a new one. Returns the incidents that
    were created or updated. One detection failing never stops the rest.
    """
    touched: List[dict] = []
    for detection in detections:
        try:
            incident = await _upsert_for_detection(detection)
            if incident:
                touched.append(incident)
        except Exception as exc:
            logger.error(f"correlator: failed for detection {detection.detection_id}: {exc}")
    return touched


async def _upsert_for_detection(detection: DetectionEvent) -> Optional[dict]:
    correlation_key = detection.threat_type
    entity = detection.entity.model_dump()
    severity = str(detection.severity)

    existing = await mongo.find_open_incident(
        entity_value=entity["value"],
        correlation_key=correlation_key,
        statuses=_ACTIVE_STATUSES,
    )
    if existing:
        return await _add_to_incident(existing, detection, severity)

    now = mongo.utcnow()
    incident_ref = f"INC-{await mongo.next_incident_sequence()}"
    await mongo.insert_incident(
        {
            "incident_ref": incident_ref,
            "threat_type": threat_label(correlation_key),
            "correlation_key": correlation_key,
            "severity": severity,
            "mitre_technique": detection.mitre_technique,
            "entity": entity,
            "status": IncidentStatus.OPEN.value,
            "detection_ids": [detection.detection_id],
            "evidence_log_ids": list(detection.evidence_log_ids),
            "description": detection.explanation,
            "investigation_notes": [
                _system_note(f"Incident opened from a {threat_label(correlation_key)} detection.")
            ],
            "assigned_to": None,
            "created_at": now,
            "updated_at": now,
            "resolved_at": None,
        }
    )
    logger.info(f"correlator: created {incident_ref} ({correlation_key} / {entity['value']})")
    return await mongo.get_incident_by_ref(incident_ref)


async def _add_to_incident(incident: dict, detection: DetectionEvent, severity: str) -> Optional[dict]:
    update: dict = {
        "$addToSet": {
            "detection_ids": detection.detection_id,
            "evidence_log_ids": {"$each": detection.evidence_log_ids},
        },
        # The newest detection describes the attack's current extent.
        "$set": {"updated_at": mongo.utcnow(), "description": detection.explanation},
    }
    if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK.get(incident.get("severity", "low"), 0):
        update["$set"]["severity"] = severity
        update["$push"] = {
            "investigation_notes": _system_note(
                f"Severity escalated to {severity.upper()} by a new detection."
            )
        }
    return await mongo.update_incident(incident["incident_ref"], update)
