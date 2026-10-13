"""
app/incidents/correlator.py

Purpose:
    Detection → Incident correlation (architecture.md §2.4).
    Buckets DetectionEvents by (entity.value, threat key, open status)
    so a burst of related detections updates one incident instead of
    spawning dozens. Called from detection/engine.handle_ingested_logs
    after detections are persisted.
"""
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from app.core.logging_config import get_logger
from app.db import mongo
from app.models.detection_schema import DetectionEvent, DetectionEngine
from app.models.incident_schema import IncidentStatus

logger = get_logger(__name__)

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_ACTIVE_STATUSES = [IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value]


def _sev_str(severity) -> str:
    return severity.value if hasattr(severity, "value") else str(severity)


def _rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity.lower(), 0)


def _threat_key(detection: DetectionEvent) -> Tuple[str, str]:
    """(threat_type label, correlation key for open-incident lookup)."""
    engine = detection.engine.value if hasattr(detection.engine, "value") else detection.engine
    if engine == DetectionEngine.ML.value or engine == "ml":
        return ("AI Anomaly", "ml_anomaly")
    rule = detection.rule_name or "unknown_rule"
    label = rule.replace("_", " ").title()
    return (label, rule)


def _entity_dict(detection: DetectionEvent) -> dict:
    etype = detection.entity.type
    return {
        "type": etype.value if hasattr(etype, "value") else etype,
        "value": detection.entity.value,
    }


async def correlate_detections(detections: List[DetectionEvent]) -> List[dict]:
    """
    For each detection, find an OPEN/INVESTIGATING incident for the same
    (entity, threat key) or create a new one. Returns the incidents that
    were created or updated.
    """
    if not detections:
        return []

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
    threat_type, corr_key = _threat_key(detection)
    entity = _entity_dict(detection)
    severity = _sev_str(detection.severity)
    now = datetime.now(timezone.utc)

    existing = await mongo.find_open_incident(
        entity_value=entity["value"],
        correlation_key=corr_key,
        statuses=_ACTIVE_STATUSES,
    )

    if existing:
        update: dict = {
            "$addToSet": {
                "detection_ids": detection.detection_id,
            },
            "$set": {"updated_at": now},
        }
        if detection.evidence_log_ids:
            update["$addToSet"]["evidence_log_ids"] = {"$each": detection.evidence_log_ids}
        if _rank(severity) > _rank(existing.get("severity", "low")):
            update["$set"]["severity"] = severity
            update["$push"] = {
                "investigation_notes": {
                    "author": "system",
                    "note": f"Severity escalated to {severity.upper()} "
                    f"based on detection {detection.detection_id[:8]}…",
                    "created_at": now,
                }
            }
        await mongo.update_incident_raw(existing["incident_ref"], update)
        return await mongo.get_incident_by_ref(existing["incident_ref"])

    seq = await mongo.next_incident_sequence()
    incident_ref = f"INC-{seq}"
    engine = detection.engine.value if hasattr(detection.engine, "value") else detection.engine
    doc = {
        "incident_ref": incident_ref,
        "threat_type": threat_type,
        "correlation_key": corr_key,
        "severity": severity,
        "entity": entity,
        "status": IncidentStatus.OPEN.value,
        "detection_ids": [detection.detection_id],
        "evidence_log_ids": list(detection.evidence_log_ids),
        "description": detection.explanation,
        "investigation_notes": [
            {
                "author": "system",
                "note": f"Incident opened from {engine} detection "
                f"({detection.rule_name or 'anomaly'}).",
                "created_at": now,
            }
        ],
        "assigned_to": None,
        "created_at": now,
        "updated_at": now,
        "resolved_at": None,
    }
    await mongo.insert_incident(doc)
    logger.info(f"correlator: created {incident_ref} ({threat_type} / {entity['value']})")
    return await mongo.get_incident_by_ref(incident_ref)
