"""
app/models/detection_schema.py

Purpose:
    Canonical output shape for BOTH detection engines (rule-based and ML).
    This is what lets incidents/correlator.py treat a brute-force rule hit
    and an Isolation Forest anomaly identically when deciding whether to
    open/update an incident — it doesn't care which engine produced the
    detection, only its shape.

Connects to:
    - detection/engine.py and detection/ml/prediction_service.py emit these
    - detection/service.py persists them (de-duplicated by `fingerprint`)
    - incidents/correlator.py consumes these to create/update incidents
"""
import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, model_validator

from app.models.log_schema import Severity


#: threat_type of every finding produced by the ML engine (rule findings use the rule name).
ML_THREAT_TYPE = "ml_anomaly"

_ACRONYMS = {"ssh": "SSH", "sql": "SQL", "xss": "XSS"}


def threat_label(threat_type: str) -> str:
    """Display name for a threat type: 'ssh_brute_force' -> 'SSH Brute Force', 'ml_anomaly' -> 'AI Anomaly'."""
    if threat_type == ML_THREAT_TYPE:
        return "AI Anomaly"
    return " ".join(_ACRONYMS.get(word, word.capitalize()) for word in threat_type.split("_"))


class DetectionEngine(str, Enum):
    RULE = "rule"
    ML = "ml"


class EntityType(str, Enum):
    IP = "ip"
    USER = "user"
    HOST = "host"


class Entity(BaseModel):
    type: EntityType
    value: str

    model_config = {"use_enum_values": True}


class DetectionEvent(BaseModel):
    detection_id: str = Field(default_factory=lambda: str(uuid4()))
    engine: DetectionEngine

    # Populated when engine == RULE
    rule_name: Optional[str] = None

    # Populated when engine == ML
    anomaly_score: Optional[float] = Field(default=None, description="Raw Isolation Forest score")
    risk_percentage: Optional[float] = Field(default=None, ge=0, le=100)

    confidence: float = Field(..., ge=0, le=1)
    severity: Severity
    mitre_technique: Optional[str] = Field(
        default=None, description="MITRE ATT&CK technique ID + name, e.g. 'T1110 - Brute Force'"
    )

    entity: Entity
    evidence_log_ids: List[str] = Field(default_factory=list)
    explanation: str = Field(..., description="Human-readable reason this was flagged")

    #: Content hash of (engine, rule, entity, evidence). Two detections with
    #: the same fingerprint describe the same finding over the same logs, so
    #: re-running detection over a window never stores a finding twice.
    fingerprint: str = ""

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"use_enum_values": True}

    @property
    def threat_type(self) -> str:
        """Stable threat identifier: the rule name, or ML_THREAT_TYPE for the ML engine."""
        return self.rule_name or ML_THREAT_TYPE

    @model_validator(mode="after")
    def _set_fingerprint(self) -> "DetectionEvent":
        if not self.fingerprint:
            key = "|".join(
                [
                    str(self.engine),
                    self.rule_name or "",
                    str(self.entity.type),
                    self.entity.value,
                    ",".join(sorted(self.evidence_log_ids)),
                ]
            )
            self.fingerprint = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return self
