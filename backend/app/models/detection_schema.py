"""
app/models/detection_schema.py

Purpose:
    Canonical output shape for BOTH detection engines (rule-based and ML).
    This is what lets incidents/correlator.py treat a brute-force rule hit
    and an Isolation Forest anomaly identically when deciding whether to
    open/update an incident — it doesn't care which engine produced the
    detection, only its shape.

Connects to:
    - detection/engine.py emits these from detection/rules/*.py and detection/ml/*.py
    - incidents/correlator.py consumes these to create/update Incident documents
"""
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from app.models.log_schema import Severity


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

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"use_enum_values": True}
