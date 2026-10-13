"""
app/models/alert_schema.py

Purpose:
    In-application alert record. When the detection engine (rule-based or
    ML) produces a DetectionEvent at or above ALERT_SEVERITY_THRESHOLD,
    an Alert is created and persisted — this is the "generate alerts
    automatically" requirement for Phase 3/4. External channel dispatch
    (email/Discord/Telegram) is a separate concern (Phase 8 per the
    original roadmap) and is intentionally NOT implemented here; this
    schema and its `channel_dispatched` flag are what that future phase
    will consume, so the integration seam already exists.

Connects to:
    - detection/alerting.py creates these from DetectionEvent/Incident data
    - db/mongo.py persists them in the `alerts` collection
    - api/v1/detections.py exposes read endpoints
"""
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field

from app.models.detection_schema import Entity
from app.models.log_schema import Severity


class AlertCreate(BaseModel):
    title: str
    threat_type: str
    severity: Severity
    entity: Entity
    detection_id: str
    mitre_technique: Optional[str] = None
    description: str


class AlertInDB(AlertCreate):
    id: str = Field(..., alias="_id")
    channel_dispatched: bool = Field(
        default=False, description="Whether this alert has been sent to an external channel (Phase 8)."
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"populate_by_name": True, "use_enum_values": True}
