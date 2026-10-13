"""
app/models/alert_schema.py

Purpose:
    In-application alert record. When either detection engine produces a
    DetectionEvent at or above the alerting severity threshold, an Alert
    is created, persisted, and handed to alerts/dispatcher.py for delivery
    to whichever external channels (email / Discord / Telegram) are
    configured.

Connects to:
    - detection/alerting.py creates these from DetectionEvents
    - db/mongo.py persists them in the `alerts` collection
    - alerts/dispatcher.py records which channels delivered each alert
    - api/v1/alerts.py exposes list / acknowledge endpoints
"""
from datetime import datetime, timezone
from typing import List, Optional

from pydantic import BaseModel, Field

from app.models.detection_schema import Entity
from app.models.log_schema import Severity


class Alert(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")
    title: str
    threat_type: str
    severity: Severity
    entity: Entity
    detection_id: str
    mitre_technique: Optional[str] = None
    description: str

    dispatched_channels: List[str] = Field(
        default_factory=list, description="External channels this alert was delivered to."
    )
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = {"populate_by_name": True, "use_enum_values": True}
