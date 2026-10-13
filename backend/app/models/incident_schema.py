"""
app/models/incident_schema.py

Purpose:
    Incident data model — what a SOC analyst actually works with in the
    Incident Management page. Incidents are created/updated by
    incidents/correlator.py from one or more DetectionEvents, never
    directly from raw logs.

Connects to:
    - db/mongo.py persists these in the `incidents` collection
    - api/v1/incidents.py exposes CRUD + status-transition endpoints
    - alerts/dispatcher.py reads these to format alert messages
"""
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field

from app.models.detection_schema import Entity
from app.models.log_schema import Severity


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class InvestigationNote(BaseModel):
    author: str
    note: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IncidentBase(BaseModel):
    threat_type: str = Field(..., description="e.g. 'SSH Brute Force', 'SQL Injection Attempt'")
    severity: Severity
    entity: Entity
    status: IncidentStatus = IncidentStatus.OPEN


class IncidentCreate(IncidentBase):
    detection_ids: List[str] = Field(default_factory=list)
    evidence_log_ids: List[str] = Field(default_factory=list)
    description: Optional[str] = None


class IncidentInDB(IncidentBase):
    id: str = Field(..., alias="_id")
    incident_ref: str = Field(..., description="Human-facing ID, e.g. INC-1001")
    detection_ids: List[str] = Field(default_factory=list)
    evidence_log_ids: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    investigation_notes: List[InvestigationNote] = Field(default_factory=list)
    assigned_to: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None

    model_config = {"populate_by_name": True, "use_enum_values": True}


class IncidentStatusUpdate(BaseModel):
    status: IncidentStatus
    note: Optional[str] = None


class IncidentNoteCreate(BaseModel):
    note: str
