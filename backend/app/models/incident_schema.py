"""
app/models/incident_schema.py

Purpose:
    Incident workflow models — the status machine and the request bodies
    an analyst submits from the Incident Management page. Incident
    documents themselves are built by incidents/correlator.py from
    DetectionEvents and stored as plain MongoDB documents.

Connects to:
    - incidents/correlator.py and incidents/service.py use IncidentStatus
    - api/v1/incidents.py uses the request models
"""
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class IncidentStatusUpdate(BaseModel):
    status: IncidentStatus
    note: Optional[str] = Field(default=None, max_length=2000)


class IncidentNoteCreate(BaseModel):
    note: str = Field(..., min_length=1, max_length=2000)


class IncidentAssignRequest(BaseModel):
    assigned_to: str = Field(..., min_length=1, max_length=50)
