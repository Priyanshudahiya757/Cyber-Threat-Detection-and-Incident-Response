"""
app/api/v1/incidents.py

Purpose:
    Incident Management endpoints — list/filter, detail, status transitions,
    investigation notes, and analyst assignment. Backed by
    incidents/service.py; incidents are created by incidents/correlator.py
    from DetectionEvents (never deleted — closed for audit integrity).
"""
from typing import Optional

from fastapi import APIRouter, Depends, Query, status

from app.core.dependencies import get_current_user
from app.incidents import service as incident_service
from app.models.incident_schema import (
    IncidentAssignRequest,
    IncidentNoteCreate,
    IncidentStatus,
    IncidentStatusUpdate,
)
from app.models.log_schema import Severity
from app.models.user_schema import UserInDB

router = APIRouter(prefix="/incidents", tags=["Incident Management"])


@router.get("")
async def list_incidents(
    status_filter: Optional[IncidentStatus] = Query(default=None, alias="status"),
    severity: Optional[Severity] = None,
    assigned_to: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500),
    current_user: UserInDB = Depends(get_current_user),
):
    incidents = await incident_service.list_incidents(
        status_filter=status_filter,
        severity=severity.value if severity else None,
        assigned_to=assigned_to,
        limit=limit,
    )
    return {"incidents": incidents, "count": len(incidents)}


@router.get("/{incident_ref}")
async def get_incident(incident_ref: str, current_user: UserInDB = Depends(get_current_user)):
    return await incident_service.get_incident(incident_ref)


@router.patch("/{incident_ref}/status")
async def update_incident_status(
    incident_ref: str,
    body: IncidentStatusUpdate,
    current_user: UserInDB = Depends(get_current_user),
):
    return await incident_service.update_status(incident_ref, body, actor=current_user.username)


@router.post("/{incident_ref}/notes", status_code=status.HTTP_201_CREATED)
async def add_investigation_note(
    incident_ref: str,
    body: IncidentNoteCreate,
    current_user: UserInDB = Depends(get_current_user),
):
    return await incident_service.add_note(incident_ref, body, actor=current_user.username)


@router.patch("/{incident_ref}/assign")
async def assign_incident(
    incident_ref: str,
    body: IncidentAssignRequest,
    current_user: UserInDB = Depends(get_current_user),
):
    return await incident_service.assign_analyst(
        incident_ref, assigned_to=body.assigned_to, actor=current_user.username
    )
