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
from pydantic import BaseModel, Field

from app.core.dependencies import get_current_user
from app.incidents import service as incident_service
from app.models.incident_schema import IncidentNoteCreate, IncidentStatusUpdate
from app.models.user_schema import UserInDB

router = APIRouter(prefix="/incidents", tags=["Incident Management"])


class AssignRequest(BaseModel):
    assigned_to: str = Field(..., min_length=1, max_length=64)


@router.get("")
async def list_incidents(
    status_filter: Optional[str] = Query(default=None, alias="status"),
    severity: Optional[str] = None,
    assigned_to: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500),
    current_user: UserInDB = Depends(get_current_user),
):
    incidents = await incident_service.list_incidents(
        status_filter=status_filter,
        severity=severity,
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
    body: AssignRequest,
    current_user: UserInDB = Depends(get_current_user),
):
    return await incident_service.assign_analyst(
        incident_ref, assigned_to=body.assigned_to, actor=current_user.username
    )
