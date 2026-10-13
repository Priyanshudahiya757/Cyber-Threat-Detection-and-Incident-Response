"""
app/incidents/service.py

Purpose:
    Incident CRUD and workflow transitions used by api/v1/incidents.py.
    Status machine: OPEN → INVESTIGATING → RESOLVED → CLOSED.
    Incidents are never deleted — they are closed for audit integrity.
"""
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import HTTPException, status

from app.db import mongo
from app.models.incident_schema import (
    IncidentNoteCreate,
    IncidentStatus,
    IncidentStatusUpdate,
)

_VALID_TRANSITIONS = {
    IncidentStatus.OPEN: {IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED, IncidentStatus.CLOSED},
    IncidentStatus.INVESTIGATING: {IncidentStatus.RESOLVED, IncidentStatus.CLOSED, IncidentStatus.OPEN},
    IncidentStatus.RESOLVED: {IncidentStatus.CLOSED, IncidentStatus.INVESTIGATING},
    IncidentStatus.CLOSED: set(),
}


def _normalize_doc(doc: dict) -> dict:
    if not doc:
        return doc
    doc = dict(doc)
    if "_id" in doc:
        doc["id"] = str(doc.pop("_id"))
    return doc


async def list_incidents(
    status_filter: Optional[str] = None,
    severity: Optional[str] = None,
    assigned_to: Optional[str] = None,
    limit: int = 100,
) -> List[dict]:
    docs = await mongo.list_incidents(
        status=status_filter,
        severity=severity,
        assigned_to=assigned_to,
        limit=limit,
    )
    return [_normalize_doc(d) for d in docs]


async def get_incident(incident_ref: str) -> dict:
    doc = await mongo.get_incident_by_ref(incident_ref)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident {incident_ref} not found")
    return _normalize_doc(doc)


async def update_status(incident_ref: str, body: IncidentStatusUpdate, actor: str) -> dict:
    doc = await mongo.get_incident_by_ref(incident_ref)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident {incident_ref} not found")

    current = IncidentStatus(doc["status"])
    target = body.status if isinstance(body.status, IncidentStatus) else IncidentStatus(body.status)

    if target == current:
        return _normalize_doc(doc)

    allowed = _VALID_TRANSITIONS.get(current, set())
    if target not in allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot transition from {current.value} to {target.value}",
        )

    now = datetime.now(timezone.utc)
    note_text = body.note or f"Status changed to {target.value}"
    update: dict = {
        "$set": {
            "status": target.value,
            "updated_at": now,
        },
        "$push": {
            "investigation_notes": {
                "author": actor,
                "note": note_text,
                "created_at": now,
            }
        },
    }
    if target in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED):
        update["$set"]["resolved_at"] = now
    elif target in (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING):
        update["$set"]["resolved_at"] = None

    await mongo.update_incident_raw(incident_ref, update)
    return await get_incident(incident_ref)


async def add_note(incident_ref: str, body: IncidentNoteCreate, actor: str) -> dict:
    doc = await mongo.get_incident_by_ref(incident_ref)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident {incident_ref} not found")

    now = datetime.now(timezone.utc)
    await mongo.update_incident_raw(
        incident_ref,
        {
            "$push": {
                "investigation_notes": {
                    "author": actor,
                    "note": body.note,
                    "created_at": now,
                }
            },
            "$set": {"updated_at": now},
        },
    )
    return await get_incident(incident_ref)


async def assign_analyst(incident_ref: str, assigned_to: str, actor: str) -> dict:
    doc = await mongo.get_incident_by_ref(incident_ref)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident {incident_ref} not found")

    now = datetime.now(timezone.utc)
    await mongo.update_incident_raw(
        incident_ref,
        {
            "$set": {
                "assigned_to": assigned_to,
                "updated_at": now,
                **(
                    {"status": IncidentStatus.INVESTIGATING.value}
                    if doc["status"] == IncidentStatus.OPEN.value
                    else {}
                ),
            },
            "$push": {
                "investigation_notes": {
                    "author": actor,
                    "note": f"Assigned to {assigned_to}",
                    "created_at": now,
                }
            },
        },
    )
    return await get_incident(incident_ref)
