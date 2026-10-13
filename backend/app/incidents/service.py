"""
app/incidents/service.py

Purpose:
    Incident workflow used by api/v1/incidents.py: listing, status
    transitions, investigation notes and analyst assignment.
    Status machine: OPEN → INVESTIGATING → RESOLVED → CLOSED.
    Incidents are never deleted — they are closed for audit integrity —
    and every change is appended to the incident's timeline.
"""
from typing import List, Optional

from fastapi import HTTPException, status

from app.core.logging_config import audit_event
from app.db import mongo
from app.models.incident_schema import IncidentNoteCreate, IncidentStatus, IncidentStatusUpdate

_VALID_TRANSITIONS = {
    IncidentStatus.OPEN: {IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED, IncidentStatus.CLOSED},
    IncidentStatus.INVESTIGATING: {IncidentStatus.RESOLVED, IncidentStatus.CLOSED, IncidentStatus.OPEN},
    IncidentStatus.RESOLVED: {IncidentStatus.CLOSED, IncidentStatus.INVESTIGATING},
    IncidentStatus.CLOSED: set(),
}


def _to_response(doc: dict) -> dict:
    doc = dict(doc)
    doc["id"] = str(doc.pop("_id"))
    return doc


def _note(author: str, text: str) -> dict:
    return {"author": author, "note": text, "created_at": mongo.utcnow()}


async def _get_or_404(incident_ref: str) -> dict:
    doc = await mongo.get_incident_by_ref(incident_ref)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident {incident_ref} not found")
    return doc


async def list_incidents(
    status_filter: Optional[IncidentStatus] = None,
    severity: Optional[str] = None,
    assigned_to: Optional[str] = None,
    limit: int = 100,
) -> List[dict]:
    docs = await mongo.list_incidents(
        status=status_filter.value if status_filter else None,
        severity=severity,
        assigned_to=assigned_to,
        limit=limit,
    )
    return [_to_response(d) for d in docs]


async def get_incident(incident_ref: str) -> dict:
    return _to_response(await _get_or_404(incident_ref))


async def update_status(incident_ref: str, body: IncidentStatusUpdate, actor: str) -> dict:
    doc = await _get_or_404(incident_ref)
    current, target = IncidentStatus(doc["status"]), body.status

    if target == current:
        return _to_response(doc)
    if target not in _VALID_TRANSITIONS[current]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot transition from {current.value} to {target.value}",
        )

    is_finished = target in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED)
    updated = await mongo.update_incident(
        incident_ref,
        {
            "$set": {
                "status": target.value,
                "updated_at": mongo.utcnow(),
                "resolved_at": mongo.utcnow() if is_finished else None,
            },
            "$push": {"investigation_notes": _note(actor, body.note or f"Status changed to {target.value}")},
        },
    )
    audit_event("incident_status_changed", incident=incident_ref, status=target.value, actor=actor)
    return _to_response(updated)


async def add_note(incident_ref: str, body: IncidentNoteCreate, actor: str) -> dict:
    await _get_or_404(incident_ref)
    updated = await mongo.update_incident(
        incident_ref,
        {
            "$push": {"investigation_notes": _note(actor, body.note)},
            "$set": {"updated_at": mongo.utcnow()},
        },
    )
    return _to_response(updated)


async def assign_analyst(incident_ref: str, assigned_to: str, actor: str) -> dict:
    doc = await _get_or_404(incident_ref)
    if doc["status"] == IncidentStatus.CLOSED.value:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="A closed incident cannot be reassigned")

    assignee = await mongo.get_user_by_username(assigned_to)
    if assignee is None or not assignee.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=f"'{assigned_to}' is not an active user"
        )

    fields = {"assigned_to": assignee.username, "updated_at": mongo.utcnow()}
    if doc["status"] == IncidentStatus.OPEN.value:
        # Taking ownership of an untouched incident starts the investigation.
        fields["status"] = IncidentStatus.INVESTIGATING.value

    updated = await mongo.update_incident(
        incident_ref,
        {"$set": fields, "$push": {"investigation_notes": _note(actor, f"Assigned to {assignee.username}")}},
    )
    audit_event("incident_assigned", incident=incident_ref, assigned_to=assignee.username, actor=actor)
    return _to_response(updated)
