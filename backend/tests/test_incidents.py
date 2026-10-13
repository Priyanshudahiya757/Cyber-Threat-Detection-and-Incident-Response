"""
tests/test_incidents.py

Purpose:
    Incident workflow through the API: status machine, investigation
    notes, and assignment to real, active analysts.
"""
import pytest

from app.incidents.correlator import correlate_detections
from app.models.detection_schema import DetectionEngine, DetectionEvent, Entity, EntityType
from app.models.log_schema import Severity


async def _open_incident(ip: str = "203.0.113.50", severity: Severity = Severity.HIGH) -> str:
    detection = DetectionEvent(
        engine=DetectionEngine.RULE,
        rule_name="ssh_brute_force",
        confidence=0.8,
        severity=severity,
        mitre_technique="T1110 - Brute Force",
        entity=Entity(type=EntityType.IP, value=ip),
        evidence_log_ids=[f"{ip}-log"],
        explanation="5 failed SSH login attempts.",
    )
    [incident] = await correlate_detections([detection])
    return incident["incident_ref"]


@pytest.mark.asyncio
async def test_list_and_filter_incidents(client, auth_headers):
    headers = await auth_headers()
    await _open_incident("203.0.113.50")
    await _open_incident("198.51.100.9", severity=Severity.CRITICAL)

    everything = await client.get("/api/v1/incidents", headers=headers)
    assert everything.json()["count"] == 2

    critical = await client.get("/api/v1/incidents", params={"severity": "critical"}, headers=headers)
    assert [i["entity"]["value"] for i in critical.json()["incidents"]] == ["198.51.100.9"]

    assert (await client.get("/api/v1/incidents", params={"status": "bogus"}, headers=headers)).status_code == 422
    assert (await client.get("/api/v1/incidents/INC-9999", headers=headers)).status_code == 404


@pytest.mark.asyncio
async def test_status_workflow_and_timeline(client, auth_headers):
    headers = await auth_headers()
    ref = await _open_incident()

    investigating = await client.patch(
        f"/api/v1/incidents/{ref}/status", json={"status": "INVESTIGATING"}, headers=headers
    )
    assert investigating.json()["status"] == "INVESTIGATING"
    assert investigating.json()["resolved_at"] is None

    resolved = await client.patch(
        f"/api/v1/incidents/{ref}/status",
        json={"status": "RESOLVED", "note": "Blocked the source IP at the firewall."},
        headers=headers,
    )
    body = resolved.json()
    assert body["status"] == "RESOLVED"
    assert body["resolved_at"] is not None
    assert body["investigation_notes"][-1] == {
        "author": "soc_analyst_user",
        "note": "Blocked the source IP at the firewall.",
        "created_at": body["investigation_notes"][-1]["created_at"],
    }

    closed = await client.patch(f"/api/v1/incidents/{ref}/status", json={"status": "CLOSED"}, headers=headers)
    assert closed.json()["status"] == "CLOSED"

    # CLOSED is terminal.
    reopen = await client.patch(f"/api/v1/incidents/{ref}/status", json={"status": "OPEN"}, headers=headers)
    assert reopen.status_code == 400


@pytest.mark.asyncio
async def test_notes_are_appended_and_validated(client, auth_headers):
    headers = await auth_headers()
    ref = await _open_incident()

    added = await client.post(
        f"/api/v1/incidents/{ref}/notes", json={"note": "Checked threat intel: known scanner."}, headers=headers
    )
    assert added.status_code == 201
    assert added.json()["investigation_notes"][-1]["note"] == "Checked threat intel: known scanner."

    assert (await client.post(f"/api/v1/incidents/{ref}/notes", json={"note": ""}, headers=headers)).status_code == 422


@pytest.mark.asyncio
async def test_assignment_requires_an_active_user(client, auth_headers, mock_db):
    headers = await auth_headers(username="alice")
    await auth_headers(username="bob")
    ref = await _open_incident()

    unknown = await client.patch(f"/api/v1/incidents/{ref}/assign", json={"assigned_to": "ghost"}, headers=headers)
    assert unknown.status_code == 400

    await mock_db.users.update_one({"username": "bob"}, {"$set": {"is_active": False}})
    disabled = await client.patch(f"/api/v1/incidents/{ref}/assign", json={"assigned_to": "bob"}, headers=headers)
    assert disabled.status_code == 400

    assigned = await client.patch(f"/api/v1/incidents/{ref}/assign", json={"assigned_to": "alice"}, headers=headers)
    assert assigned.status_code == 200
    assert assigned.json()["assigned_to"] == "alice"
    # Taking ownership of an OPEN incident starts the investigation.
    assert assigned.json()["status"] == "INVESTIGATING"


@pytest.mark.asyncio
async def test_new_detection_after_closure_opens_a_fresh_incident(client, auth_headers):
    headers = await auth_headers()
    first = await _open_incident()
    await client.patch(f"/api/v1/incidents/{first}/status", json={"status": "CLOSED"}, headers=headers)

    second = await _open_incident()
    assert second != first
