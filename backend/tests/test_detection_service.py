"""
tests/test_detection_service.py

Purpose:
    The detection workflow end to end against an in-memory MongoDB:
    findings are stored once, alerts and incidents follow from new
    findings only, and an attack split across two uploads is still
    detected through the stored-log context window.
"""
from datetime import datetime, timedelta, timezone

import pytest

from app.detection import service
from app.models.detection_schema import DetectionEngine
from app.models.log_schema import EventCategory, NormalizedLog, SourceType

BASE_TIME = datetime(2026, 7, 18, 12, 0, 0, tzinfo=timezone.utc)
ATTACKER = "203.0.113.50"


def failed_login(index: int, ip: str = ATTACKER) -> NormalizedLog:
    return NormalizedLog(
        log_id=f"{ip}-{index}",
        source_type=SourceType.LINUX,
        event_category=EventCategory.AUTHENTICATION,
        event_type="failed_login",
        source_ip=ip,
        user="root",
        raw_log=f"Failed password for root from {ip} #{index}",
        timestamp=BASE_TIME + timedelta(seconds=index * 3),
    )


@pytest.fixture
def stored_logs(monkeypatch):
    """Stand-in for Elasticsearch: search_logs returns whatever this list holds."""
    stored: list[NormalizedLog] = []

    async def fake_search_logs(**kwargs):
        return {"total": len(stored), "results": [log.model_dump(mode="json") for log in stored]}

    monkeypatch.setattr("app.detection.service.elastic.search_logs", fake_search_logs)
    return stored


@pytest.fixture(autouse=True)
def no_ml_model(monkeypatch):
    """These tests exercise the rule path; ML scoring has its own test module."""
    monkeypatch.setattr(service.default_prediction_service, "predict", lambda logs: [])


@pytest.mark.asyncio
class TestHandleIngestedLogs:
    async def test_brute_force_batch_creates_detection_alert_and_incident(self, mock_db, stored_logs):
        await service.handle_ingested_logs([failed_login(i) for i in range(5)])

        detection = await mock_db.detections.find_one({})
        assert detection["rule_name"] == "ssh_brute_force"
        assert await mock_db.alerts.count_documents({}) == 1

        incident = await mock_db.incidents.find_one({})
        assert incident["incident_ref"] == "INC-1001"
        assert incident["status"] == "OPEN"
        assert incident["entity"] == {"type": "ip", "value": ATTACKER}

    async def test_benign_batch_stores_nothing(self, mock_db, stored_logs):
        await service.handle_ingested_logs([failed_login(0)])

        assert await mock_db.detections.count_documents({}) == 0
        assert await mock_db.incidents.count_documents({}) == 0

    async def test_attack_split_across_two_uploads_is_detected(self, mock_db, stored_logs):
        first_upload = [failed_login(i) for i in range(2)]
        second_upload = [failed_login(i) for i in range(2, 5)]

        # Neither upload reaches the threshold of 4 on its own.
        await service.handle_ingested_logs(first_upload)
        assert await mock_db.detections.count_documents({}) == 0

        stored_logs.extend(first_upload)
        await service.handle_ingested_logs(second_upload)

        detection = await mock_db.detections.find_one({})
        assert len(detection["evidence_log_ids"]) == 5

    async def test_old_findings_are_not_re_reported_by_an_unrelated_upload(self, mock_db, stored_logs):
        attack = [failed_login(i) for i in range(5)]
        await service.handle_ingested_logs(attack)
        stored_logs.extend(attack)

        # A later upload from someone else pulls the attack in as context,
        # but the finding involves none of the new logs.
        await service.handle_ingested_logs([failed_login(99, ip="10.0.0.7")])

        assert await mock_db.detections.count_documents({}) == 1
        assert await mock_db.alerts.count_documents({}) == 1

    async def test_continuing_attack_updates_the_same_incident_without_a_second_alert(
        self, mock_db, stored_logs
    ):
        first = [failed_login(i) for i in range(5)]
        await service.handle_ingested_logs(first)
        stored_logs.extend(first)

        await service.handle_ingested_logs([failed_login(i) for i in range(5, 14)])

        assert await mock_db.detections.count_documents({}) == 2
        assert await mock_db.incidents.count_documents({}) == 1
        assert await mock_db.alerts.count_documents({}) == 1

        incident = await mock_db.incidents.find_one({})
        assert len(incident["detection_ids"]) == 2
        assert len(incident["evidence_log_ids"]) == 14
        # 14 attempts crosses the rule's critical threshold (3x4).
        assert incident["severity"] == "critical"

    async def test_context_lookup_failure_falls_back_to_the_batch_alone(self, mock_db, monkeypatch):
        async def broken_search(**kwargs):
            raise ConnectionError("elasticsearch is down")

        monkeypatch.setattr("app.detection.service.elastic.search_logs", broken_search)

        await service.handle_ingested_logs([failed_login(i) for i in range(5)])
        assert await mock_db.detections.count_documents({}) == 1

    async def test_ml_failure_does_not_block_rule_detections(self, mock_db, stored_logs, monkeypatch):
        def exploding_predict(logs):
            raise RuntimeError("model file corrupt")

        monkeypatch.setattr(service.default_prediction_service, "predict", exploding_predict)

        await service.handle_ingested_logs([failed_login(i) for i in range(5)])
        assert await mock_db.detections.count_documents({}) == 1


@pytest.mark.asyncio
class TestManualScan:
    async def test_rescanning_the_same_logs_is_idempotent(self, mock_db, stored_logs):
        stored_logs.extend(failed_login(i) for i in range(5))

        first = await service.scan_recent_logs(DetectionEngine.RULE, minutes=60)
        second = await service.scan_recent_logs(DetectionEngine.RULE, minutes=60)

        assert first.logs_scanned == 5
        assert len(first.detections) == 1 and first.alerts_generated == 1
        assert second.detections == [] and second.alerts_generated == 0
        assert await mock_db.detections.count_documents({}) == 1
        assert await mock_db.incidents.count_documents({}) == 1

    async def test_scan_endpoint_reports_the_outcome(self, client, auth_headers, stored_logs):
        stored_logs.extend(failed_login(i) for i in range(5))
        headers = await auth_headers("soc_analyst")

        response = await client.post("/api/v1/detections/run", params={"minutes": 60}, headers=headers)

        assert response.status_code == 200
        body = response.json()
        assert body["logs_scanned"] == 5
        assert body["detections_found"] == 1
        assert body["alerts_generated"] == 1

        listed = await client.get("/api/v1/detections", params={"engine": "rule"}, headers=headers)
        assert listed.json()["count"] == 1

    async def test_predict_without_a_trained_model_is_a_clear_error(self, client, auth_headers, monkeypatch):
        monkeypatch.setattr("app.api.v1.ml.default_registry.get_latest_metadata", lambda *a, **k: None)
        headers = await auth_headers("soc_analyst")

        response = await client.post("/api/v1/ml/predict", headers=headers)
        assert response.status_code == 409
